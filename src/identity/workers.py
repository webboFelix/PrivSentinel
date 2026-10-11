"""Qt worker threads for camera preview, model work, and live verification."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import cv2
import numpy as np
from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QImage

from src.config.defaults import DEFAULT_CAMERA_INDEX
from src.config.settings import AppSettings
from src.identity.camera import CameraCapture
from src.identity.face_detector import DetectedFace, FaceDetector, ImageQuality
from src.identity.face_verifier import FaceRecognitionEngine
from src.identity.liveness import BasicMotionLiveness
from src.identity.verification_policy import VerificationPolicy
from src.storage.repositories.identity_repository import IdentityRepository


def frame_to_image(frame: np.ndarray) -> QImage:
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    height, width, channels = rgb.shape
    return QImage(
        rgb.data,
        width,
        height,
        channels * width,
        QImage.Format.Format_RGB888,
    ).copy()


class CameraListWorker(QThread):
    devicesReady = Signal(object)
    failed = Signal(str)

    def run(self) -> None:
        try:
            from src.identity.camera import CameraCapture

            self.devicesReady.emit(CameraCapture.available_devices())
        except Exception as exc:
            self.failed.emit(str(exc))


class CameraPreviewWorker(QThread):
    previewReady = Signal(object, object, object, object, object)
    cameraError = Signal(str)
    status = Signal(str)

    def __init__(
        self,
        camera_index: int,
        width: int,
        height: int,
        parent=None,
        frame_interval_ms: int = 120,
        require_single_face: bool = True,
        *,
        models_directory: str | Path,
        allow_download: bool = False,
        camera_factory=CameraCapture,
    ) -> None:
        super().__init__(parent)
        self.camera_index = camera_index
        self.width = width
        self.height = height
        self.frame_interval_ms = frame_interval_ms
        self.require_single_face = require_single_face
        self.models_directory = Path(models_directory)
        self.allow_download = allow_download
        self.camera_factory = camera_factory
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        capture = self.camera_factory(self.camera_index, self.width, self.height)
        engine = FaceRecognitionEngine(
            self.models_directory,
            allow_download=self.allow_download,
        )
        model_ready = threading.Event()
        model_errors: list[RuntimeError] = []
        model_loader: threading.Thread | None = None
        preview_frame: np.ndarray | None = None

        def load_model() -> None:
            try:
                engine.load()
            except RuntimeError as exc:
                model_errors.append(exc)
            finally:
                model_ready.set()

        try:
            capture.open()
            first_frame = capture.read()
            preview_frame = first_frame
            self.previewReady.emit(
                frame_to_image(first_frame),
                [],
                first_frame.copy(),
                ImageQuality(False, "Face guidance is loading.", 0.0, 0.0),
                {"camera_check": True},
            )
            self.status.emit(
                "Camera connected. Loading the local face-position model; "
                "the first download may take several minutes."
            )
            model_loader = threading.Thread(
                target=load_model,
                name="face-recognition-model-loader",
            )
            model_loader.start()
            while not model_ready.is_set() and not self._stop_event.is_set():
                frame = capture.read()
                preview_frame = frame
                self.previewReady.emit(
                    frame_to_image(frame),
                    [],
                    frame.copy(),
                    ImageQuality(False, "Face guidance is loading.", 0.0, 0.0),
                    {"model_loading": True},
                )
                self._stop_event.wait(self.frame_interval_ms / 1000)
            model_loader.join()
            if self._stop_event.is_set():
                return
            if model_errors:
                raise model_errors[0]
            if preview_frame is not None:
                self.previewReady.emit(
                    frame_to_image(preview_frame),
                    [],
                    preview_frame.copy(),
                    ImageQuality(True, "Face guidance is ready.", 0.0, 0.0),
                    {"model_ready": True},
                )
            eye_cascade_path = (
                Path(cv2.data.haarcascades) / "haarcascade_eye_tree_eyeglasses.xml"
            )
            eye_cascade = cv2.CascadeClassifier(str(eye_cascade_path))
            if eye_cascade.empty():
                raise RuntimeError(
                    f"Could not load eye detector cascade: {eye_cascade_path}"
                )
            while not self._stop_event.is_set():
                frame = capture.read()
                observations = engine.analyze(frame)
                faces = [
                    DetectedFace(
                        observation.bounding_box[0],
                        observation.bounding_box[1],
                        observation.bounding_box[2] - observation.bounding_box[0],
                        observation.bounding_box[3] - observation.bounding_box[1],
                    )
                    for observation in observations
                ]
                quality = FaceDetector.validate_enrollment_frame(
                    frame,
                    faces,
                    require_single_face=self.require_single_face,
                )
                guidance = None
                if len(observations) == 1:
                    face = observations[0]
                    pose = engine.estimate_head_pose(
                        face.landmarks,
                        frame.shape[1],
                        frame.shape[0],
                    )
                    x, y, width, height = (
                        faces[0].x,
                        faces[0].y,
                        faces[0].width,
                        faces[0].height,
                    )
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    eye_region = gray[
                        max(0, y) : min(gray.shape[0], y + int(height * 0.65)),
                        max(0, x) : min(gray.shape[1], x + width),
                    ]
                    eyes = eye_cascade.detectMultiScale(
                        eye_region,
                        scaleFactor=1.1,
                        minNeighbors=4,
                        minSize=(max(12, width // 10), max(12, height // 12)),
                    )
                    midpoint = eye_region.shape[1] / 2
                    left_eye = any(eye[0] + eye[2] / 2 < midpoint for eye in eyes)
                    right_eye = any(eye[0] + eye[2] / 2 >= midpoint for eye in eyes)
                    guidance = {
                        "yaw": pose.yaw_degrees,
                        "pitch": pose.pitch_degrees,
                        "eyes_open": left_eye and right_eye,
                        "embedding": face.embedding,
                    }
                image = frame_to_image(frame)
                self.previewReady.emit(image, faces, frame.copy(), quality, guidance)
                self._stop_event.wait(self.frame_interval_ms / 1000)
        except Exception as exc:
            if not self._stop_event.is_set():
                self.cameraError.emit(
                    f"Camera {self.camera_index} could not provide a live frame: {exc}"
                )
        finally:
            if model_loader is not None:
                model_loader.join()
            capture.release()


class SpeechPromptWorker(QThread):
    completed = Signal()
    failed = Signal(str)

    def __init__(self, prompt: str, parent=None) -> None:
        super().__init__(parent)
        self.prompt = prompt

    def run(self) -> None:
        engine = None
        failure = None
        try:
            import pyttsx3

            engine = pyttsx3.init()
            engine.say(self.prompt)
            engine.runAndWait()
        except Exception as exc:
            failure = exc
        if engine is not None:
            try:
                engine.stop()
            except Exception as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            self.failed.emit(str(failure))
            return
        self.completed.emit()


class EmbeddingWorker(QThread):
    completed = Signal(object, float)
    failed = Signal(str)
    status = Signal(str)

    def __init__(
        self,
        models_directory: str | Path,
        frames: np.ndarray | list[np.ndarray],
        parent=None,
        *,
        allow_download: bool = False,
        require_single_face: bool = True,
    ) -> None:
        super().__init__(parent)
        self.models_directory = Path(models_directory)
        if isinstance(frames, np.ndarray):
            frames = [frames]
        self.frames = [frame.copy() for frame in frames]
        self.allow_download = allow_download
        self.require_single_face = require_single_face

    def run(self) -> None:
        try:
            self.status.emit("Preparing the recognition model (first use may download it)…")
            engine = FaceRecognitionEngine(
                self.models_directory,
                allow_download=self.allow_download,
            )
            embeddings = []
            for index, frame in enumerate(self.frames, start=1):
                self.status.emit(
                    f"Analyzing sample {index} of {len(self.frames)}…"
                )
                faces = engine.analyze(frame)
                if not faces:
                    raise ValueError(
                        f"The recognition model did not find a face in sample {index}."
                    )
                if len(faces) > 1 and self.require_single_face:
                    raise ValueError(
                        f"The recognition model found multiple faces in sample {index}; "
                        "exactly one is required."
                    )
                face = max(
                    faces,
                    key=lambda item: max(
                        0, item.bounding_box[2] - item.bounding_box[0]
                    )
                    * max(0, item.bounding_box[3] - item.bounding_box[1]),
                )
                embeddings.append(face.embedding)
            template, consistency = engine.aggregate_embeddings(embeddings)
            self.completed.emit(template, consistency)
        except Exception as exc:
            self.failed.emit(str(exc))


class CameraMonitorWorker(QThread):
    stateChanged = Signal(str, str)
    verification = Signal(object)
    previewReady = Signal(object)
    lockRequested = Signal()
    workerError = Signal(str)

    def __init__(
        self,
        settings: AppSettings,
        models_directory: str | Path,
        repository: IdentityRepository,
        parent=None,
        *,
        camera_factory=CameraCapture,
        detector_factory=FaceDetector,
        engine_factory=FaceRecognitionEngine,
        reconnect_delay_seconds: float = 2.0,
    ) -> None:
        super().__init__(parent)
        self.settings = settings
        self.models_directory = Path(models_directory)
        self.repository = repository
        self.camera_factory = camera_factory
        self.detector_factory = detector_factory
        self.engine_factory = engine_factory
        self.reconnect_delay_seconds = reconnect_delay_seconds
        self._stop_event = threading.Event()
        self._last_event_state: str | None = None
        self._last_event_time = 0.0
        self._last_frame: np.ndarray | None = None
        self._last_face: tuple[int, int, int, int] | None = None
        self._failure_count = 0
        self._monitor_started = time.monotonic()
        self._camera_error_reported = False
        self._policy = VerificationPolicy()

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def monitoring_seconds(self) -> float:
        return max(0.0, time.monotonic() - self._monitor_started)

    @property
    def failed_attempts(self) -> int:
        return self._failure_count

    def run(self) -> None:
        try:
            profile = self.repository.profile()
            template = self.repository.template()
            if profile is None or template is None:
                self.stateChanged.emit(
                    "verification_failure", "Enroll an identity before monitoring."
                )
                return
            engine = self.engine_factory(
                self.models_directory,
                model_name=profile.model_name,
                allow_download=False,
            )
            engine.load()
        except Exception as exc:
            self.stateChanged.emit("verification_failure", str(exc))
            return

        while not self._stop_event.is_set():
            capture = self.camera_factory(
                DEFAULT_CAMERA_INDEX,
                self.settings.camera_width,
                self.settings.camera_height,
            )
            try:
                capture.open()
                self._camera_error_reported = False
                self.stateChanged.emit("camera_ready", "Camera connected.")
                liveness = BasicMotionLiveness()
                while not self._stop_event.is_set():
                    cycle_start = time.monotonic()
                    frame = capture.read()
                    self.previewReady.emit(frame_to_image(frame))
                    observations = engine.analyze(frame)
                    faces = observations
                    if len(faces) > 1:
                        state = "multiple_faces"
                        self._handle_state(
                            "multiple_faces",
                            "Multiple faces detected; verification paused.",
                            None,
                            "not_checked",
                        )
                        if self.settings.multiple_face_policy == "stop_monitoring":
                            self._stop_event.set()
                    elif not faces:
                        liveness.reset()
                        state = "no_face_detected"
                        self._handle_state(
                            "no_face_detected",
                            "No face detected.",
                            None,
                            "not_checked",
                        )
                    else:
                        observation = faces[0]
                        liveness_result = (
                            liveness.update(
                                observation.landmarks,
                                frame.shape[1],
                                frame.shape[0],
                            )
                            if self.settings.liveness_enabled
                            else "disabled"
                        )
                        confidence = engine.similarity(template, observation.embedding)
                        if len(observation.landmarks) == 0 and self.settings.liveness_enabled:
                            state = "low_confidence"
                            detail = "Recognition model returned no facial landmarks."
                        elif (
                            self.settings.liveness_enabled
                            and liveness_result != "basic_motion_observed"
                        ):
                            if liveness.sample_ready:
                                state = "liveness_failure"
                                detail = (
                                    "Basic facial-landmark motion was not observed; "
                                    "this is not a robust anti-spoofing result."
                                )
                            else:
                                state = "low_confidence"
                                detail = (
                                    "Basic facial-landmark motion has not yet been "
                                    "observed; this is not robust anti-spoofing."
                                )
                        elif confidence >= self.settings.verification_threshold:
                            state = "recognized"
                            detail = "Enrolled identity recognized."
                        elif confidence >= self.settings.verification_threshold - 0.08:
                            state = "low_confidence"
                            detail = "Face similarity is near the configured threshold."
                        else:
                            state = "unknown_face"
                            detail = "Detected face does not match the enrolled identity."
                        self._handle_state(
                            state, detail, confidence, liveness_result
                        )
                    if state == "recognized":
                        self._failure_count = 0
                    elif state in {
                        "unknown_face",
                        "low_confidence",
                        "liveness_failure",
                        "multiple_faces",
                        "no_face_detected",
                    }:
                        self._failure_count += 1
                    action = (
                        self.settings.presence_loss_action
                        if state == "no_face_detected"
                        else self.settings.unknown_face_action
                    )
                    decision = self._policy.decide(
                        state,
                        self._failure_count,
                        self.settings.identity_failure_limit,
                        self.settings.automatic_lock_enabled,
                        action,
                    )
                    if decision.action == "warn_then_lock":
                        self.lockRequested.emit()
                        self._failure_count = 0
                    elapsed = time.monotonic() - cycle_start
                    self._stop_event.wait(
                        max(0.0, self.settings.capture_interval_ms / 1000 - elapsed)
                    )
            except Exception as exc:
                if not self._stop_event.is_set():
                    self.stateChanged.emit("camera_unavailable", str(exc))
                    if not self._camera_error_reported:
                        self._handle_state(
                            "camera_unavailable",
                            f"Camera unavailable: {exc}; no attack is inferred.",
                            None,
                            "not_checked",
                        )
                        self._camera_error_reported = True
                    capture.release()
                    if (
                        self.settings.camera_failure_action
                        == "notify_and_stop_monitoring"
                    ):
                        self._stop_event.set()
                    else:
                        self._stop_event.wait(
                            self.settings.camera_reconnect_seconds
                        )
            finally:
                capture.release()
        self.stateChanged.emit("stopped", "Identity monitoring stopped.")

    def _handle_state(
        self,
        state: str,
        detail: str,
        confidence: float | None,
        liveness: str,
    ) -> None:
        now = time.monotonic()
        if (
            state != self._last_event_state
            or now - self._last_event_time
            >= self.settings.verification_cooldown_seconds
        ):
            try:
                event = self.repository.record_event(
                    event_type=state,
                    state=state,
                    confidence=confidence,
                    liveness=liveness,
                    detail=detail,
                    monitoring_seconds=self.monitoring_seconds,
                )
                self.verification.emit(event)
            except Exception as exc:
                self.workerError.emit(f"Could not save identity event: {exc}")
            self._last_event_state = state
            self._last_event_time = now
        self.stateChanged.emit(state, detail)
