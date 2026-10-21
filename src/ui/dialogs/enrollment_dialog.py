"""Camera preview and explicitly consented local identity enrollment."""

from __future__ import annotations

import sqlite3
import winsound
from datetime import UTC, datetime
from getpass import getuser

import numpy as np
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QPainter, QPen, QPixmap, QResizeEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.identity.face_detector import DetectedFace, ImageQuality
from src.identity.face_verifier import (
    MODEL_NAME,
    FaceRecognitionEngine,
    recognition_model_is_installed,
)
from src.identity.workers import (
    CameraPreviewWorker,
    SpeechPromptWorker,
)
from src.storage.repositories.identity_repository import IdentityRepository


class EnrollmentDialog(QDialog):
    enrollmentCompleted = Signal()

    _BASE_SAMPLE_STEPS = (
        ("Center your face in the frame", "center"),
        ("Please turn your head to your left", "left"),
        ("Please turn your head to your right", "right"),
        ("Please look up", "up"),
        ("Please look down", "down"),
        ("Please blink twice", "blink"),
        ("Please face the camera", "center"),
        ("Hold still for verification", "center"),
    )
    _GLASSES_SAMPLE_STEPS = (
        ("If you normally wear them, put on your glasses", "center"),
        ("Now remove your glasses", "center"),
    )
    _HIGH_CONSISTENCY_THRESHOLD = 0.85
    _MODERATE_CONSISTENCY_THRESHOLD = 0.70
    _POSE_ANGLE_THRESHOLD = 12.0
    _STABLE_FRAMES_REQUIRED = 5

    def __init__(
        self,
        services: ApplicationServices,
        repository: IdentityRepository,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self.repository = repository
        self.setWindowTitle("Identity enrollment")
        screen = self.screen()
        available_geometry = screen.availableGeometry()
        initial_width = min(760, int(available_geometry.width() * 0.9))
        initial_height = min(860, int(available_geometry.height() * 0.9))
        self.setMinimumSize(min(520, initial_width), min(560, initial_height))
        self.resize(initial_width, initial_height)
        self._preview_worker: CameraPreviewWorker | None = None
        self._speech_worker: SpeechPromptWorker | None = None
        self._last_frame: np.ndarray | None = None
        self._preview_source: QPixmap | None = None
        self._last_embedding: np.ndarray | None = None
        self._enrollment_embeddings: list[np.ndarray] = []
        self._pose_embeddings: dict[str, list[np.ndarray]] = {
            "front": [],
            "turned": [],
        }
        self._step_index = 0
        self._enrollment_succeeded = False
        self._setup_failed = False
        self._preview_worker_finished = False
        self._pending_dialog_result: int | None = None
        self._last_quality: ImageQuality | None = None
        self._camera_discovery_started = False
        self._model_preparation_pending = False
        self._speech_ready = False
        self._speech_prompt_step_index: int | None = None
        self._stable_frames = 0
        self._blink_count = 0
        self._eyes_closed_frames = 0
        self._eyes_open_frames = 0
        self._blink_armed = False

        dialog_layout = QVBoxLayout(self)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(6)
        title = QLabel("Enroll your identity")
        title.setObjectName("sectionTitle")
        intro = QLabel(
            "Frames are processed locally and kept in memory only. The application "
            "stores an encrypted face embedding, not the captured photo. Optional "
            "profile details are encrypted for this Windows account."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(intro)
        self.enrollment_summary = QLabel()
        self.enrollment_summary.setWordWrap(True)
        self.enrollment_summary.hide()
        layout.addWidget(self.enrollment_summary)

        self.sequence_label = QLabel()
        self.sequence_label.setObjectName("muted")
        self.sequence_label.setWordWrap(True)
        self.sequence_label.setText(
            "Enrollment starts after you enter a profile name and consent. Follow the "
            "spoken and visible instructions, keeping your face inside the fixed oval "
            "guide; each pose is checked, then sampled automatically. Prompts use your "
            "local Windows voice. No microphone audio is recorded or saved."
        )
        layout.addWidget(self.sequence_label)

        self.preview = QLabel("Camera is off")
        self.preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview.setMinimumSize(320, 180)
        self.preview.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self.preview.setStyleSheet(
            "background:#061326;border:1px solid #163a60;border-radius:8px;"
        )
        self.step_prompt = QLabel()
        self.step_prompt.setObjectName("sectionTitle")
        self.step_prompt.setWordWrap(True)
        self.readiness_indicator = QLabel("Waiting for enrollment consent.")
        self.readiness_indicator.setObjectName("muted")
        self.readiness_indicator.setWordWrap(True)
        self.enrollment_progress_label = QLabel(
            "Enrollment progress: 0% (0 of 8 poses captured)"
        )
        self.enrollment_progress_label.setObjectName("muted")
        self.enrollment_progress_label.setWordWrap(True)
        self.readiness_progress = QProgressBar()
        self.readiness_progress.setRange(0, 100)
        self.readiness_progress.setValue(0)
        self.readiness_progress.setTextVisible(True)
        self.readiness_progress.setFormat("Current pose: %p%")

        identity_form = QFormLayout()
        self.display_name = QLineEdit()
        self.display_name.setPlaceholderText("Full name")
        self.identity_name_label = QLabel("Identity name")
        self.identity_name_label.setText("Full name")
        identity_form.addRow(self.identity_name_label, self.display_name)
        self.email = QLineEdit()
        self.email.setPlaceholderText("name@example.com (optional)")
        identity_form.addRow("Work email (optional)", self.email)
        self.department = QLineEdit()
        self.department.setPlaceholderText("Department or team (optional)")
        identity_form.addRow("Department (optional)", self.department)
        self.employee_id = QLineEdit()
        self.employee_id.setPlaceholderText("Employee ID (optional)")
        identity_form.addRow("Employee ID (optional)", self.employee_id)
        self.machine_user = QLineEdit(getuser())
        self.machine_user.setPlaceholderText("Windows account name")
        identity_form.addRow("Windows account", self.machine_user)
        self.profile_privacy_note = QLabel(
            "Profile details are optional and DPAPI-encrypted for this Windows account. "
            "They are not sent to a server."
        )
        self.profile_privacy_note.setObjectName("muted")
        self.profile_privacy_note.setWordWrap(True)
        identity_form.addRow(self.profile_privacy_note)
        layout.addLayout(identity_form)
        self.email.textChanged.connect(self._maybe_start_enrollment)

        self.consent_checkbox = QCheckBox(
            "I consent to local encrypted face-template enrollment."
        )
        self.consent_checkbox.setToolTip(
            "I consent to creating and storing an encrypted face template on this device."
        )
        self.model_download_checkbox = QCheckBox(
            "Allow first-use download of the local recognition model (if needed)."
        )
        self.model_download_checkbox.setToolTip(
            "I explicitly allow downloading the InsightFace buffalo_l model to this "
            "device if needed. Camera images will not be uploaded."
        )
        self._model_download_consent_required = not recognition_model_is_installed(
            self.services.paths.models_directory
        )
        if not self._model_download_consent_required:
            self.model_download_checkbox.setChecked(True)
            self.model_download_checkbox.setEnabled(False)
            self.model_download_checkbox.setText(
                "Recognition model is already installed; no model download is needed."
            )
        elif self.services.settings.recognition_model_download_allowed:
            self.model_download_checkbox.setChecked(True)
        self.consent_checkbox.stateChanged.connect(self._update_enroll_requirements)
        self.model_download_checkbox.stateChanged.connect(
            self._update_enroll_requirements
        )
        self.glasses_checkbox = QCheckBox(
            "I normally wear glasses (include glasses-on/off samples)"
        )
        self.glasses_checkbox.stateChanged.connect(self._update_step_prompt)
        layout.addWidget(self.consent_checkbox)
        layout.addWidget(self.model_download_checkbox)
        layout.addWidget(self.glasses_checkbox)
        self.enrollment_requirements = QLabel()
        self.enrollment_requirements.setObjectName("muted")
        self.enrollment_requirements.setWordWrap(True)
        layout.addWidget(self.enrollment_requirements)
        self.start_button = QPushButton("Start guided enrollment")
        self.start_button.setObjectName("primaryButton")
        self.start_button.setEnabled(False)
        self.start_button.clicked.connect(self._begin_enrollment)
        layout.addWidget(self.start_button)
        scroll_area.setWidget(content)
        scroll_area.setMaximumHeight(min(260, int(initial_height * 0.34)))
        dialog_layout.addWidget(scroll_area)
        dialog_layout.addWidget(self.step_prompt)
        dialog_layout.addWidget(self.readiness_indicator)
        dialog_layout.addWidget(self.enrollment_progress_label)
        dialog_layout.addWidget(self.readiness_progress)
        dialog_layout.addWidget(self.preview, 1)

        buttons = QHBoxLayout()
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self._close_dialog)
        buttons.addStretch(1)
        buttons.addWidget(self.close_button)
        dialog_layout.addLayout(buttons)
        self.status = QLabel(self._initial_status())
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        dialog_layout.addWidget(self.status)
        self.display_name.textChanged.connect(self._update_enroll_requirements)
        self.email.textChanged.connect(self._update_enroll_requirements)
        self.glasses_checkbox.setEnabled(True)
        self._update_step_prompt()
        self._update_enroll_requirements()

    def _close_dialog(self, *_args) -> None:
        if self._setup_failed:
            self._restart_enrollment()
            return
        if self._enrollment_succeeded:
            self.accept()
        else:
            self.reject()

    def done(self, result: int) -> None:
        if self._pending_dialog_result is None:
            self._pending_dialog_result = result
        if self._preview_worker is not None and self._preview_worker.isRunning():
            self._preview_worker.stop()
            self.status.setText(
                "Stopping the camera and waiting for background setup before closing…"
            )
            self.close_button.setEnabled(False)
            return
        if self._speech_worker is not None and self._speech_worker.isRunning():
            self.status.setText("Finishing the spoken instruction before closing…")
            self.close_button.setEnabled(False)
            return
        self._finish_pending_close()

    def _finish_pending_close(self) -> None:
        result = self._pending_dialog_result
        if result is None:
            return
        if self._preview_worker is not None and self._preview_worker.isRunning():
            return
        if self._speech_worker is not None and self._speech_worker.isRunning():
            return
        self._pending_dialog_result = None
        self._enrollment_embeddings.clear()
        for embeddings in self._pose_embeddings.values():
            embeddings.clear()
        self._last_frame = None
        self._last_embedding = None
        self._preview_source = None
        self.preview.clear()
        if not self.services.identity_service.is_monitoring:
            self.services.identity_service.set_camera_state(
                "idle" if self.services.settings.camera_access_enabled else "disabled",
                "Enrollment camera session is not active.",
            )
        super().done(result)

    def _sample_steps(self) -> tuple[tuple[str, str], ...]:
        glasses_steps = (
            self._GLASSES_SAMPLE_STEPS if self.glasses_checkbox.isChecked() else ()
        )
        return (
            *self._BASE_SAMPLE_STEPS[:5],
            *glasses_steps,
            *self._BASE_SAMPLE_STEPS[5:],
        )

    def _update_step_prompt(self, *_args) -> None:
        steps = self._sample_steps()
        if self._step_index >= len(steps):
            self.step_prompt.setText(f"All {len(steps)} samples captured.")
            self._set_position_progress(0)
            return
        self.step_prompt.setText(
            f"Sample {self._step_index + 1} of {len(steps)}: "
            f"{steps[self._step_index][0]}"
        )
        self._set_position_progress(0)
        if self._camera_discovery_started or self._preview_worker is not None:
            self.readiness_indicator.setText("Waiting for the required face position.")

    def _maybe_start_enrollment(self, *_args) -> None:
        self._update_enroll_requirements()

    def _begin_enrollment(self, *_args) -> None:
        self._update_enroll_requirements()
        if not self.start_button.isEnabled():
            return
        if self._camera_discovery_started or self._enrollment_succeeded:
            return
        if self._model_preparation_pending:
            self.readiness_indicator.setText(
                "The local model is downloading in the background. Enrollment "
                "can start when preparation finishes."
            )
            self.status.setText("Waiting for background face-model preparation…")
            return
        self._camera_discovery_started = True
        self.start_button.setEnabled(False)
        for widget in (
            self.display_name,
            self.consent_checkbox,
            self.model_download_checkbox,
            self.glasses_checkbox,
            self.email,
            self.department,
            self.employee_id,
            self.machine_user,
        ):
            widget.setEnabled(False)
        self._start_preview()

    def set_model_preparation_pending(self) -> None:
        self._model_preparation_pending = True
        self.step_prompt.setText("Preparing local face guidance…")
        self.readiness_progress.setRange(0, 0)
        self.readiness_indicator.setText(
            "The local model is downloading in the background. Enrollment will "
            "be ready to start when preparation finishes."
        )
        self.status.setText("Waiting for background face-model preparation…")

    def model_preparation_finished(self, succeeded: bool, message: str) -> None:
        self._model_preparation_pending = False
        self.readiness_progress.setRange(0, 100)
        self.readiness_progress.setValue(0)
        if succeeded and recognition_model_is_installed(
            self.services.paths.models_directory
        ):
            self._model_download_consent_required = False
            self.model_download_checkbox.setChecked(True)
            self.model_download_checkbox.setEnabled(False)
            self.model_download_checkbox.setText(
                "Recognition model is installed and ready."
            )
        self.status.setText(message)
        self._update_enroll_requirements()

    def _update_enroll_requirements(self) -> None:
        requirements = []
        if not self.services.settings.camera_access_enabled:
            requirements.append("enable camera access in Settings")
        if not self.display_name.text().strip():
            requirements.append("enter an identity name")
        if not self._email_is_valid():
            requirements.append("enter a valid email address or leave it blank")
        if not self.consent_checkbox.isChecked():
            requirements.append("consent to local encrypted face-template enrollment")
        if (
            self._model_download_consent_required
            and not self.model_download_checkbox.isChecked()
        ):
            requirements.append("consent to download the local recognition model")
        self.enrollment_requirements.setText(
            "Select Start guided enrollment when you are ready."
            if not requirements
            else "To begin: " + "; ".join(requirements) + "."
        )
        self.start_button.setEnabled(
            not requirements
            and not self._camera_discovery_started
            and not self._model_preparation_pending
            and not self._enrollment_succeeded
        )

    def _email_is_valid(self) -> bool:
        email = self.email.text().strip()
        if not email:
            return True
        if email.count("@") != 1 or any(character.isspace() for character in email):
            return False
        local_part, domain = email.split("@")
        return bool(local_part and "." in domain and not domain.startswith("."))

    def _initial_status(self) -> str:
        if not self.services.settings.camera_access_enabled:
            return "Camera access is disabled in Settings. Enable it before enrollment."
        return (
            "Enter an identity name and give consent to begin guided enrollment. "
            "No face samples are taken before consent."
        )

    def _start_preview(self) -> None:
        if self._step_index >= len(self._sample_steps()):
            self._complete_enrollment()
            return
        if not self.services.settings.camera_access_enabled:
            self.status.setText(
                "Enable camera access in Settings before starting camera preview."
            )
            return
        if self.services.identity_service.is_monitoring:
            self.status.setText(
                "Stop identity monitoring before starting the enrollment camera preview."
            )
            return
        if self._preview_worker and self._preview_worker.isRunning():
            return
        settings = self.services.settings
        worker = CameraPreviewWorker(
            settings.camera_index,
            settings.camera_width,
            settings.camera_height,
            self,
            require_single_face=settings.require_single_face,
            models_directory=self.services.paths.models_directory,
            allow_download=(
                self._model_download_consent_required
                and self.model_download_checkbox.isChecked()
            ),
        )
        self._preview_worker = worker
        self._preview_worker_finished = False
        worker.previewReady.connect(self._show_preview)
        worker.cameraError.connect(self._camera_error)
        worker.status.connect(self.status.setText)
        worker.finished.connect(
            lambda worker=worker: self._preview_finished(worker)
        )
        worker.finished.connect(worker.deleteLater)
        self.status.setText(f"Opening camera {settings.camera_index}…")
        self.services.identity_service.set_camera_state(
            "connecting", "Opening the camera for identity enrollment."
        )
        self.step_prompt.setText("Preparing local face guidance…")
        self.readiness_progress.setRange(0, 0)
        self.readiness_indicator.setText(
            "Starting the camera and preparing the local recognition model. "
            "No face samples are captured during setup."
        )
        worker.start()

    def _preview_finished(self, worker: CameraPreviewWorker) -> None:
        if self._preview_worker is worker:
            self._preview_worker = None
        self._preview_worker_finished = True
        identity = self.services.identity_service
        if not identity.is_monitoring and identity.camera_state in {
            "connecting",
            "connected",
        }:
            identity.set_camera_state(
                "idle", "Enrollment camera session is not active."
            )
        QTimer.singleShot(0, self._finish_pending_close)

    def _speak_current_step(self) -> None:
        if self._step_index >= len(self._sample_steps()):
            self._complete_enrollment()
            return
        if self._speech_worker is not None and self._speech_worker.isRunning():
            return
        instruction = self._sample_steps()[self._step_index][0]
        self._speech_ready = False
        self._stable_frames = 0
        self._blink_count = 0
        self._eyes_closed_frames = 0
        self._eyes_open_frames = 0
        self._blink_armed = False
        self._set_position_progress(0)
        self.readiness_indicator.setText("Listening for the requested position…")
        self._speech_prompt_step_index = self._step_index
        worker = SpeechPromptWorker(instruction, self)
        self._speech_worker = worker
        worker.completed.connect(self._speech_finished)
        worker.failed.connect(self._speech_failed)
        worker.finished.connect(
            lambda worker=worker: self._speech_worker_finished(worker)
        )
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _speech_finished(self) -> None:
        self._speech_ready = True
        self.readiness_indicator.setText(
            "Follow the instruction; the camera will capture automatically."
        )

    def _speech_failed(self, message: str) -> None:
        self._speech_ready = True
        self.readiness_indicator.setText(
            f"Spoken prompt unavailable ({message}). Follow the visible instruction."
        )

    def _speech_worker_finished(self, worker: SpeechPromptWorker) -> None:
        if self._speech_worker is worker:
            self._speech_worker = None
        QTimer.singleShot(0, self._finish_pending_close)
        if (
            self._pending_dialog_result is None
            and self._speech_prompt_step_index != self._step_index
            and self._step_index < len(self._sample_steps())
        ):
            QTimer.singleShot(0, self._speak_current_step)

    def _show_preview(self, image, faces, frame, quality, guidance) -> None:
        if self._enrollment_succeeded or self._step_index >= len(self._sample_steps()):
            return
        self._last_frame = frame
        self._last_quality = quality
        self.services.identity_service.set_camera_state(
            "connected", "Camera is open for guided identity enrollment."
        )
        frame_width = image.width()
        frame_height = image.height()
        face_centered = len(faces) == 1 and self._face_centered_in_guide(
            faces[0],
            frame_width,
            frame_height,
        )
        position_matches = False
        if len(faces) == 1 and guidance is not None and not any(
            guidance.get(state)
            for state in ("camera_check", "model_loading", "model_ready")
        ):
            action = self._sample_steps()[self._step_index][1]
            position_matches = self._pose_matches(action, guidance)
        face_ready = face_centered and quality.accepted and position_matches
        pixmap = QPixmap.fromImage(image)
        painter = QPainter(pixmap)
        painter.setPen(
            QPen(
                Qt.GlobalColor.green
                if face_ready
                else Qt.GlobalColor.yellow,
                3,
            )
        )
        for face in faces:
            painter.drawRect(face.x, face.y, face.width, face.height)
        guide_width, guide_height = self._guide_size(frame_width, frame_height)
        guide_x = (frame_width - guide_width) // 2
        guide_y = (frame_height - guide_height) // 2
        painter.setPen(
            QPen(
                Qt.GlobalColor.green
                if face_ready
                else Qt.GlobalColor.yellow
                if faces
                else Qt.GlobalColor.cyan,
                3,
            )
        )
        painter.drawEllipse(guide_x, guide_y, guide_width, guide_height)
        painter.end()
        self._preview_source = pixmap
        self._render_preview()

        if guidance is not None and guidance.get("camera_check"):
            self.step_prompt.setText("Preparing local face guidance…")
            self.readiness_progress.setRange(0, 0)
            self.readiness_indicator.setText(
                f"✓ Camera {self.services.settings.camera_index} is delivering a live image. "
                "Preparing the local face model; no samples are captured yet."
            )
            return
        if guidance is not None and guidance.get("model_loading"):
            self.step_prompt.setText("Preparing local face guidance…")
            self.readiness_progress.setRange(0, 0)
            self.readiness_indicator.setText(
                "Live camera preview is active. Preparing the local face model. "
                "First-time download can take several minutes; capture starts "
                "automatically when setup finishes."
            )
            return
        if guidance is not None and guidance.get("model_ready"):
            self.readiness_progress.setRange(0, 100)
            self.readiness_progress.setValue(0)
            self._update_step_prompt()
            self._speak_current_step()
            return

        if not faces:
            self._stable_frames = 0
            self.readiness_indicator.setText("No face detected. Center your face.")
            self._set_position_progress(0)
            return
        if len(faces) != 1 or guidance is None:
            self._stable_frames = 0
            self.readiness_indicator.setText(
                "Keep only one face in the frame for enrollment."
            )
            self._set_position_progress(0)
            return
        if not quality.accepted:
            self._stable_frames = 0
            self.readiness_indicator.setText(
                f"Adjust your position: {quality.detail}"
            )
            self._set_position_progress(0)
            return

        if not self._face_centered_in_guide(
            faces[0],
            image.width(),
            image.height(),
        ):
            self._stable_frames = 0
            self.readiness_indicator.setText(
                "Move your face into the center of the oval guide."
            )
            self._set_position_progress(0)
            return

        self._last_embedding = np.asarray(guidance["embedding"], dtype=np.float32)
        action = self._sample_steps()[self._step_index][1]
        ready, progress, detail = self._evaluate_position(action, guidance)
        self.readiness_indicator.setText(detail)
        self._set_position_progress(progress)
        if ready:
            self._complete_step()

    def _set_position_progress(self, position_progress: int) -> None:
        total_steps = len(self._sample_steps())
        completed_steps = min(self._step_index, total_steps)
        position_fraction = (
            0.0
            if completed_steps >= total_steps
            else max(0, min(position_progress, 100)) / 100
        )
        overall_percent = int(
            (completed_steps + position_fraction) * 100 / total_steps
        )
        self.readiness_progress.setValue(position_progress)
        self.enrollment_progress_label.setText(
            f"Enrollment progress: {overall_percent}% "
            f"({completed_steps} of {total_steps} poses captured)"
        )

    @staticmethod
    def _face_centered_in_guide(
        face: DetectedFace,
        frame_width: int,
        frame_height: int,
    ) -> bool:
        if frame_width <= 0 or frame_height <= 0:
            return False
        guide_width, guide_height = EnrollmentDialog._guide_size(
            frame_width,
            frame_height,
        )
        center_x = face.x + face.width / 2
        center_y = face.y + face.height / 2
        return (
            abs(center_x - frame_width / 2) <= guide_width * 0.15
            and abs(center_y - frame_height / 2) <= guide_height * 0.15
        )

    @staticmethod
    def _guide_size(frame_width: int, frame_height: int) -> tuple[int, int]:
        short_side = min(frame_width, frame_height)
        return int(short_side * 0.58), int(short_side * 0.82)

    def _render_preview(self) -> None:
        if self._preview_source is None or self.preview.size().isEmpty():
            return
        self.preview.setPixmap(
            self._preview_source.scaled(
                self.preview.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._render_preview()

    def _evaluate_position(self, action: str, guidance: dict) -> tuple[bool, int, str]:
        action_matched = self._pose_matches(action, guidance)
        if action == "blink":
            if action_matched and guidance["eyes_open"]:
                if self._blink_armed and self._eyes_closed_frames >= 1:
                    self._blink_count += 1
                self._eyes_closed_frames = 0
                self._eyes_open_frames += 1
                if self._eyes_open_frames >= 2:
                    self._blink_armed = True
            elif action_matched:
                if self._blink_armed:
                    self._eyes_closed_frames += 1
                self._eyes_open_frames = 0
            else:
                self._eyes_closed_frames = 0
                self._eyes_open_frames = 0
                self._blink_armed = False
            self._blink_count = min(self._blink_count, 2)
            percent = self._blink_count * 50
            if self._blink_count < 2:
                return False, percent, f"Blink detected: {self._blink_count}/2"
            action_matched = True

        if not action_matched:
            self._stable_frames = 0
            instruction = self._sample_steps()[self._step_index][0].lower()
            return False, 0, f"Adjust your position: {instruction}."

        self._stable_frames += 1
        percent = min(
            100,
            self._stable_frames * 100 // self._STABLE_FRAMES_REQUIRED,
        )
        if self._stable_frames < self._STABLE_FRAMES_REQUIRED:
            return False, percent, "✓ Position detected. Hold steady…"
        return True, 100, "✓ Position confirmed. Capturing automatically."

    def _pose_matches(self, action: str, guidance: dict) -> bool:
        yaw = float(guidance["yaw"])
        pitch = float(guidance["pitch"])
        if action in {"center", "blink"}:
            return (
                abs(yaw) <= self._POSE_ANGLE_THRESHOLD
                and abs(pitch) <= self._POSE_ANGLE_THRESHOLD
            )
        if action == "left":
            return yaw >= self._POSE_ANGLE_THRESHOLD
        if action == "right":
            return yaw <= -self._POSE_ANGLE_THRESHOLD
        if action == "up":
            return pitch <= -self._POSE_ANGLE_THRESHOLD
        if action == "down":
            return pitch >= self._POSE_ANGLE_THRESHOLD
        return False

    def _complete_step(self) -> None:
        if self._last_embedding is None or self._step_index >= len(self._sample_steps()):
            return
        try:
            winsound.MessageBeep(winsound.MB_OK)
        except OSError as exc:
            self.status.setText(f"Capture tone unavailable: {exc}")
        action = self._sample_steps()[self._step_index][1]
        pose_group = "turned" if action in {"left", "right"} else "front"
        sample_embedding = self._last_embedding.copy()
        self._enrollment_embeddings.append(sample_embedding)
        self._pose_embeddings[pose_group].append(sample_embedding)
        self._step_index += 1
        self._last_embedding = None
        self._stable_frames = 0
        self.readiness_indicator.setText(
            f"✓ Sample {self._step_index} captured. Moving to the next instruction…"
        )
        self._update_step_prompt()
        if self._preview_worker and self._preview_worker.isRunning():
            self._speak_current_step()

    def _complete_enrollment(self) -> None:
        if self._enrollment_succeeded or not self._enrollment_embeddings:
            return
        self.status.setText(
            "Saving encrypted front-facing and turned-face templates…"
        )
        if self._preview_worker and self._preview_worker.isRunning():
            self._preview_worker.stop()
        try:
            if any(not embeddings for embeddings in self._pose_embeddings.values()):
                raise ValueError(
                    "Enrollment needs both front-facing and turned-face samples."
                )
            templates = np.stack(
                [
                    FaceRecognitionEngine.aggregate_embeddings(
                        self._pose_embeddings[group]
                    )[0]
                    for group in ("front", "turned")
                ]
            )
            consistency = FaceRecognitionEngine.aggregate_embeddings(
                self._enrollment_embeddings
            )[1]
        except (OSError, TypeError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._enrollment_failed(str(exc))
            return
        self._embedding_ready(templates, consistency)

    def _embedding_ready(self, embedding, consistency: float) -> None:
        try:
            self.repository.enroll(
                self.display_name.text(),
                embedding,
                MODEL_NAME,
                datetime.now(UTC),
                {
                    "email": self.email.text(),
                    "department": self.department.text(),
                    "employee_id": self.employee_id.text(),
                    "machine_user": self.machine_user.text(),
                },
            )
        except (OSError, TypeError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._enrollment_failed(str(exc))
            return
        if consistency >= self._HIGH_CONSISTENCY_THRESHOLD:
            confidence = "High"
        elif consistency >= self._MODERATE_CONSISTENCY_THRESHOLD:
            confidence = "Moderate"
        else:
            confidence = "Low — retake recommended"
        self._enrollment_succeeded = True
        self._enrollment_embeddings.clear()
        for embeddings in self._pose_embeddings.values():
            embeddings.clear()
        self._last_frame = None
        self._last_embedding = None
        self.status.setText(
            "Enrollment complete. Front-facing and turned-face templates saved."
        )
        self.enrollment_summary.setText(
            "Enrollment complete\n"
            f"Verification confidence: {confidence}\n"
            f"Sample consistency: {consistency:.2f} average cosine similarity\n"
            "Templates: Front-facing and turned-face samples\n"
            "Template storage: Encrypted, local device only (Windows DPAPI)\n"
            "Camera photos are not saved.\n"
            "Recovery method: Windows Hello / PIN (same Windows account)"
        )
        self.enrollment_summary.show()
        self.enrollment_summary.setToolTip(
            "Sample consistency is the mean cosine similarity between captured face "
            "embeddings and their combined verification template; it is not a probability. "
            "Labels use fixed sample-consistency bands (High ≥ 0.85, Moderate ≥ 0.70). "
            "Both pose templates are protected by Windows DPAPI for this Windows user. "
            "PrivSentinel does not store or manage your PIN."
        )
        for widget in (
            self.sequence_label,
            self.preview,
            self.step_prompt,
            self.readiness_indicator,
            self.enrollment_progress_label,
            self.readiness_progress,
            self.identity_name_label,
            self.display_name,
            self.email,
            self.department,
            self.employee_id,
            self.machine_user,
            self.profile_privacy_note,
            self.consent_checkbox,
            self.model_download_checkbox,
            self.glasses_checkbox,
            self.enrollment_requirements,
        ):
            widget.hide()
        self._preview_source = None
        self.preview.clear()
        self.close_button.setText("Done")
        self.enrollmentCompleted.emit()

    def _enrollment_failed(self, message: str) -> None:
        self.status.setText("Enrollment could not be completed.")
        self.readiness_indicator.setText(
            "No template was saved. Review the error and retry enrollment."
        )
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle("Identity enrollment failed")
        box.setText("PrivSentinel could not create the encrypted face template.")
        box.setInformativeText(
            "Your temporary face samples remain in memory only and will be cleared "
            "when you close this dialog. Check the details, then retry or close."
        )
        box.setDetailedText(message)
        box.setStandardButtons(
            QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Close
        )
        if box.exec() == QMessageBox.StandardButton.Retry:
            self._restart_enrollment()

    def _restart_enrollment(self) -> None:
        self._enrollment_embeddings.clear()
        for embeddings in self._pose_embeddings.values():
            embeddings.clear()
        self._step_index = 0
        self._enrollment_succeeded = False
        self._setup_failed = False
        self._speech_ready = False
        self.close_button.setText("Close")
        self.start_button.setEnabled(False)
        self._update_step_prompt()
        self._camera_discovery_started = True
        if self._preview_worker and not self._preview_worker_finished:
            self._preview_worker.stop()
            self._preview_worker.finished.connect(self._start_preview)
        else:
            self._start_preview()

    def _camera_error(self, message: str) -> None:
        self._setup_failed = True
        self.readiness_progress.setRange(0, 100)
        self.readiness_progress.setValue(0)
        self.close_button.setText("Retry setup")
        self.status.setText("Guided enrollment stopped: camera or vision setup failed.")
        self.readiness_indicator.setText(
            "Check camera access, the recognition-model setup, and OpenCV installation."
        )
        self.services.identity_service.set_camera_state("unavailable", message)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle("Guided enrollment cannot continue")
        box.setText(
            "PrivSentinel could not access the camera or initialize local face guidance."
        )
        box.setInformativeText(
            f"PrivSentinel opens camera {self.services.settings.camera_index}. "
            "Allow desktop-app "
            "camera access in Windows privacy settings and close other apps using the "
            "camera. The recognition model will download only after a live camera "
            "frame is received. No enrollment template was saved."
        )
        box.setDetailedText(message)
        box.setStandardButtons(
            QMessageBox.StandardButton.Retry | QMessageBox.StandardButton.Close
        )
        if box.exec() == QMessageBox.StandardButton.Retry:
            self._restart_enrollment()
        else:
            self._camera_discovery_started = False
            self.start_button.setEnabled(False)
            self.readiness_indicator.setText(
                "Setup did not complete. Resolve the issue, then select Retry setup. "
                "Close this window with its title-bar close control to exit."
            )

    def closeEvent(self, event: QCloseEvent) -> None:
        if (
            self._preview_worker is not None
            and self._preview_worker.isRunning()
        ) or (
            self._speech_worker is not None
            and self._speech_worker.isRunning()
        ):
            event.ignore()
            self.done(self.DialogCode.Rejected)
            return
        super().closeEvent(event)
