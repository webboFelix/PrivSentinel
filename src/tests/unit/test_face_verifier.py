import threading
from types import SimpleNamespace

import cv2
import numpy as np
import pytest

from src.config.settings import AppSettings
from src.identity.face_detector import FaceDetector
from src.identity.face_verifier import (
    FaceRecognitionEngine,
    RecognitionModelUnavailable,
    recognition_model_is_installed,
)
from src.identity.workers import (
    CameraMonitorWorker,
    CameraPreviewWorker,
    EmbeddingWorker,
)


def test_aggregate_embeddings_returns_normalized_template_and_consistency():
    embeddings = [
        np.array([1.0, 0.0, 0.0], dtype=np.float32),
        np.array([0.8, 0.6, 0.0], dtype=np.float32),
    ]

    template, consistency = FaceRecognitionEngine.aggregate_embeddings(embeddings)

    assert np.isclose(np.linalg.norm(template), 1.0)
    assert np.isclose(consistency, np.sqrt(0.9))
    assert 0.0 <= consistency <= 1.0


def test_best_similarity_matches_either_saved_pose_template():
    templates = np.asarray(
        [[1.0, 0.0], [0.0, 1.0]],
        dtype=np.float32,
    )

    assert FaceRecognitionEngine.best_similarity(
        templates,
        np.asarray([0.0, 1.0], dtype=np.float32),
    ) == pytest.approx(1.0)


def test_glasses_detector_requires_frame_structure_over_both_eyes():
    frame = np.full((160, 160, 3), 180, dtype=np.uint8)
    landmarks = np.asarray(
        [[50, 65], [110, 65], [80, 90], [60, 115], [100, 115]],
        dtype=np.float32,
    )
    without_glasses = frame.copy()
    for eye_x in (50, 110):
        cv2.rectangle(
            frame,
            (eye_x - 15, 54),
            (eye_x + 15, 76),
            (20, 20, 20),
            2,
        )

    assert FaceDetector.glasses_visible(frame, landmarks)
    assert not FaceDetector.glasses_visible(without_glasses, landmarks)


def test_recognition_model_is_installed_requires_core_model_files(tmp_path):
    model_directory = tmp_path / "models" / "buffalo_l"
    model_directory.mkdir(parents=True)
    (model_directory / "det_10g.onnx").write_bytes(b"detector")

    assert not recognition_model_is_installed(tmp_path)

    (model_directory / "w600k_r50.onnx").write_bytes(b"recognizer")

    assert recognition_model_is_installed(tmp_path)


def test_incomplete_recognition_model_requires_download_consent(tmp_path):
    model_directory = tmp_path / "models" / "buffalo_l"
    model_directory.mkdir(parents=True)
    (model_directory / "det_10g.onnx").write_bytes(b"detector")
    engine = FaceRecognitionEngine(tmp_path)

    with pytest.raises(RecognitionModelUnavailable, match="not fully installed"):
        engine.load()


@pytest.mark.parametrize(
    "embeddings",
    [
        [],
        [np.array([0.0, 0.0], dtype=np.float32)],
        [
            np.array([1.0, 0.0], dtype=np.float32),
            np.array([1.0, 0.0, 0.0], dtype=np.float32),
        ],
        [np.array([np.nan, 1.0], dtype=np.float32)],
    ],
)
def test_aggregate_embeddings_rejects_invalid_samples(embeddings):
    with pytest.raises(ValueError):
        FaceRecognitionEngine.aggregate_embeddings(embeddings)


@pytest.mark.parametrize(
    ("yaw", "pitch"),
    [
        (0.0, 0.0),
        (16.0, 0.0),
        (-16.0, 0.0),
        (0.0, 16.0),
        (0.0, -16.0),
    ],
)
def test_estimate_head_pose_recovers_guidance_angles(yaw, pitch):
    width, height = 640, 480
    focal_length = float(max(width, height))
    camera_matrix = np.asarray(
        [
            [focal_length, 0.0, width / 2],
            [0.0, focal_length, height / 2],
            [0.0, 0.0, 1.0],
        ],
        dtype=np.float32,
    )
    rotation_vector, _ = cv2.Rodrigues(
        np.deg2rad([pitch, yaw, 0.0]).astype(np.float32)
    )
    image_points, _ = cv2.projectPoints(
        FaceRecognitionEngine._FACE_MODEL_POINTS,
        rotation_vector,
        np.asarray([[0.0], [0.0], [600.0]], dtype=np.float32),
        camera_matrix,
        np.zeros((4, 1), dtype=np.float32),
    )

    pose = FaceRecognitionEngine.estimate_head_pose(
        image_points.reshape(5, 2),
        width,
        height,
    )

    assert pose.yaw_degrees == pytest.approx(yaw, abs=0.5)
    assert pose.pitch_degrees == pytest.approx(pitch, abs=0.5)


def test_embedding_worker_analyzes_each_sample_and_emits_confidence(
    monkeypatch, tmp_path
):
    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def analyze(self, frame):
            return [
                SimpleNamespace(
                    embedding=frame,
                    bounding_box=(0, 0, 100, 100),
                )
            ]

        aggregate_embeddings = staticmethod(
            FaceRecognitionEngine.aggregate_embeddings
        )

    monkeypatch.setattr("src.identity.workers.FaceRecognitionEngine", FakeEngine)
    worker = EmbeddingWorker(
        tmp_path,
        [
            np.array([1.0, 0.0], dtype=np.float32),
            np.array([0.8, 0.6], dtype=np.float32),
        ],
    )
    completed = []
    failures = []
    statuses = []
    worker.completed.connect(lambda template, score: completed.append((template, score)))
    worker.failed.connect(failures.append)
    worker.status.connect(statuses.append)

    worker.run()

    assert not failures
    assert len(completed) == 1
    assert np.isclose(completed[0][1], np.sqrt(0.9))
    assert statuses[0].startswith("Preparing the recognition model")
    assert statuses[1:] == [
        "Analyzing sample 1 of 2…",
        "Analyzing sample 2 of 2…",
    ]


def test_camera_preview_is_emitted_while_model_is_loading(monkeypatch, tmp_path):
    first_preview_ready = threading.Event()
    model_load_started = threading.Event()
    model_load_continue = threading.Event()
    worker_reference = []
    preview_frames = []

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def load(self):
            assert first_preview_ready.is_set()
            model_load_started.set()
            if not model_load_continue.wait(2):
                raise RuntimeError("Test model load timed out.")

        def analyze(self, frame):
            return []

    class FakeEyeCascade:
        def empty(self):
            return False

    class FakeCamera:
        def __init__(self, *_args):
            self.read_count = 0

        def open(self):
            pass

        def read(self):
            self.read_count += 1
            if self.read_count == 1:
                return np.zeros((480, 640, 3), dtype=np.uint8)
            elif self.read_count == 2:
                assert model_load_started.wait(2)
                model_load_continue.set()
            elif self.read_count == 3:
                worker_reference[0].stop()
            return np.zeros((480, 640, 3), dtype=np.uint8)

        def release(self):
            model_load_continue.set()

    monkeypatch.setattr("src.identity.workers.FaceRecognitionEngine", FakeEngine)
    monkeypatch.setattr(
        "src.identity.workers.cv2.CascadeClassifier",
        lambda _path: FakeEyeCascade(),
    )
    worker = CameraPreviewWorker(
        0,
        640,
        480,
        models_directory=tmp_path,
        camera_factory=FakeCamera,
    )
    worker_reference.append(worker)

    def record_preview(*args):
        preview_frames.append(args)
        guidance = args[-1]
        if guidance and guidance.get("camera_check"):
            first_preview_ready.set()

    worker.previewReady.connect(record_preview)

    worker.run()

    assert any(
        guidance is not None and guidance.get("model_loading")
        for _image, _faces, _frame, _quality, guidance in preview_frames
    )
    assert preview_frames[0][-1] == {"camera_check": True}
    assert any(
        guidance is not None and guidance.get("model_ready")
        for _image, _faces, _frame, _quality, guidance in preview_frames
    )


def test_camera_failure_prevents_recognition_model_download(monkeypatch, tmp_path):
    model_load_called = []
    camera_errors = []

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def load(self):
            model_load_called.append(True)

    class FakeCamera:
        def __init__(self, *_args):
            pass

        def open(self):
            pass

        def read(self):
            raise OSError("Camera did not provide a frame.")

        def release(self):
            pass

    monkeypatch.setattr("src.identity.workers.FaceRecognitionEngine", FakeEngine)
    worker = CameraPreviewWorker(
        1,
        640,
        480,
        models_directory=tmp_path,
        camera_factory=FakeCamera,
    )
    worker.cameraError.connect(camera_errors.append)

    worker.run()

    assert not model_load_called
    assert camera_errors == [
        "Camera 1 could not provide a live frame: Camera did not provide a frame."
    ]


def test_model_initialization_failure_is_reported_before_ready(monkeypatch, tmp_path):
    preview_frames = []
    camera_errors = []

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def load(self):
            raise ValueError("Model files are incomplete.")

    class FakeCamera:
        def __init__(self, *_args):
            pass

        def open(self):
            pass

        def read(self):
            return np.zeros((480, 640, 3), dtype=np.uint8)

        def release(self):
            pass

    monkeypatch.setattr("src.identity.workers.FaceRecognitionEngine", FakeEngine)
    worker = CameraPreviewWorker(
        0,
        640,
        480,
        models_directory=tmp_path,
        camera_factory=FakeCamera,
    )
    worker.previewReady.connect(lambda *args: preview_frames.append(args))
    worker.cameraError.connect(camera_errors.append)

    worker.run()

    assert camera_errors
    assert "Model files are incomplete." in camera_errors[0]
    assert not any(
        guidance is not None and guidance.get("model_ready")
        for *_args, guidance in preview_frames
    )


def test_camera_monitor_uses_configured_camera_index(tmp_path):
    opened_indexes = []

    class FakeRepository:
        def profile(self):
            return SimpleNamespace(model_name="test-model")

        def templates(self):
            return np.ones((2, 32), dtype=np.float32)

    class FakeEngine:
        def __init__(self, *_args, **_kwargs):
            pass

        def load(self):
            pass

    worker_reference = []

    class FakeCamera:
        def __init__(self, index, _width, _height):
            opened_indexes.append(index)

        def open(self):
            worker_reference[0].stop()

        def release(self):
            pass

    worker = CameraMonitorWorker(
        AppSettings(camera_index=7),
        tmp_path,
        FakeRepository(),
        camera_factory=FakeCamera,
        engine_factory=FakeEngine,
    )
    worker_reference.append(worker)

    worker.run()

    assert opened_indexes == [7]