from types import SimpleNamespace

import numpy as np
import pytest

from src.config.settings import AppSettings
from src.identity.liveness import BasicMotionLiveness
from src.identity.verification_policy import VerificationPolicy
from src.identity.workers import CameraMonitorWorker


def test_repeated_unknown_face_can_trigger_grace_period_lock():
    decision = VerificationPolicy().decide(
        "unknown_face",
        consecutive_failures=3,
        failure_limit=3,
        automatic_lock_enabled=True,
        action="lock_after_grace",
    )

    assert decision.action == "warn_then_lock"
    assert decision.requires_explicit_opt_in


def test_repeated_no_face_can_trigger_grace_period_lock():
    decision = VerificationPolicy().decide(
        "no_face_detected",
        consecutive_failures=3,
        failure_limit=3,
        automatic_lock_enabled=True,
        action="lock_after_grace",
    )

    assert decision.action == "warn_then_lock"
    assert decision.requires_explicit_opt_in
    assert "no-face" in decision.reason


@pytest.mark.parametrize(
    "state",
    (
        "no_face_detected",
        "low_confidence",
        "liveness_failure",
        "multiple_faces",
        "camera_unavailable",
    ),
)
def test_non_unknown_states_never_trigger_a_grace_period_lock(state):
    decision = VerificationPolicy().decide(
        state,
        consecutive_failures=10,
        failure_limit=1,
        automatic_lock_enabled=True,
        action="notify_only",
    )

    assert decision.action != "warn_then_lock"


def test_worker_emits_one_lock_warning_until_verification(tmp_path):
    worker = CameraMonitorWorker(AppSettings(), tmp_path, repository=None)
    requests = []
    worker.lockRequested.connect(lambda: requests.append(True))

    worker._request_lock_warning_once()
    worker._request_lock_warning_once()

    assert requests == [True]
    assert worker._lock_warning_issued

    worker._clear_lock_warning_after_verification()
    assert not worker._lock_warning_issued
    worker._request_lock_warning_once()

    assert requests == [True, True]


def test_camera_worker_warns_after_consecutive_no_face_samples(tmp_path):
    class FakeCapture:
        frames_read = 0

        def open(self):
            return None

        def read(self):
            self.frames_read += 1
            return np.zeros((2, 2, 3), dtype=np.uint8)

        def release(self):
            return None

    class FakeEngine:
        def load(self):
            return None

        def analyze(self, _frame):
            return []

    class FakeRepository:
        def profile(self):
            return SimpleNamespace(model_name="test")

        def templates(self):
            return ()

        def record_event(self, **_kwargs):
            return object()

    capture = FakeCapture()
    settings = AppSettings(
        automatic_lock_enabled=True,
        presence_loss_action="lock_after_grace",
        identity_failure_limit=2,
    )
    worker = CameraMonitorWorker(
        settings,
        tmp_path,
        FakeRepository(),
        camera_factory=lambda *_args: capture,
        engine_factory=lambda *_args, **_kwargs: FakeEngine(),
    )
    requests = []
    worker.lockRequested.connect(lambda: (requests.append(True), worker.stop()))

    worker.run()

    assert capture.frames_read == settings.identity_failure_limit
    assert requests == [True]


def test_still_face_remains_pending_instead_of_becoming_liveness_failure(
    tmp_path, monkeypatch
):
    class FakeCapture:
        def open(self):
            return None

        def read(self):
            return np.zeros((10, 10, 3), dtype=np.uint8)

        def release(self):
            return None

    class PendingMotion:
        sample_ready = True

        def __init__(self):
            pass

        def update(self, *_args):
            return "awaiting_basic_motion"

        def reset(self):
            return None

    class FakeEngine:
        def load(self):
            return None

        def analyze(self, _frame):
            return [
                SimpleNamespace(
                    bounding_box=(0, 0, 10, 10),
                    landmarks=np.zeros((5, 2), dtype=np.float32),
                    embedding=np.ones(4, dtype=np.float32),
                )
            ]

        def best_similarity(self, *_args):
            return 0.99

    class FakeRepository:
        def __init__(self):
            self.events = []

        def profile(self):
            return SimpleNamespace(model_name="test")

        def templates(self):
            return (object(),)

        def record_event(self, **event):
            self.events.append(event)
            return object()

    monkeypatch.setattr(
        "src.identity.workers.BasicMotionLiveness",
        PendingMotion,
    )
    repository = FakeRepository()
    worker = CameraMonitorWorker(
        AppSettings(liveness_enabled=True, capture_interval_ms=0),
        tmp_path,
        repository,
        camera_factory=lambda *_args: FakeCapture(),
        engine_factory=lambda *_args, **_kwargs: FakeEngine(),
    )
    states = []

    def stop_after_pending(state, _detail):
        states.append(state)
        if state == "low_confidence":
            worker.stop()

    worker.stateChanged.connect(stop_after_pending)

    worker.run()

    assert "liveness_failure" not in states
    assert repository.events[0]["state"] == "low_confidence"
    assert "not evidence of spoofing" in repository.events[0]["detail"]


def test_basic_motion_verification_stays_passed_after_motion_is_observed():
    liveness = BasicMotionLiveness(required_samples=3, minimum_motion=0.02)
    landmarks = np.zeros((5, 2), dtype=np.float32)

    assert liveness.update(landmarks, 100, 100) == "awaiting_basic_motion"
    assert liveness.update(landmarks + 2, 100, 100) == "awaiting_basic_motion"
    assert liveness.update(landmarks + 5, 100, 100) == "basic_motion_observed"
    assert liveness.update(landmarks + 5, 100, 100) == "basic_motion_observed"

    liveness.reset()

    assert liveness.result == "awaiting_basic_motion"


def test_matched_and_unmatched_faces_raise_tailgating_warning(tmp_path):
    class FakeCapture:
        def open(self):
            return None

        def read(self):
            return np.zeros((10, 10, 3), dtype=np.uint8)

        def release(self):
            return None

    class FakeEngine:
        def load(self):
            return None

        def analyze(self, _frame):
            return [
                SimpleNamespace(
                    bounding_box=(0, 0, 5, 5),
                    landmarks=np.zeros((5, 2), dtype=np.float32),
                    embedding=np.array([1.0], dtype=np.float32),
                ),
                SimpleNamespace(
                    bounding_box=(5, 5, 10, 10),
                    landmarks=np.zeros((5, 2), dtype=np.float32),
                    embedding=np.array([0.0], dtype=np.float32),
                ),
            ]

        def best_similarity(self, _templates, embedding):
            return float(embedding[0])

    class FakeRepository:
        def __init__(self):
            self.events = []

        def profile(self):
            return SimpleNamespace(model_name="test")

        def templates(self):
            return (object(),)

        def record_event(self, **event):
            self.events.append(event)
            return object()

    repository = FakeRepository()
    worker = CameraMonitorWorker(
        AppSettings(capture_interval_ms=0, verification_threshold=0.8),
        tmp_path,
        repository,
        camera_factory=lambda *_args: FakeCapture(),
        engine_factory=lambda *_args, **_kwargs: FakeEngine(),
    )
    states = []

    def stop_after_warning(state, _detail):
        states.append(state)
        if state == "multiple_faces":
            worker.stop()

    worker.stateChanged.connect(stop_after_warning)

    worker.run()

    assert "multiple_faces" in states
    assert repository.events[0]["state"] == "multiple_faces"
    assert "Possible tailgating" in repository.events[0]["detail"]
    assert "secure the workstation" in repository.events[0]["detail"]
