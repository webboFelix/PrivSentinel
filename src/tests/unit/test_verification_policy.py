import pytest

from src.config.settings import AppSettings
from src.identity.verification_policy import VerificationPolicy
from src.identity.workers import CameraMonitorWorker


def test_only_unknown_face_can_trigger_grace_period_lock():
    decision = VerificationPolicy().decide(
        "unknown_face",
        consecutive_failures=3,
        failure_limit=3,
        automatic_lock_enabled=True,
        unknown_face_action="lock_after_grace",
    )

    assert decision.action == "warn_then_lock"
    assert decision.requires_explicit_opt_in


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
        unknown_face_action="lock_after_grace",
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
