from datetime import UTC, datetime, timedelta

from src.identity.security_score import calculate_identity_security_score
from src.storage.models import IdentityEvent


def _event(
    state: str,
    *,
    confidence: float | None = None,
    liveness: str = "not_checked",
    occurred_at: datetime | None = None,
) -> IdentityEvent:
    return IdentityEvent(
        id=state,
        occurred_at=occurred_at or datetime(2025, 1, 1, tzinfo=UTC),
        event_type="verification",
        state=state,
        confidence=confidence,
        liveness=liveness,
        detail="",
    )


def test_score_uses_requested_weights_for_measured_components():
    now = datetime(2025, 1, 1, 1, tzinfo=UTC)
    events = [
        _event(
            "recognized",
            confidence=0.8,
            liveness="basic_motion_observed",
            occurred_at=now,
        ),
        _event(
            "liveness_failure",
            confidence=0.6,
            liveness="failed",
            occurred_at=now - timedelta(minutes=1),
        ),
    ]

    result = calculate_identity_security_score(
        events,
        0.9,
        now=now,
        latest_successful_at=now,
    )

    assert result.score == 69
    assert result.measured_checks == 5
    assert result.measured_weight == 100
    assert "Face-match quality: 70/100 (40% weight)" in result.details
    assert "Liveness / anti-spoofing: 50/100 (25% weight)" in result.details
    assert "Enrollment quality: 90/100 (15% weight)" in result.details


def test_partial_score_normalizes_only_real_measurements():
    result = calculate_identity_security_score([], 0.8)

    assert result.score == 80
    assert result.measured_checks == 1
    assert result.measured_weight == 15
    assert "Verification stability: not measured" in result.details


def test_score_is_unavailable_without_any_measurable_component():
    result = calculate_identity_security_score([], None)

    assert result.score is None
    assert result.measured_checks == 0
    assert result.measured_weight == 0


def test_freshness_decays_to_zero_after_thirty_days():
    now = datetime(2025, 2, 1, tzinfo=UTC)

    result = calculate_identity_security_score(
        [],
        None,
        now=now,
        latest_successful_at=now - timedelta(days=30),
    )

    assert result.score == 0
    assert result.measured_weight == 10


def test_pending_liveness_is_not_counted_as_a_failed_check():
    result = calculate_identity_security_score(
        [_event("low_confidence", liveness="awaiting_basic_motion")],
        None,
    )

    assert result.measured_weight == 0
    assert "Liveness / anti-spoofing: not measured" in result.details
