"""Measurable identity-security score components for the dashboard."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from math import fsum

from src.storage.models import IdentityEvent

IDENTITY_SCORE_WEIGHTS: dict[str, int] = {
    "Face-match quality": 40,
    "Liveness / anti-spoofing": 25,
    "Enrollment quality": 15,
    "Verification freshness": 10,
    "Verification stability": 10,
}
_VERIFICATION_STATES = frozenset(
    {
        "recognized",
        "unknown_face",
        "low_confidence",
        "liveness_failure",
        "no_face_detected",
        "multiple_faces",
    }
)
_LIVENESS_NOT_CHECKED = frozenset({"disabled", "not_checked"})
_LIVENESS_PENDING = frozenset({"awaiting_basic_motion"})
_LIVENESS_PASSED = frozenset({"basic_motion_observed", "passed"})
_FRESHNESS_WINDOW_SECONDS = 30 * 24 * 60 * 60
_MAX_RECENT_EVENTS = 20


@dataclass(frozen=True, slots=True)
class IdentitySecurityScore:
    score: int | None
    measured_checks: int
    measured_weight: int
    details: str


def calculate_identity_security_score(
    events: Sequence[IdentityEvent],
    enrollment_quality: float | None,
    *,
    now: datetime | None = None,
    latest_successful_at: datetime | None = None,
) -> IdentitySecurityScore:
    """Return a partial weighted average using only checks with real measurements."""
    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=UTC)
    recent = sorted(events, key=lambda event: event.occurred_at, reverse=True)[
        :_MAX_RECENT_EVENTS
    ]
    components: dict[str, int | None] = {
        name: None for name in IDENTITY_SCORE_WEIGHTS
    }

    confidences = [
        event.confidence
        for event in recent
        if event.confidence is not None
        and event.state.casefold() in _VERIFICATION_STATES
    ]
    if confidences:
        components["Face-match quality"] = round(
            fsum(min(1.0, max(0.0, value)) for value in confidences)
            * 100
            / len(confidences)
        )

    liveness_checks = [
        event.liveness.casefold()
        for event in recent
        if event.liveness.casefold() not in _LIVENESS_NOT_CHECKED
        and event.liveness.casefold() not in _LIVENESS_PENDING
    ]
    if liveness_checks:
        passed_checks = sum(value in _LIVENESS_PASSED for value in liveness_checks)
        components["Liveness / anti-spoofing"] = round(
            passed_checks * 100 / len(liveness_checks)
        )

    if enrollment_quality is not None:
        components["Enrollment quality"] = round(
            min(1.0, max(0.0, enrollment_quality)) * 100
        )

    if latest_successful_at is None:
        successful_events = [
            event
            for event in recent
            if event.state.casefold() == "recognized"
        ]
        latest_successful_at = (
            successful_events[0].occurred_at if successful_events else None
        )
    if latest_successful_at is not None:
        latest = latest_successful_at
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=UTC)
        age_seconds = max(0.0, (current_time - latest.astimezone(UTC)).total_seconds())
        components["Verification freshness"] = round(
            max(0.0, 1.0 - age_seconds / _FRESHNESS_WINDOW_SECONDS) * 100
        )

    verification_results = [
        event.state.casefold()
        for event in recent
        if event.state.casefold() in _VERIFICATION_STATES
    ]
    if len(verification_results) >= 2:
        recognized = sum(state == "recognized" for state in verification_results)
        components["Verification stability"] = round(
            recognized * 100 / len(verification_results)
        )

    weighted_components = [
        (IDENTITY_SCORE_WEIGHTS[name], value)
        for name, value in components.items()
        if value is not None
    ]
    measured_weight = sum(weight for weight, _ in weighted_components)
    score = (
        round(fsum(weight * value for weight, value in weighted_components) / measured_weight)
        if measured_weight
        else None
    )
    details = "; ".join(
        (
            f"{name}: {value}/100 ({IDENTITY_SCORE_WEIGHTS[name]}% weight)"
            if value is not None
            else f"{name}: not measured"
        )
        for name, value in components.items()
    )
    return IdentitySecurityScore(
        score=score,
        measured_checks=len(weighted_components),
        measured_weight=measured_weight,
        details=details,
    )
