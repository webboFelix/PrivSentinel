"""Explicit weighted risk scoring; scores are inferences, not observations."""

from src.core.event_models import RiskAssessment, SecurityEvent


_SEVERITY_WEIGHT = {
    "info": 0.0,
    "low": 8.0,
    "medium": 20.0,
    "high": 35.0,
    "critical": 50.0,
}


def score_event(event: SecurityEvent) -> RiskAssessment:
    factors: list[str] = []
    severity = event.severity.casefold()
    score = _SEVERITY_WEIGHT.get(severity, 0.0)
    if severity not in _SEVERITY_WEIGHT:
        factors.append(f"Unrecognized severity {event.severity!r}; no severity points.")
    else:
        factors.append(f"Observed severity contributes {_SEVERITY_WEIGHT[severity]:.0f} points.")
    if event.event_type.casefold() in {
        "unknown_face",
        "liveness_failure",
        "suspicious_process",
    }:
        score += 15.0
        factors.append(f"Event type {event.event_type} adds 15 points.")
    if not event.observed:
        score *= 0.5
        factors.append("Inference-only event score is halved.")
    score = min(100.0, max(0.0, score))
    category = (
        "critical"
        if score >= 80
        else "high"
        if score >= 55
        else "medium"
        if score >= 25
        else "low"
    )
    return RiskAssessment(score, category, tuple(factors))