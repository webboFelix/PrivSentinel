"""Alert state transition validation."""

_TRANSITIONS = {
    "open": {"acknowledged", "investigating", "dismissed"},
    "acknowledged": {"investigating", "resolved", "dismissed", "open"},
    "investigating": {"acknowledged", "resolved", "dismissed", "open"},
    "resolved": {"open"},
    "dismissed": {"open"},
}


def validate_alert_transition(current: str, target: str) -> None:
    if current not in _TRANSITIONS:
        raise ValueError(f"Unknown alert status: {current!r}.")
    if target not in _TRANSITIONS[current]:
        raise ValueError(f"Alert cannot transition from {current!r} to {target!r}.")