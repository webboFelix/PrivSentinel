"""Audited dry-run response policy; destructive response is intentionally absent."""

from dataclasses import dataclass

from src.core.event_models import Detection, SecurityEvent


@dataclass(frozen=True, slots=True)
class ResponsePlan:
    action: str
    mode: str
    executed: bool
    reason: str


class ResponsePolicy:
    def __init__(self, dry_run: bool = True, automated_response_enabled: bool = False):
        self.dry_run = dry_run
        self.automated_response_enabled = automated_response_enabled

    def plan(self, event: SecurityEvent, detection: Detection) -> ResponsePlan:
        action = "request_review" if detection.severity in {"high", "critical"} else "notify"
        if self.dry_run or not self.automated_response_enabled:
            return ResponsePlan(
                action,
                "dry_run",
                False,
                "Recorded proposal only; automated response is disabled.",
            )
        return ResponsePlan(
            action,
            "automated",
            action == "notify",
            "Only non-destructive notifications can be executed.",
        )
