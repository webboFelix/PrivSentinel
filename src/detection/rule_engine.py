"""Configurable detection rules with transparent rationale."""

from dataclasses import dataclass

from src.core.event_models import Detection, SecurityEvent


@dataclass(frozen=True, slots=True)
class DetectionRule:
    id: str
    title: str
    event_type: str
    severity: str
    description: str
    enabled: bool = True

    def evaluate(self, event: SecurityEvent) -> Detection | None:
        if not self.enabled or event.event_type != self.event_type:
            return None
        observation = (
            "confirmed event observation"
            if event.observed
            else "inferred event requiring review"
        )
        return Detection(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            rationale=f"{self.description}; matched {observation} from {event.source}.",
            event_id=event.id,
        )


class DetectionEngine:
    def __init__(self, rules: tuple[DetectionRule, ...] | None = None) -> None:
        self.rules = rules or (
            DetectionRule(
                "identity.unknown-face",
                "Unknown face detected",
                "unknown_face",
                "high",
                "Face similarity was below the configured recognition threshold",
            ),
            DetectionRule(
                "identity.liveness-failure",
                "Basic liveness check failed",
                "liveness_failure",
                "medium",
                "Configured basic motion heuristic was not observed",
            ),
            DetectionRule(
                "identity.multiple-faces",
                "Multiple faces present",
                "multiple_faces",
                "medium",
                "More than one face was detected by the configured model",
            ),
            DetectionRule(
                "endpoint.high-risk-process",
                "High-risk process observation",
                "suspicious_process",
                "high",
                "An enabled process rule matched collected process metadata",
            ),
        )
        identifiers = [rule.id for rule in self.rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Detection rule IDs must be unique.")

    def evaluate(self, event: SecurityEvent) -> list[Detection]:
        return [
            detection
            for rule in self.rules
            if (detection := rule.evaluate(event)) is not None
        ]