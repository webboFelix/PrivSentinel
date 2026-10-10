"""Normalized event and detection models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    source: str
    event_type: str
    severity: str
    description: str
    attributes: dict[str, Any] = field(default_factory=dict)
    observed: bool = True
    correlation_id: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    rationale: str
    event_id: str


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float
    category: str
    factors: tuple[str, ...]