"""Typed identity metadata and verification event models."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class IdentityProfile:
    display_name: str
    enrolled_at: datetime
    model_name: str
    template_dimensions: int
    consent_recorded_at: datetime
    email: str = ""
    department: str = ""
    employee_id: str = ""
    machine_user: str = ""
    phone: str = ""
    profile_image: str = ""


@dataclass(frozen=True, slots=True)
class IdentityEvent:
    id: str
    occurred_at: datetime
    event_type: str
    state: str
    confidence: float | None
    liveness: str
    detail: str
    monitoring_seconds: float = 0.0