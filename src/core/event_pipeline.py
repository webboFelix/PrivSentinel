"""Normalized event pipeline: persistence, rules, alerts, and response audit."""

from __future__ import annotations

import logging
from typing import Any

from src.core.event_bus import EventBus
from src.core.event_models import SecurityEvent
from src.detection.correlation_engine import CorrelationEngine
from src.detection.risk_scoring import score_event
from src.detection.rule_engine import DetectionEngine
from src.security.response_policy import ResponsePolicy
from src.storage.repositories.security_repository import SecurityRepository


class EventPipeline:
    def __init__(
        self,
        repository: SecurityRepository,
        detection_engine: DetectionEngine | None = None,
        response_policy: ResponsePolicy | None = None,
    ) -> None:
        self.repository = repository
        self.detection_engine = detection_engine or DetectionEngine()
        self.response_policy = response_policy or ResponsePolicy()
        self.correlation = CorrelationEngine()
        self.bus = EventBus()
        self.logger = logging.getLogger("privsentinel.events")

    def publish(self, event: SecurityEvent) -> None:
        risk = score_event(event)
        inserted = self.repository.record_event(event, risk)
        if not inserted:
            return
        self.correlation.add(event)
        for detection in self.detection_engine.evaluate(event):
            self.repository.record_detection(event, detection)
            plan = self.response_policy.plan(event, detection)
            self.repository.record_audit(
                "event-pipeline",
                f"response.{plan.action}",
                plan.mode,
                f"{event.id}: {plan.reason}; rationale={detection.rationale}",
            )
            self.logger.info(
                "detection event_id=%s rule_id=%s severity=%s risk=%.1f "
                "observed=%s rationale=%s response=%s",
                event.id,
                detection.rule_id,
                detection.severity,
                risk.score,
                event.observed,
                detection.rationale,
                plan.mode,
            )
        self.bus.publish(event)
