"""Persistent security events, alerts, investigations, evidence, and audit data."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import UTC, datetime

from src.alerts.alert_manager import validate_alert_transition
from src.alerts.deduplication import deduplication_key
from src.core.event_models import Detection, RiskAssessment, SecurityEvent
from src.storage.database import SQLiteDatabase


class SecurityRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    def record_event(self, event: SecurityEvent, risk: RiskAssessment) -> bool:
        encoded_attributes = json.dumps(
            event.attributes, ensure_ascii=False, sort_keys=True
        )
        with self.database.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO security_events (
                    id, occurred_at, source, event_type, severity,
                    description, observed, attributes_json, correlation_id, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.occurred_at.astimezone(UTC).isoformat(),
                    event.source,
                    event.event_type,
                    event.severity,
                    event.description[:2000],
                    int(event.observed),
                    encoded_attributes,
                    event.correlation_id,
                    risk.score,
                ),
            )
            return cursor.rowcount > 0

    def record_detection(self, event: SecurityEvent, detection: Detection) -> str:
        key = deduplication_key(detection.rule_id, event)
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            existing = connection.execute(
                """
                SELECT id FROM alerts
                WHERE rule_id = ? AND dedupe_key = ?
                  AND status IN ('open', 'acknowledged', 'investigating')
                ORDER BY created_at DESC LIMIT 1
                """,
                (detection.rule_id, key),
            ).fetchone()
            if existing is not None:
                return str(existing["id"])
            alert_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO alerts (
                    id, event_id, rule_id, dedupe_key, title, severity,
                    rationale, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (
                    alert_id,
                    event.id,
                    detection.rule_id,
                    key,
                    detection.title,
                    detection.severity,
                    detection.rationale,
                    now,
                    now,
                ),
            )
        return alert_id

    def list_events(self, limit: int = 500, query: str = "") -> list[dict[str, object]]:
        if not 1 <= limit <= 10000:
            raise ValueError("Event limit must be between 1 and 10000.")
        parameters: list[object] = []
        where = ""
        if query.strip():
            where = "WHERE source LIKE ? OR event_type LIKE ? OR description LIKE ?"
            token = f"%{query.strip()}%"
            parameters.extend((token, token, token))
        parameters.append(limit)
        rows = self.database.fetchall(
            f"SELECT * FROM security_events {where} ORDER BY occurred_at DESC LIMIT ?",
            tuple(parameters),
        )
        return [
            {
                "id": row["id"],
                "occurred_at": row["occurred_at"],
                "source": row["source"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "description": row["description"],
                "observed": bool(row["observed"]),
                "attributes": json.loads(row["attributes_json"]),
                "correlation_id": row["correlation_id"],
                "risk_score": row["risk_score"],
            }
            for row in rows
        ]

    def add_threat_indicator(
        self, value: str, indicator_type: str, source: str = "Local analyst"
    ) -> str:
        normalized_type = indicator_type.strip().casefold()
        if normalized_type not in {"ip", "domain", "sha256"}:
            raise ValueError("Indicator type must be IP, domain, or SHA-256.")
        normalized_value = value.strip()
        if normalized_type == "ip":
            try:
                normalized_value = str(ipaddress.ip_address(normalized_value))
            except ValueError as exc:
                raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc
        elif normalized_type == "domain":
            normalized_value = normalized_value.rstrip(".")
            try:
                normalized_value = normalized_value.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("Enter a valid domain name.") from exc
            labels = normalized_value.split(".")
            if (
                len(normalized_value) > 253
                or len(labels) < 2
                or any(
                    not label
                    or len(label) > 63
                    or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                    for label in labels
                )
            ):
                raise ValueError("Enter a valid fully-qualified domain name.")
        else:
            if not re.fullmatch(r"[a-fA-F0-9]{64}", normalized_value):
                raise ValueError("Enter a 64-character SHA-256 digest.")
            normalized_value = normalized_value.lower()
        normalized_source = source.strip()
        if not normalized_source or len(normalized_source) > 200:
            raise ValueError("Indicator source must contain 1–200 characters.")

        identifier = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM threat_indicators "
                "WHERE indicator_type = ? AND value = ?",
                (normalized_type, normalized_value),
            ).fetchone()
            if exists is not None:
                raise ValueError("That indicator is already in the local list.")
            connection.execute(
                "INSERT INTO threat_indicators VALUES (?, ?, ?, ?, ?)",
                (
                    identifier,
                    normalized_type,
                    normalized_value,
                    normalized_source,
                    created_at,
                ),
            )
        self.record_audit(
            "user",
            "threat-intelligence.indicator.add",
            "success",
            f"{normalized_type}:{normalized_value}",
        )
        return identifier

    def list_threat_indicators(self) -> list[dict[str, object]]:
        return [
            dict(row)
            for row in self.database.fetchall(
                "SELECT id, indicator_type, value, source, created_at "
                "FROM threat_indicators ORDER BY created_at DESC"
            )
        ]

    def threat_indicator_match_counts(
        self, limit: int = 10000
    ) -> dict[str, int]:
        if not 1 <= limit <= 10000:
            raise ValueError("Indicator match limit must be between 1 and 10000.")
        indicators = self.list_threat_indicators()
        events = self.list_events(limit=limit)
        match_counts: dict[str, int] = {}
        for indicator in indicators:
            pattern = _indicator_pattern(
                str(indicator["value"]),
                str(indicator["indicator_type"]),
            )
            match_counts[str(indicator["id"])] = sum(
                _event_matches_pattern(event, pattern) for event in events
            )
        return match_counts

    def delete_threat_indicator(self, indicator_id: str) -> None:
        with self.database.transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM threat_indicators WHERE id = ?", (indicator_id,)
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Threat indicator not found: {indicator_id}")
        self.record_audit(
            "user",
            "threat-intelligence.indicator.delete",
            "success",
            indicator_id,
        )

    def list_threat_indicator_matches(
        self, indicator_id: str, limit: int = 10000
    ) -> list[dict[str, object]]:
        if not 1 <= limit <= 10000:
            raise ValueError("Indicator match limit must be between 1 and 10000.")
        indicator = self.database.fetchone(
            "SELECT indicator_type, value FROM threat_indicators WHERE id = ?",
            (indicator_id,),
        )
        if indicator is None:
            raise KeyError(f"Threat indicator not found: {indicator_id}")
        indicator_type = str(indicator["indicator_type"])
        pattern = _indicator_pattern(
            str(indicator["value"]), indicator_type
        )
        events = self.list_events(limit=limit)
        return [
            event
            for event in events
            if _event_matches_pattern(event, pattern)
        ]

    def create_investigation_for_alert(self, alert_id: str) -> str:
        investigation_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            alert = connection.execute(
                "SELECT event_id, status, title FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()
            if alert is None:
                raise KeyError(f"Alert not found: {alert_id}")
            status = str(alert["status"])
            if status in {"open", "acknowledged"}:
                validate_alert_transition(status, "investigating")
                connection.execute(
                    "UPDATE alerts SET status = 'investigating', updated_at = ? "
                    "WHERE id = ?",
                    (now, alert_id),
                )
            elif status != "investigating":
                raise ValueError(
                    f"Cannot create an investigation for an alert in {status!r} status."
                )
            title = str(alert["title"])[:180]
            connection.execute(
                "INSERT INTO investigations VALUES (?, ?, 'open', ?, ?)",
                (investigation_id, f"Alert investigation: {title}", now, now),
            )
            connection.execute(
                "INSERT INTO investigation_events VALUES (?, ?)",
                (investigation_id, alert["event_id"]),
            )
        self.record_audit(
            "user",
            "investigation.create-from-alert",
            "success",
            f"{alert_id}:{investigation_id}",
        )
        return investigation_id

    def list_alerts(self, limit: int = 500, status: str = "") -> list[dict[str, object]]:
        if not 1 <= limit <= 10000:
            raise ValueError("Alert limit must be between 1 and 10000.")
        where = "WHERE status = ?" if status else ""
        parameters: tuple[object, ...] = (status, limit) if status else (limit,)
        rows = self.database.fetchall(
            f"""
            SELECT a.*, e.source, e.event_type, e.description, e.observed,
                   e.attributes_json, e.risk_score
            FROM alerts a JOIN security_events e ON e.id = a.event_id
            {where} ORDER BY a.created_at DESC LIMIT ?
            """,
            parameters,
        )
        return [
            {
                "id": row["id"],
                "event_id": row["event_id"],
                "rule_id": row["rule_id"],
                "title": row["title"],
                "severity": row["severity"],
                "rationale": row["rationale"],
                "status": row["status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "source": row["source"],
                "event_type": row["event_type"],
                "description": row["description"],
                "observed": bool(row["observed"]),
                "attributes": json.loads(row["attributes_json"]),
                "risk_score": row["risk_score"],
            }
            for row in rows
        ]

    def transition_alert(self, alert_id: str, target: str) -> None:
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT status FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Alert not found: {alert_id}")
            validate_alert_transition(row["status"], target)
            connection.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                (target, datetime.now(UTC).isoformat(), alert_id),
            )
        self.record_audit("user", "alert.transition", "success", f"{alert_id}: {target}")

    def create_investigation(self, title: str) -> str:
        normalized = title.strip()
        if not normalized or len(normalized) > 200:
            raise ValueError("Investigation title must contain 1–200 characters.")
        identifier = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO investigations VALUES (?, ?, 'open', ?, ?)",
                (identifier, normalized, now, now),
            )
        self.record_audit("user", "investigation.create", "success", identifier)
        return identifier

    def list_investigations(self) -> list[dict[str, object]]:
        rows = self.database.fetchall(
            """
            SELECT i.*, COUNT(n.id) AS note_count, COUNT(DISTINCT e.event_id) AS event_count
            FROM investigations i
            LEFT JOIN investigation_notes n ON n.investigation_id = i.id
            LEFT JOIN investigation_events e ON e.investigation_id = i.id
            GROUP BY i.id ORDER BY i.updated_at DESC
            """
        )
        return [
            {
                "id": row["id"],
                "title": row["title"],
                "status": row["status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "note_count": row["note_count"],
                "event_count": row["event_count"],
            }
            for row in rows
        ]

    def add_investigation_note(self, investigation_id: str, body: str) -> str:
        note = body.strip()
        if not note or len(note) > 10000:
            raise ValueError("Investigation note must contain 1–10000 characters.")
        note_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(f"Investigation not found: {investigation_id}")
            connection.execute(
                "INSERT INTO investigation_notes VALUES (?, ?, ?, ?)",
                (note_id, investigation_id, now, note),
            )
            connection.execute(
                "UPDATE investigations SET updated_at = ? WHERE id = ?",
                (now, investigation_id),
            )
        self.record_audit("user", "investigation.note", "success", investigation_id)
        return note_id

    def list_investigation_notes(
        self, investigation_id: str
    ) -> list[dict[str, object]]:
        exists = self.database.fetchone(
            "SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)
        )
        if exists is None:
            raise KeyError(f"Investigation not found: {investigation_id}")
        return [
            dict(row)
            for row in self.database.fetchall(
                "SELECT id, created_at, body FROM investigation_notes "
                "WHERE investigation_id = ? ORDER BY created_at",
                (investigation_id,),
            )
        ]

    def set_investigation_status(self, investigation_id: str, status: str) -> None:
        if status not in {"open", "in_progress", "closed"}:
            raise ValueError(f"Unknown investigation status: {status!r}.")
        with self.database.transaction() as connection:
            cursor = connection.execute(
                "UPDATE investigations SET status = ?, updated_at = ? WHERE id = ?",
                (
                    status,
                    datetime.now(UTC).isoformat(),
                    investigation_id,
                ),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Investigation not found: {investigation_id}")
        self.record_audit(
            "user", "investigation.status", "success", f"{investigation_id}: {status}"
        )

    def link_event_to_investigation(
        self, investigation_id: str, event_id: str
    ) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO investigation_events VALUES (?, ?)",
                (investigation_id, event_id),
            )

    def add_evidence(
        self,
        title: str,
        evidence_type: str,
        path: str,
        sha256: str,
        investigation_id: str | None = None,
    ) -> str:
        identifier = str(uuid.uuid4())
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO evidence_items VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    identifier,
                    investigation_id,
                    title[:200],
                    evidence_type[:80],
                    path,
                    sha256,
                    datetime.now(UTC).isoformat(),
                ),
            )
        self.record_audit("user", "evidence.add", "success", identifier)
        return identifier

    def list_evidence(self) -> list[dict[str, object]]:
        rows = self.database.fetchall(
            "SELECT * FROM evidence_items ORDER BY added_at DESC"
        )
        return [dict(row) for row in rows]

    def record_audit(self, actor: str, action: str, outcome: str, details: str) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO audit_records VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    datetime.now(UTC).isoformat(),
                    actor[:120],
                    action[:120],
                    outcome[:40],
                    details[:2000],
                ),
            )

    def list_audit(self, limit: int = 500) -> list[dict[str, object]]:
        if not 1 <= limit <= 10000:
            raise ValueError("Audit limit must be between 1 and 10000.")
        return [
            dict(row)
            for row in self.database.fetchall(
                "SELECT * FROM audit_records ORDER BY occurred_at DESC LIMIT ?",
                (limit,),
            )
        ]


def _indicator_pattern(value: str, indicator_type: str) -> re.Pattern[str]:
    if indicator_type == "domain":
        return re.compile(
            rf"(?<![a-z0-9.-]){re.escape(value)}(?![a-z0-9.-])",
            re.IGNORECASE,
        )
    if indicator_type == "sha256":
        return re.compile(
            rf"(?<![a-f0-9]){re.escape(value)}(?![a-f0-9])",
            re.IGNORECASE,
        )
    return re.compile(
        rf"(?<![a-f0-9:.]){re.escape(value)}(?![a-f0-9:.])",
        re.IGNORECASE,
    )


def _event_matches_pattern(
    event: dict[str, object], pattern: re.Pattern[str]
) -> bool:
    attributes = event.get("attributes")
    candidates: list[str] = [str(event.get("description", ""))]

    def collect_strings(item: object) -> None:
        if isinstance(item, dict):
            for nested in item.values():
                collect_strings(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                collect_strings(nested)
        elif isinstance(item, str):
            candidates.append(item)

    collect_strings(attributes)
    return any(pattern.search(candidate) for candidate in candidates)
