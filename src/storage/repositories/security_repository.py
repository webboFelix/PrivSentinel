"""Persistent security events, alerts, investigations, evidence, and audit data."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid

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
                    event.occurred_at.astimezone(timezone.utc).isoformat(),
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
        now = datetime.now(timezone.utc).isoformat()
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

    def list_alerts(self, limit: int = 500, status: str = "") -> list[dict[str, object]]:
        if not 1 <= limit <= 10000:
            raise ValueError("Alert limit must be between 1 and 10000.")
        where = "WHERE status = ?" if status else ""
        parameters: tuple[object, ...] = (status, limit) if status else (limit,)
        rows = self.database.fetchall(
            f"""
            SELECT a.*, e.source, e.event_type, e.description, e.observed, e.attributes_json
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
                (target, datetime.now(timezone.utc).isoformat(), alert_id),
            )
        self.record_audit("user", "alert.transition", "success", f"{alert_id}: {target}")

    def create_investigation(self, title: str) -> str:
        normalized = title.strip()
        if not normalized or len(normalized) > 200:
            raise ValueError("Investigation title must contain 1–200 characters.")
        identifier = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
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
        now = datetime.now(timezone.utc).isoformat()
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
                    datetime.now(timezone.utc).isoformat(),
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
                    datetime.now(timezone.utc).isoformat(),
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
