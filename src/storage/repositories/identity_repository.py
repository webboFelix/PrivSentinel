"""SQLite persistence for DPAPI-protected identity templates and metadata."""

from __future__ import annotations

from datetime import datetime, timezone
import io
import uuid

import numpy as np

from src.security.secret_store import WindowsSecretStore
from src.storage.database import SQLiteDatabase
from src.storage.models import IdentityEvent, IdentityProfile


class IdentityRepository:
    _SECRET_NAME = "face-template"

    def __init__(self, database: SQLiteDatabase, secrets: WindowsSecretStore) -> None:
        self.database = database
        self.secrets = secrets

    def profile(self) -> IdentityProfile | None:
        row = self.database.fetchone(
            "SELECT display_name, enrolled_at, model_name, template_dimensions, "
            "consent_recorded_at FROM identity_profile WHERE id = 1"
        )
        if row is None:
            return None
        return IdentityProfile(
            display_name=row["display_name"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            model_name=row["model_name"],
            template_dimensions=row["template_dimensions"],
            consent_recorded_at=datetime.fromisoformat(row["consent_recorded_at"]),
        )

    def template(self) -> np.ndarray | None:
        encrypted = self.secrets.get(self._SECRET_NAME)
        if encrypted is None:
            return None
        try:
            vector = np.load(io.BytesIO(encrypted), allow_pickle=False)
        except (ValueError, OSError) as exc:
            raise ValueError("Stored face template is invalid or unreadable.") from exc
        if vector.ndim != 1 or vector.size == 0 or not np.isfinite(vector).all():
            raise ValueError("Stored face template failed validation.")
        return vector.astype(np.float32, copy=False)

    def enroll(
        self,
        display_name: str,
        embedding: np.ndarray,
        model_name: str,
        consent_recorded_at: datetime,
    ) -> IdentityProfile:
        name = display_name.strip()
        vector = np.asarray(embedding, dtype=np.float32)
        if not name or len(name) > 120:
            raise ValueError("Display name must contain between 1 and 120 characters.")
        if (
            vector.ndim != 1
            or vector.size < 32
            or not np.isfinite(vector).all()
            or np.linalg.norm(vector) == 0
        ):
            raise ValueError("Face embedding must be a finite, non-zero vector.")
        if not model_name or len(model_name) > 120:
            raise ValueError("A valid recognition model name is required.")
        now = datetime.now(timezone.utc)
        stream = io.BytesIO()
        np.save(stream, vector / np.linalg.norm(vector), allow_pickle=False)
        previous_template = self.secrets.get(self._SECRET_NAME)
        self.secrets.set(self._SECRET_NAME, stream.getvalue())
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO identity_profile (
                        id, display_name, enrolled_at, model_name,
                        template_dimensions, consent_recorded_at
                    ) VALUES (1, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        display_name=excluded.display_name,
                        enrolled_at=excluded.enrolled_at,
                        model_name=excluded.model_name,
                        template_dimensions=excluded.template_dimensions,
                        consent_recorded_at=excluded.consent_recorded_at
                    """,
                    (
                        name,
                        now.isoformat(),
                        model_name,
                        int(vector.size),
                        consent_recorded_at.astimezone(timezone.utc).isoformat(),
                    ),
                )
        except BaseException:
            if previous_template is None:
                self.secrets.delete(self._SECRET_NAME)
            else:
                self.secrets.set(self._SECRET_NAME, previous_template)
            raise
        return IdentityProfile(name, now, model_name, int(vector.size), consent_recorded_at)

    def delete_profile(self) -> bool:
        had_profile = self.profile() is not None
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM identity_profile WHERE id = 1")
        self.secrets.delete(self._SECRET_NAME)
        return had_profile

    def record_event(
        self,
        event_type: str,
        state: str,
        confidence: float | None,
        liveness: str,
        detail: str,
        monitoring_seconds: float = 0.0,
        occurred_at: datetime | None = None,
    ) -> IdentityEvent:
        when = occurred_at or datetime.now(timezone.utc)
        if confidence is not None and not 0 <= confidence <= 1:
            raise ValueError("Confidence must be between 0 and 1.")
        if not all((event_type, state, liveness)):
            raise ValueError("Event type, state, and liveness are required.")
        if monitoring_seconds < 0:
            raise ValueError("Monitoring duration cannot be negative.")
        event = IdentityEvent(
            id=str(uuid.uuid4()),
            occurred_at=when,
            event_type=event_type,
            state=state,
            confidence=confidence,
            liveness=liveness,
            detail=detail[:1000],
            monitoring_seconds=monitoring_seconds,
        )
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO identity_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.id,
                    event.occurred_at.astimezone(timezone.utc).isoformat(),
                    event.event_type,
                    event.state,
                    event.confidence,
                    event.liveness,
                    event.detail,
                    event.monitoring_seconds,
                ),
            )
        return event

    def list_events(
        self,
        limit: int = 500,
        query: str = "",
        state: str = "",
    ) -> list[IdentityEvent]:
        if not 1 <= limit <= 10000:
            raise ValueError("Event limit must be between 1 and 10000.")
        clauses: list[str] = []
        parameters: list[object] = []
        if query.strip():
            wildcard_query = f"%{query.strip()}%"
            clauses.append(
                "(event_type LIKE ? OR state LIKE ? OR detail LIKE ? OR liveness LIKE ?)"
            )
            parameters.extend([wildcard_query] * 4)
        if state:
            clauses.append("state = ?")
            parameters.append(state)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.database.fetchall(
            f"SELECT * FROM identity_events {where} ORDER BY occurred_at DESC LIMIT ?",
            (*parameters, limit),
        )
        return [
            IdentityEvent(
                id=row["id"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                event_type=row["event_type"],
                state=row["state"],
                confidence=row["confidence"],
                liveness=row["liveness"],
                detail=row["detail"],
                monitoring_seconds=row["monitoring_seconds"],
            )
            for row in rows
        ]

    def count_events(self, state: str | None = None) -> int:
        if state is None:
            row = self.database.fetchone("SELECT COUNT(*) AS count FROM identity_events")
        else:
            row = self.database.fetchone(
                "SELECT COUNT(*) AS count FROM identity_events WHERE state = ?",
                (state,),
            )
        return int(row["count"]) if row is not None else 0

    def delete_events(self, event_ids: list[str]) -> int:
        if not event_ids:
            return 0
        placeholders = ",".join("?" for _ in event_ids)
        with self.database.transaction() as connection:
            cursor = connection.execute(
                f"DELETE FROM identity_events WHERE id IN ({placeholders})", event_ids
            )
            return cursor.rowcount

    def prune_events(self, retention_days: int) -> int:
        if not 1 <= retention_days <= 3650:
            raise ValueError("Retention must be between 1 and 3650 days.")
        cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
        with self.database.transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM identity_events WHERE occurred_at < ?", (cutoff_iso,)
            )
            return cursor.rowcount