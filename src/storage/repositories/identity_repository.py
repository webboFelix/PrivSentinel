"""SQLite persistence for DPAPI-protected identity templates and metadata."""

from __future__ import annotations

import base64
import binascii
import io
import json
import re
import uuid
from datetime import UTC, datetime

import numpy as np

from src.security.secret_store import WindowsSecretStore
from src.storage.database import SQLiteDatabase
from src.storage.models import IdentityEvent, IdentityProfile


class IdentityRepository:
    _SECRET_NAME = "face-template"
    _PROFILE_SECRET_NAME = "identity-profile"
    _PROFILE_FIELDS = frozenset({
        "email",
        "phone",
        "profile_image",
        "department",
        "employee_id",
        "machine_user",
    })

    def __init__(self, database: SQLiteDatabase, secrets: WindowsSecretStore) -> None:
        self.database = database
        self.secrets = secrets

    def profile(self) -> IdentityProfile | None:
        row = self.database.fetchone(
            "SELECT display_name, enrolled_at, model_name, template_dimensions, "
            "consent_recorded_at, enrollment_quality "
            "FROM identity_profile WHERE id = 1"
        )
        if row is None:
            return None
        details = self._profile_details()
        return IdentityProfile(
            display_name=row["display_name"],
            enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
            model_name=row["model_name"],
            template_dimensions=row["template_dimensions"],
            consent_recorded_at=datetime.fromisoformat(row["consent_recorded_at"]),
            enrollment_quality=(
                float(row["enrollment_quality"])
                if row["enrollment_quality"] is not None
                else None
            ),
            **details,
        )

    def template(self) -> np.ndarray | None:
        templates = self.templates()
        if templates is None:
            return None
        template = templates.mean(axis=0)
        norm = float(np.linalg.norm(template))
        if norm == 0:
            raise ValueError("Stored face templates do not produce a usable template.")
        return (template / norm).astype(np.float32, copy=False)

    def templates(self) -> np.ndarray | None:
        encrypted = self.secrets.get(self._SECRET_NAME)
        if encrypted is None:
            return None
        try:
            vectors = np.load(io.BytesIO(encrypted), allow_pickle=False)
        except (ValueError, OSError) as exc:
            raise ValueError("Stored face template is invalid or unreadable.") from exc
        if vectors.ndim == 1:
            vectors = vectors[np.newaxis, :]
        if (
            vectors.ndim != 2
            or vectors.shape[0] == 0
            or vectors.shape[1] < 32
            or not np.isfinite(vectors).all()
        ):
            raise ValueError("Stored face template failed validation.")
        vectors = vectors.astype(np.float32, copy=False)
        norms = np.linalg.norm(vectors, axis=1)
        if np.any(norms == 0):
            raise ValueError("Stored face template failed validation.")
        return vectors / norms[:, np.newaxis]

    def enroll(
        self,
        display_name: str,
        embedding: np.ndarray,
        model_name: str,
        consent_recorded_at: datetime,
        profile_details: dict[str, str] | None = None,
        enrollment_quality: float | None = None,
    ) -> IdentityProfile:
        name = display_name.strip()
        vector = np.asarray(embedding, dtype=np.float32)
        details = self._validate_profile_details(profile_details or {})
        if not name or len(name) > 120:
            raise ValueError("Display name must contain between 1 and 120 characters.")
        if vector.ndim == 1:
            vector = vector[np.newaxis, :]
        if (
            vector.ndim != 2
            or vector.shape[0] == 0
            or vector.shape[1] < 32
            or not np.isfinite(vector).all()
            or np.any(np.linalg.norm(vector, axis=1) == 0)
        ):
            raise ValueError("Face embedding must be a finite, non-zero vector.")
        if not model_name or len(model_name) > 120:
            raise ValueError("A valid recognition model name is required.")
        if enrollment_quality is not None and (
            not np.isfinite(enrollment_quality) or not 0.0 <= enrollment_quality <= 1.0
        ):
            raise ValueError("Enrollment quality must be between 0 and 1.")
        now = datetime.now(UTC)
        stream = io.BytesIO()
        normalized = vector / np.linalg.norm(vector, axis=1)[:, np.newaxis]
        np.save(stream, normalized, allow_pickle=False)
        previous_template = self.secrets.get(self._SECRET_NAME)
        previous_details = self.secrets.get(self._PROFILE_SECRET_NAME)
        try:
            self.secrets.set(self._SECRET_NAME, stream.getvalue())
            if any(details.values()):
                self.secrets.set(
                    self._PROFILE_SECRET_NAME,
                    json.dumps(details, sort_keys=True).encode("utf-8"),
                )
            else:
                self.secrets.delete(self._PROFILE_SECRET_NAME)
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO identity_profile (
                        id, display_name, enrolled_at, model_name,
                        template_dimensions, consent_recorded_at, enrollment_quality
                    ) VALUES (1, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        display_name=excluded.display_name,
                        enrolled_at=excluded.enrolled_at,
                        model_name=excluded.model_name,
                        template_dimensions=excluded.template_dimensions,
                        consent_recorded_at=excluded.consent_recorded_at,
                        enrollment_quality=excluded.enrollment_quality
                    """,
                    (
                        name,
                        now.isoformat(),
                        model_name,
                        int(vector.shape[1]),
                        consent_recorded_at.astimezone(UTC).isoformat(),
                        enrollment_quality,
                    ),
                )
        except BaseException as exc:
            try:
                self._restore_secret(self._SECRET_NAME, previous_template)
                self._restore_secret(self._PROFILE_SECRET_NAME, previous_details)
            except (OSError, RuntimeError, ValueError) as rollback_exc:
                raise RuntimeError(
                    f"Enrollment failed and its protected data could not be fully restored: {rollback_exc}"
                ) from exc
            raise
        return IdentityProfile(
            name,
            now,
            model_name,
            int(vector.shape[1]),
            consent_recorded_at,
            enrollment_quality=enrollment_quality,
            **details,
        )

    def delete_profile(self) -> bool:
        had_profile = self.profile() is not None
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM identity_profile WHERE id = 1")
        self.secrets.delete(self._SECRET_NAME)
        self.secrets.delete(self._PROFILE_SECRET_NAME)
        return had_profile

    def _profile_details(self) -> dict[str, str]:
        protected = self.secrets.get(self._PROFILE_SECRET_NAME)
        if protected is None:
            return {}
        try:
            details = json.loads(protected.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Stored identity profile details are unreadable.") from exc
        if not isinstance(details, dict):
            raise TypeError("Stored identity profile details failed validation.")
        normalized = self._validate_profile_details(details)
        return {key: value for key, value in normalized.items() if value}

    @classmethod
    def _validate_profile_details(
        cls, details: dict[str, str]
    ) -> dict[str, str]:
        if set(details) - cls._PROFILE_FIELDS:
            raise ValueError("Identity profile contains unsupported fields.")
        normalized = {
            key: value.strip()
            for key, value in details.items()
            if isinstance(value, str)
        }
        if len(normalized) != len(details):
            raise ValueError("Identity profile fields must be text.")
        limits = {
            "email": 254,
            "phone": 32,
            "profile_image": 400_000,
            "department": 120,
            "employee_id": 64,
            "machine_user": 120,
        }
        for key, value in normalized.items():
            if len(value) > limits[key] or any(ord(character) < 32 for character in value):
                raise ValueError(f"Identity {key.replace('_', ' ')} is invalid.")
        email = normalized.get("email", "")
        if email and (
            email.count("@") != 1
            or any(character.isspace() for character in email)
            or "." not in email.rsplit("@", 1)[1]
        ):
            raise ValueError("Enter a valid email address.")
        phone = normalized.get("phone", "")
        if phone and (
            not re.fullmatch(r"[+0-9(). -]+", phone)
            or not 7 <= sum(character.isdigit() for character in phone) <= 15
        ):
            raise ValueError("Enter a valid phone number.")
        image = normalized.get("profile_image", "")
        if image:
            try:
                base64.b64decode(image, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("Profile image data is invalid.") from exc
        return {key: normalized.get(key, "") for key in cls._PROFILE_FIELDS}

    def _restore_secret(self, name: str, value: bytes | None) -> None:
        if value is None:
            self.secrets.delete(name)
        else:
            self.secrets.set(name, value)

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
        when = occurred_at or datetime.now(UTC)
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
                    event.occurred_at.astimezone(UTC).isoformat(),
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
        cutoff = datetime.now(UTC).timestamp() - retention_days * 86400
        cutoff_iso = datetime.fromtimestamp(cutoff, UTC).isoformat()
        with self.database.transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM identity_events WHERE occurred_at < ?", (cutoff_iso,)
            )
            return cursor.rowcount