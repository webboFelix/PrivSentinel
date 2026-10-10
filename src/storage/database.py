"""Thread-safe SQLite storage for identity profiles and event metadata."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
import threading
from typing import Iterator


class SQLiteDatabase:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=10,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 10000")
        self.initialize()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def fetchone(self, query: str, parameters: tuple[object, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._connection.execute(query, parameters).fetchone()

    def fetchall(
        self, query: str, parameters: tuple[object, ...] = ()
    ) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._connection.execute(query, parameters).fetchall())

    def initialize(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS identity_profile (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    display_name TEXT NOT NULL,
                    enrolled_at TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    template_dimensions INTEGER NOT NULL,
                    consent_recorded_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS identity_events (
                    id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    confidence REAL,
                    liveness TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    monitoring_seconds REAL NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_identity_events_time
                    ON identity_events (occurred_at DESC);
                CREATE INDEX IF NOT EXISTS idx_identity_events_type
                    ON identity_events (event_type);
                CREATE TABLE IF NOT EXISTS security_events (
                    id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    observed INTEGER NOT NULL,
                    attributes_json TEXT NOT NULL,
                    correlation_id TEXT,
                    risk_score REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_security_events_time
                    ON security_events (occurred_at DESC);
                CREATE TABLE IF NOT EXISTS file_integrity_baselines (
                    path TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    modified_ns INTEGER NOT NULL,
                    size INTEGER NOT NULL,
                    captured_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL REFERENCES security_events(id),
                    rule_id TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('open', 'acknowledged', 'investigating', 'resolved', 'dismissed')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_status_time
                    ON alerts (status, created_at DESC);
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('open', 'in_progress', 'closed')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS investigation_notes (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL REFERENCES investigations(id)
                        ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS investigation_events (
                    investigation_id TEXT NOT NULL REFERENCES investigations(id)
                        ON DELETE CASCADE,
                    event_id TEXT NOT NULL REFERENCES security_events(id),
                    PRIMARY KEY (investigation_id, event_id)
                );
                CREATE TABLE IF NOT EXISTS evidence_items (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT REFERENCES investigations(id)
                        ON DELETE SET NULL,
                    title TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    added_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_records (
                    id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                """
            )
            alert_columns = {
                row["name"]
                for row in self._connection.execute("PRAGMA table_info(alerts)")
            }
            if "dedupe_key" not in alert_columns:
                self._connection.execute(
                    "ALTER TABLE alerts ADD COLUMN dedupe_key TEXT NOT NULL DEFAULT ''"
                )

    def close(self) -> None:
        with self._lock:
            self._connection.close()
