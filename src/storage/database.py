"""Thread-safe SQLite storage for identity profiles and event metadata."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


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
                CREATE TABLE IF NOT EXISTS file_integrity_baseline_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    roots_json TEXT NOT NULL,
                    exclusions_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS file_integrity_findings (
                    path TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS file_integrity_approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL,
                    previous_sha256 TEXT,
                    approved_sha256 TEXT,
                    actor TEXT NOT NULL,
                    approved_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_file_integrity_approvals_time
                    ON file_integrity_approvals (approved_at DESC);
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
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL CHECK(
                        indicator_type IN ('ip', 'domain', 'sha256')
                    ),
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (indicator_type, value)
                );
                CREATE TABLE IF NOT EXISTS malware_rule_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT NOT NULL,
                    source TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS malware_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL CHECK(provider IN ('yara', 'defender')),
                    status TEXT NOT NULL CHECK(status IN
                        ('requested', 'running', 'completed', 'failed', 'cancelled')),
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    scanned_files INTEGER NOT NULL DEFAULT 0,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    error_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS malware_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES malware_scans(id),
                    provider TEXT NOT NULL,
                    path TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                        ('detected', 'quarantined', 'restored', 'dismissed')),
                    detected_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_malware_findings_status_time
                    ON malware_findings (status, detected_at DESC);
                CREATE TABLE IF NOT EXISTS quarantined_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id INTEGER NOT NULL REFERENCES malware_findings(id),
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('quarantined', 'restored')),
                    quarantined_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reputation_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    indicator_type TEXT NOT NULL CHECK(indicator_type IN
                        ('url', 'domain', 'ip', 'sha256')),
                    value TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(provider, indicator_type, value)
                );
                CREATE INDEX IF NOT EXISTS idx_reputation_indicator_value
                    ON reputation_indicators (indicator_type, value);
                CREATE TABLE IF NOT EXISTS reputation_feed_status (
                    provider TEXT PRIMARY KEY,
                    updated_at TEXT NOT NULL,
                    entry_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reputation_cache (
                    provider TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    malicious INTEGER,
                    suspicious INTEGER,
                    detail TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    PRIMARY KEY(provider, indicator_type, value)
                );
                CREATE TABLE IF NOT EXISTS browser_domain_decisions (
                    domain TEXT PRIMARY KEY,
                    decision TEXT NOT NULL CHECK(decision IN ('allow', 'block')),
                    reason TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS browser_site_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    browser TEXT NOT NULL,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision IN
                        ('allowed', 'blocked', 'matched', 'error')),
                    provider TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_browser_site_events_time
                    ON browser_site_events (occurred_at DESC);
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
