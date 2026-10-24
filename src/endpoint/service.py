"""Lifecycle management for optional local endpoint monitoring collectors."""

from __future__ import annotations

import getpass
import json
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from src.config.settings import AppSettings
from src.core.event_pipeline import EventPipeline
from src.endpoint.integrity_baseline import (
    FileIntegrityMonitor,
    effective_file_integrity_exclusions,
)
from src.endpoint.process_monitor import ProcessMonitor
from src.integrations.windows.event_logs import WindowsEventLogCollector
from src.network.connection_monitor import ConnectionMonitor
from src.storage.database import SQLiteDatabase
from src.workers.monitoring_worker import MonitoringWorker


class EndpointMonitoringService(QObject):
    stateChanged = Signal(str, str)
    serviceError = Signal(str)

    def __init__(
        self,
        database: SQLiteDatabase,
        pipeline: EventPipeline,
        settings: AppSettings,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.database = database
        self.pipeline = pipeline
        self.settings = settings
        self.workers: dict[str, MonitoringWorker] = {}
        self._migrate_file_integrity_exclusions()

    def _migrate_file_integrity_exclusions(self) -> None:
        config = self.database.fetchone(
            "SELECT roots_json, exclusions_json FROM file_integrity_baseline_config WHERE id = 1"
        )
        if config is None or not self.settings.file_integrity_roots:
            return
        stored_roots = {
            os.path.normcase(str(Path(root).expanduser().resolve()))
            for root in json.loads(config["roots_json"])
        }
        configured_roots = {
            os.path.normcase(str(Path(root).expanduser().resolve()))
            for root in self.settings.file_integrity_roots
        }
        if stored_roots != configured_roots:
            return
        exclusions = effective_file_integrity_exclusions(
            self.settings.file_integrity_exclusions
        )
        if tuple(json.loads(config["exclusions_json"])) == exclusions:
            return
        monitor = FileIntegrityMonitor(
            self.database,
            self.settings.file_integrity_roots,
            exclusions,
        )
        paths = {
            str(row["path"])
            for row in self.database.fetchall(
                "SELECT path FROM file_integrity_baselines UNION "
                "SELECT path FROM file_integrity_inventory"
            )
            if monitor.is_excluded(Path(str(row["path"])))
        }
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            for path in paths:
                connection.execute("DELETE FROM file_integrity_baselines WHERE path = ?", (path,))
                connection.execute("DELETE FROM file_integrity_inventory WHERE path = ?", (path,))
                connection.execute("DELETE FROM file_integrity_findings WHERE path = ?", (path,))
            connection.execute(
                "UPDATE file_integrity_baseline_config SET exclusions_json = ? WHERE id = 1",
                (json.dumps(exclusions),),
            )
            remaining = {
                Path(str(row["path"])): (
                    str(row["sha256"]),
                    int(row["modified_ns"]),
                    int(row["size"]),
                )
                for row in connection.execute(
                    "SELECT path, sha256, modified_ns, size FROM file_integrity_inventory"
                )
            }
            monitor._persist_folder_stats(connection, remaining, now)

    def set_settings(self, settings: AppSettings) -> None:
        previous = self.settings
        self.settings = settings
        source_changed = any(
            getattr(previous, name) != getattr(settings, name)
            for name in (
                "endpoint_poll_interval_seconds",
                "process_exclusions",
                "network_monitoring_enabled",
                "process_monitoring_enabled",
                "windows_log_collection_enabled",
                "file_integrity_monitoring_enabled",
                "file_integrity_roots",
                "file_integrity_exclusions",
            )
        )
        if source_changed:
            self.stop_all()
            self.start_configured()

    def start_configured(self, only: set[str] | None = None) -> None:
        enabled = {
            "process": self.settings.process_monitoring_enabled,
            "network": self.settings.network_monitoring_enabled,
            "windows-event-log": self.settings.windows_log_collection_enabled,
            "file-integrity": self.settings.file_integrity_monitoring_enabled,
        }
        for source, active in enabled.items():
            if active and (only is None or source in only):
                try:
                    self.start(source)
                except (KeyError, OSError, RuntimeError, ValueError) as exc:
                    self.serviceError.emit(f"Could not start {source} monitoring: {exc}")

    def start(self, source: str) -> None:
        if source in self.workers and self.workers[source].isRunning():
            return
        collector = self._create_collector(source)
        worker = MonitoringWorker(
            source,
            collector,
            (
                0.2
                if source == "file-integrity"
                else self.settings.endpoint_poll_interval_seconds
            ),
            self,
        )
        self.workers[source] = worker
        worker.eventObserved.connect(self.pipeline.publish)
        worker.stateChanged.connect(lambda state, key=source: self.stateChanged.emit(key, state))
        worker.errorRaised.connect(self.serviceError)
        worker.finished.connect(lambda key=source: self._remove_worker(key, worker))
        worker.start()

    def stop(self, source: str) -> None:
        worker = self.workers.get(source)
        if worker is None:
            return
        worker.stop()
        if worker.isRunning():
            worker.wait(5000)
        if not worker.isRunning() and self.workers.get(source) is worker:
            self.workers.pop(source, None)
        self.stateChanged.emit(source, "stopped")

    def stop_all(self) -> None:
        for source in tuple(self.workers):
            self.stop(source)

    def establish_file_baseline(
        self,
        roots: tuple[str, ...] | None = None,
        exclusions: tuple[str, ...] | None = None,
        progress_callback: Callable[[int], None] | None = None,
        progress_details_callback: Callable[[int, int], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> int:
        monitor = FileIntegrityMonitor(
            self.database,
            roots if roots is not None else self.settings.file_integrity_roots,
            effective_file_integrity_exclusions(
                exclusions if exclusions is not None else self.settings.file_integrity_exclusions
            ),
        )
        exists = self.database.fetchone("SELECT 1 FROM file_integrity_baseline_config WHERE id = 1")
        actor = getpass.getuser()
        count = (
            monitor.update_baseline(
                progress_callback,
                actor=actor,
                progress_details_callback=progress_details_callback,
                cancel_event=cancel_event,
            )
            if exists is not None
            else monitor.establish_baseline(
                progress_callback,
                progress_details_callback=progress_details_callback,
                cancel_event=cancel_event,
            )
        )
        self.pipeline.repository.record_audit(
            actor,
            "file-integrity.baseline.update" if exists else "file-integrity.baseline.create",
            "success",
            f"{'Updated' if exists else 'Created'} integrity baseline for {count} files.",
        )
        return count

    def verify_file_integrity(
        self,
        progress_details_callback: Callable[[int, int], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> int:
        monitor = FileIntegrityMonitor(
            self.database,
            self.settings.file_integrity_roots,
            effective_file_integrity_exclusions(self.settings.file_integrity_exclusions),
        )
        events = monitor.scan(
            progress_details_callback=progress_details_callback,
            cancel_event=cancel_event,
            force_full_verification=True,
        )
        for event in events:
            self.pipeline.publish(event)
        actor = getpass.getuser()
        self.pipeline.repository.record_audit(
            actor,
            "file-integrity.verify",
            "success",
            f"Verified protected folders; {len(events)} new changes detected.",
        )
        return len(events)

    def approve_file_integrity_change(self, path: str) -> str | None:
        monitor = FileIntegrityMonitor(
            self.database,
            self.settings.file_integrity_roots,
            effective_file_integrity_exclusions(self.settings.file_integrity_exclusions),
        )
        actor = getpass.getuser()
        new_hash = monitor.approve_path(path, actor=actor)
        self.pipeline.repository.record_audit(
            actor,
            "file-integrity.approve-change",
            "success",
            f"Approved current state for {Path(path).expanduser().resolve()}; "
            f"SHA-256={new_hash or 'file deleted'}.",
        )
        return new_hash

    def acknowledge_file_integrity_event(self, event_id: str) -> str | None:
        event = self.database.fetchone(
            "SELECT attributes_json FROM security_events "
            "WHERE id = ? AND source = 'file-integrity'",
            (event_id,),
        )
        if event is None:
            raise KeyError(f"File-integrity event not found: {event_id}")
        attributes = json.loads(event["attributes_json"])
        path = str(attributes.get("path", ""))
        if not path:
            raise ValueError("File-integrity event does not include a file path.")

        actor = getpass.getuser()
        previous_path = attributes.get("previous_path")
        monitor = FileIntegrityMonitor(
            self.database,
            self.settings.file_integrity_roots,
            effective_file_integrity_exclusions(self.settings.file_integrity_exclusions),
        )
        if attributes.get("is_directory"):
            new_hash = monitor.approve_directory(
                path,
                actor=actor,
                previous_directory_path=(
                    previous_path
                    if isinstance(previous_path, str) and previous_path != path
                    else None
                ),
            )
            self.pipeline.repository.record_audit(
                actor,
                "file-integrity.approve-change",
                "success",
                f"Approved {new_hash or 0} files in directory {Path(path).resolve()}.",
            )
        else:
            new_hash = self.approve_file_integrity_change(path)
            if isinstance(previous_path, str) and previous_path and previous_path != path:
                self.approve_file_integrity_change(previous_path)
        self._transition_file_integrity_alerts(event_id, "acknowledged")
        self._set_file_integrity_event_status(event_id, "acknowledged")
        self.pipeline.repository.record_audit(
            actor,
            "file-integrity.event.acknowledge",
            "success",
            f"Acknowledged {event_id}; approved current state for {path}.",
        )
        return new_hash

    def investigate_file_integrity_event(self, event_id: str) -> str:
        event = self.database.fetchone(
            "SELECT description FROM security_events "
            "WHERE id = ? AND source = 'file-integrity'",
            (event_id,),
        )
        if event is None:
            raise KeyError(f"File-integrity event not found: {event_id}")
        existing = self.database.fetchone(
            "SELECT investigation_id, status FROM file_integrity_event_status "
            "WHERE event_id = ?",
            (event_id,),
        )
        if existing is not None and existing["investigation_id"]:
            investigation_id = str(existing["investigation_id"])
        else:
            investigation_id = self.pipeline.repository.create_investigation(
                f"File integrity: {str(event['description'])[:150]}"
            )
            self.pipeline.repository.link_event_to_investigation(investigation_id, event_id)
        self._transition_file_integrity_alerts(event_id, "investigating")
        self._set_file_integrity_event_status(
            event_id,
            "investigating",
            investigation_id=investigation_id,
        )
        return investigation_id

    def close_file_integrity_investigation(self, event_id: str) -> None:
        event = self.database.fetchone(
            "SELECT 1 FROM security_events WHERE id = ? AND source = 'file-integrity'",
            (event_id,),
        )
        if event is None:
            raise KeyError(f"File-integrity event not found: {event_id}")
        status = self.database.fetchone(
            "SELECT investigation_id FROM file_integrity_event_status WHERE event_id = ?",
            (event_id,),
        )
        investigation_id = (
            str(status["investigation_id"])
            if status is not None and status["investigation_id"]
            else None
        )
        if investigation_id is not None:
            self.pipeline.repository.set_investigation_status(investigation_id, "closed")
        self._transition_file_integrity_alerts(event_id, "resolved")
        self._set_file_integrity_event_status(event_id, "closed")
        self.pipeline.repository.record_audit(
            getpass.getuser(),
            "file-integrity.event.close-investigation",
            "success",
            f"Closed investigation for {event_id}.",
        )

    def _set_file_integrity_event_status(
        self,
        event_id: str,
        status: str,
        investigation_id: str | None = None,
    ) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO file_integrity_event_status
                    (event_id, status, investigation_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    status = excluded.status,
                    investigation_id = COALESCE(
                        excluded.investigation_id,
                        file_integrity_event_status.investigation_id
                    ),
                    updated_at = excluded.updated_at
                """,
                (event_id, status, investigation_id, datetime.now(UTC).isoformat()),
            )

    def _transition_file_integrity_alerts(self, event_id: str, target: str) -> None:
        alerts = self.database.fetchall(
            "SELECT id, status FROM alerts WHERE event_id = ?",
            (event_id,),
        )
        for alert in alerts:
            alert_id = str(alert["id"])
            current = str(alert["status"])
            if target == "acknowledged":
                if current in {"resolved", "dismissed"}:
                    self.pipeline.repository.transition_alert(alert_id, "open")
                    current = "open"
                if current in {"open", "investigating"}:
                    self.pipeline.repository.transition_alert(alert_id, "acknowledged")
            elif target == "investigating":
                if current in {"resolved", "dismissed"}:
                    self.pipeline.repository.transition_alert(alert_id, "open")
                    current = "open"
                if current in {"open", "acknowledged"}:
                    self.pipeline.repository.transition_alert(alert_id, "investigating")
            elif target == "resolved":
                if current in {"resolved", "dismissed"}:
                    continue
                if current == "open":
                    self.pipeline.repository.transition_alert(alert_id, "acknowledged")
                    current = "acknowledged"
                if current in {"acknowledged", "investigating"}:
                    self.pipeline.repository.transition_alert(alert_id, "resolved")

    def record_file_integrity_evidence(self, file_path: str) -> str:
        path = Path(file_path).expanduser().resolve()
        monitor = FileIntegrityMonitor(
            self.database,
            self.settings.file_integrity_roots,
            effective_file_integrity_exclusions(self.settings.file_integrity_exclusions),
        )
        if not monitor.is_protected_path(path):
            raise ValueError(f"File is outside the protected folders: {path}")
        if not path.is_file():
            raise OSError(f"Evidence file is unavailable: {path}")
        if monitor.is_excluded(path):
            raise ValueError(f"Excluded files cannot be recorded as FIM evidence: {path}")
        digest = monitor.hash_file(path)
        evidence_id = self.pipeline.repository.add_evidence(
            path.name,
            "file-integrity",
            str(path),
            digest,
        )
        self.pipeline.repository.record_audit(
            getpass.getuser(),
            "file-integrity.evidence.capture",
            "success",
            f"Captured SHA-256 evidence for {path}: {digest}.",
        )
        return evidence_id

    def has_file_baseline(
        self,
        roots: tuple[str, ...] | None = None,
        exclusions: tuple[str, ...] | None = None,
    ) -> bool:
        configured_roots = roots if roots is not None else self.settings.file_integrity_roots
        configured_exclusions = (
            exclusions if exclusions is not None else self.settings.file_integrity_exclusions
        )
        configured_exclusions = effective_file_integrity_exclusions(configured_exclusions)
        config = self.database.fetchone(
            "SELECT roots_json, exclusions_json FROM file_integrity_baseline_config WHERE id = 1"
        )
        if config is None:
            return False
        expected_roots = sorted(
            {
                str(Path(root).expanduser().resolve()).casefold()
                for root in configured_roots
            }
        )
        baseline_roots = sorted(
            {
                str(Path(root).expanduser().resolve()).casefold()
                for root in json.loads(config["roots_json"])
            }
        )
        baseline_exclusions = tuple(json.loads(config["exclusions_json"]))
        return (
            expected_roots == baseline_roots
            and tuple(configured_exclusions) == baseline_exclusions
        )

    def _create_collector(self, source: str):
        if source == "process":
            return ProcessMonitor(self.settings.process_exclusions)
        if source == "network":
            return ConnectionMonitor()
        if source == "windows-event-log":
            return WindowsEventLogCollector()
        if source == "file-integrity":
            if not self.has_file_baseline():
                raise RuntimeError(
                    "Establish a file integrity baseline for the current folders "
                    "and exclusions before starting monitoring."
                )
            return FileIntegrityMonitor(
                self.database,
                self.settings.file_integrity_roots,
                effective_file_integrity_exclusions(
                    self.settings.file_integrity_exclusions
                ),
            )
        raise KeyError(f"Unknown endpoint monitor: {source}")

    def _remove_worker(self, source: str, worker: MonitoringWorker) -> None:
        if self.workers.get(source) is worker:
            self.workers.pop(source, None)
