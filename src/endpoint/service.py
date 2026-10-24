"""Lifecycle management for optional local endpoint monitoring collectors."""

from __future__ import annotations

import getpass
import json
import threading
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from src.config.settings import AppSettings
from src.core.event_pipeline import EventPipeline
from src.endpoint.integrity_baseline import FileIntegrityMonitor
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
            exclusions if exclusions is not None else self.settings.file_integrity_exclusions,
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
            self.settings.file_integrity_exclusions,
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
            self.settings.file_integrity_exclusions,
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

    def record_file_integrity_evidence(self, file_path: str) -> str:
        path = Path(file_path).expanduser().resolve()
        monitor = FileIntegrityMonitor(
            self.database,
            self.settings.file_integrity_roots,
            self.settings.file_integrity_exclusions,
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
                self.settings.file_integrity_exclusions,
            )
        raise KeyError(f"Unknown endpoint monitor: {source}")

    def _remove_worker(self, source: str, worker: MonitoringWorker) -> None:
        if self.workers.get(source) is worker:
            self.workers.pop(source, None)
