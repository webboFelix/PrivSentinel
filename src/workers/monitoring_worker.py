"""Cancellable Qt polling worker for real local endpoint collectors."""

from __future__ import annotations

import threading
import time

from PySide6.QtCore import QThread, Signal

from src.core.event_models import SecurityEvent


class MonitoringWorker(QThread):
    eventObserved = Signal(object)
    stateChanged = Signal(str)
    errorRaised = Signal(str)

    def __init__(
        self,
        source_name: str,
        collector,
        interval_seconds: int,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not 1 <= interval_seconds <= 3600:
            raise ValueError("Polling interval must be between 1 and 3600 seconds.")
        self.source_name = source_name
        self.collector = collector
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self.last_successful_collection_at: float | None = None

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        self.stateChanged.emit("starting")
        start = getattr(self.collector, "start", None)
        stop = getattr(self.collector, "stop", None)
        try:
            if start is not None:
                start()
        except Exception as exc:  # noqa: BLE001 - report collector startup failures
            self.errorRaised.emit(f"{self.source_name}: {exc}")
            self.stateChanged.emit("error")
            return
        try:
            while not self._stop_event.is_set():
                started = time.monotonic()
                try:
                    for event in self.collector.collect():
                        if isinstance(event, SecurityEvent):
                            self.eventObserved.emit(event)
                        else:
                            raise TypeError(
                                f"{self.source_name} collector returned a non-event value."
                            )
                    self.last_successful_collection_at = time.monotonic()
                    self.stateChanged.emit("running")
                except Exception as exc:  # noqa: BLE001 - report collector failures
                    self.errorRaised.emit(f"{self.source_name}: {exc}")
                    self.stateChanged.emit("error")
                elapsed = time.monotonic() - started
                self._stop_event.wait(max(0, self.interval_seconds - elapsed))
        finally:
            if stop is not None:
                try:
                    stop()
                except Exception as exc:  # noqa: BLE001 - report collector cleanup failures
                    self.errorRaised.emit(f"{self.source_name} shutdown: {exc}")
        self.stateChanged.emit("stopped")