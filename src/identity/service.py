"""Application-facing identity enrollment, monitoring, and history service."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal

from src.config.settings import AppSettings
from src.core.event_models import SecurityEvent
from src.identity.verification_policy import VerificationPolicy
from src.identity.workers import CameraMonitorWorker
from src.storage.models import IdentityEvent, IdentityProfile
from src.storage.repositories.identity_repository import IdentityRepository


class IdentityService(QObject):
    stateChanged = Signal(str, str)
    eventRecorded = Signal(object)
    profileChanged = Signal()
    monitoringChanged = Signal(bool)
    cameraStateChanged = Signal(str, str)
    lockWarningRequested = Signal(int)
    serviceError = Signal(str)
    previewChanged = Signal(object)

    def __init__(
        self,
        repository: IdentityRepository,
        models_directory: str | Path,
        settings: AppSettings,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.repository = repository
        self.models_directory = Path(models_directory)
        self.settings = settings
        self.policy = VerificationPolicy()
        self.worker: CameraMonitorWorker | None = None
        self.current_state = "stopped"
        self.current_detail = "Identity monitoring is stopped."
        self.camera_state = (
            "idle" if settings.camera_access_enabled else "disabled"
        )
        self.camera_detail = (
            "Camera access is enabled; no camera session is active."
            if settings.camera_access_enabled
            else "Camera access is disabled in Settings."
        )
        self._last_recorded: IdentityEvent | None = None
        self._last_monitoring_seconds = 0.0
        self._event_publisher = None

    def bind_event_publisher(self, publisher) -> None:
        self._event_publisher = publisher

    @property
    def profile(self) -> IdentityProfile | None:
        return self.repository.profile()

    @property
    def is_monitoring(self) -> bool:
        return self.worker is not None and self.worker.isRunning()

    @property
    def last_recorded(self) -> IdentityEvent | None:
        return self._last_recorded

    @property
    def monitoring_seconds(self) -> float:
        return (
            self.worker.monitoring_seconds
            if self.worker is not None and self.worker.isRunning()
            else self._last_monitoring_seconds
        )

    @property
    def failed_attempts(self) -> int:
        return self.worker.failed_attempts if self.worker is not None else 0

    def set_settings(self, settings: AppSettings) -> None:
        was_monitoring = self.is_monitoring
        previous = self.settings
        self.settings = settings
        if previous.camera_access_enabled != settings.camera_access_enabled:
            self.set_camera_state(
                "idle" if settings.camera_access_enabled else "disabled",
                "Camera access is enabled; no camera session is active."
                if settings.camera_access_enabled
                else "Camera access was disabled in Settings.",
            )
        if was_monitoring and self._camera_configuration_changed(previous, settings):
            self.stop_monitoring()
            if settings.camera_access_enabled and settings.identity_monitoring_enabled:
                self.start_monitoring()

    @staticmethod
    def _camera_configuration_changed(
        previous: AppSettings, current: AppSettings
    ) -> bool:
        relevant = (
            "camera_index",
            "camera_width",
            "camera_height",
            "capture_interval_ms",
            "verification_threshold",
            "verification_cooldown_seconds",
            "liveness_enabled",
            "require_single_face",
            "identity_failure_limit",
            "automatic_lock_enabled",
            "unknown_face_action",
            "presence_loss_action",
            "lock_grace_period_seconds",
            "camera_access_enabled",
            "identity_monitoring_enabled",
        )
        return any(getattr(previous, key) != getattr(current, key) for key in relevant)

    def start_monitoring(self) -> None:
        if self.is_monitoring:
            return
        if not self.settings.camera_access_enabled:
            raise PermissionError("Enable camera access in Settings before monitoring.")
        if not self.settings.identity_monitoring_enabled:
            raise PermissionError("Enable identity monitoring in Settings before starting.")
        if self.profile is None:
            raise ValueError("Enroll an identity before starting monitoring.")
        self.repository.prune_events(self.settings.identity_event_retention_days)
        worker = CameraMonitorWorker(
            self.settings,
            self.models_directory,
            self.repository,
            self,
        )
        self.set_camera_state("connecting", "Opening the selected camera.")
        self.worker = worker
        worker.stateChanged.connect(self._on_state_changed)
        worker.verification.connect(self._on_event)
        worker.previewReady.connect(self.previewChanged)
        worker.lockRequested.connect(
            lambda: self.lockWarningRequested.emit(
                self.settings.lock_grace_period_seconds
            )
        )
        worker.workerError.connect(self.serviceError)
        worker.finished.connect(lambda: self._worker_finished(worker))
        worker.start()
        self.monitoringChanged.emit(True)

    def stop_monitoring(self) -> None:
        worker = self.worker
        if worker is None:
            self._on_state_changed("stopped", "Identity monitoring stopped.")
            return
        if worker.isRunning():
            worker.stop()
        if worker is not None and worker.isRunning():
            worker.wait(2500)
        if not worker.isRunning():
            self._last_monitoring_seconds = worker.monitoring_seconds
            self.worker = None
        self._on_state_changed("stopped", "Identity monitoring stopped.")
        if self.camera_state not in {"unavailable", "disabled"}:
            self.set_camera_state(
                "idle" if self.settings.camera_access_enabled else "disabled",
                "Camera access is enabled; no camera session is active."
                if self.settings.camera_access_enabled
                else "Camera access is disabled in Settings.",
            )
        self.monitoringChanged.emit(False)

    def _worker_finished(self, worker: CameraMonitorWorker) -> None:
        self._last_monitoring_seconds = worker.monitoring_seconds
        if self.worker is worker:
            self.worker = None
        self.monitoringChanged.emit(False)

    def delete_profile(self) -> bool:
        self.stop_monitoring()
        deleted = self.repository.delete_profile()
        if deleted:
            self.profileChanged.emit()
        return deleted

    def record_enrollment(self) -> IdentityEvent:
        event = self.repository.record_event(
            event_type="enrollment",
            state="enrolled",
            confidence=None,
            liveness="not_checked",
            detail="Local face template enrolled or re-enrolled with explicit consent.",
        )
        self._on_event(event)
        self.profileChanged.emit()
        return event

    def recent_events(
        self, query: str = "", state: str = "", limit: int = 500
    ) -> list[IdentityEvent]:
        return self.repository.list_events(limit=limit, query=query, state=state)

    def event_count(self, state: str | None = None) -> int:
        return self.repository.count_events(state)

    def delete_events(self, event_ids: list[str]) -> int:
        return self.repository.delete_events(event_ids)

    def prune_events(self) -> int:
        return self.repository.prune_events(
            self.settings.identity_event_retention_days
        )

    def _on_state_changed(self, state: str, detail: str) -> None:
        self.current_state = state
        self.current_detail = detail
        camera_states = {
            "camera_ready": "connected",
            "camera_unavailable": "unavailable",
            "stopped": (
                "idle" if self.settings.camera_access_enabled else "disabled"
            ),
        }
        if state in camera_states:
            self.set_camera_state(camera_states[state], detail)
        elif state == "verification_failure" and self.camera_state == "connecting":
            self.set_camera_state(
                "idle",
                "The camera was not opened because verification setup failed.",
            )
        self.stateChanged.emit(state, detail)

    def set_camera_state(self, state: str, detail: str) -> None:
        allowed_states = {"disabled", "idle", "connecting", "connected", "unavailable"}
        if state not in allowed_states:
            raise ValueError(f"Unknown camera state: {state}")
        if self.camera_state == state and self.camera_detail == detail:
            return
        self.camera_state = state
        self.camera_detail = detail
        self.cameraStateChanged.emit(state, detail)

    def _on_event(self, event: IdentityEvent) -> None:
        self._last_recorded = event
        if self._event_publisher is not None:
            severity = {
                "unknown_face": "high",
                "liveness_failure": "medium",
                "multiple_faces": "medium",
                "camera_unavailable": "low",
                "verification_failure": "medium",
            }.get(event.state, "info")
            self._event_publisher(
                SecurityEvent(
                    source="identity",
                    event_type=event.state,
                    severity=severity,
                    description=event.detail,
                    attributes={
                        "confidence": event.confidence,
                        "liveness": event.liveness,
                        "monitoring_seconds": event.monitoring_seconds,
                    },
                    observed=True,
                    occurred_at=event.occurred_at,
                    id=event.id,
                )
            )
        self.eventRecorded.emit(event)
