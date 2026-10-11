"""Typed, versioned JSON settings with migrations and atomic persistence."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any

from src.config.defaults import (
    DEFAULT_AUTO_LOCK_ENABLED,
    DEFAULT_BACKUP_BEFORE_SAVE,
    DEFAULT_CAMERA_ACCESS_ENABLED,
    DEFAULT_CAMERA_FAILURE_ACTION,
    DEFAULT_CAMERA_HEIGHT,
    DEFAULT_CAMERA_INDEX,
    DEFAULT_CAMERA_RECONNECT_SECONDS,
    DEFAULT_CAMERA_WIDTH,
    DEFAULT_CAPTURE_INTERVAL_MS,
    DEFAULT_ENDPOINT_POLL_INTERVAL_SECONDS,
    DEFAULT_EVENT_RETENTION_DAYS,
    DEFAULT_FAILURE_LIMIT,
    DEFAULT_FILE_INTEGRITY_MONITORING_ENABLED,
    DEFAULT_FILE_LOGGING_ENABLED,
    DEFAULT_IDENTITY_EVENT_RETENTION_DAYS,
    DEFAULT_IDENTITY_MONITORING_ENABLED,
    DEFAULT_IDENTITY_NOTIFICATIONS_ENABLED,
    DEFAULT_LIVENESS_ENABLED,
    DEFAULT_LOCK_GRACE_PERIOD_SECONDS,
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_RETENTION_DAYS,
    DEFAULT_MULTIPLE_FACE_POLICY,
    DEFAULT_NETWORK_MONITORING_ENABLED,
    DEFAULT_PRESENCE_LOSS_ACTION,
    DEFAULT_PROCESS_MONITORING_ENABLED,
    DEFAULT_REQUIRE_SINGLE_FACE,
    DEFAULT_START_MONITORING_ON_LAUNCH,
    DEFAULT_UNKNOWN_FACE_ACTION,
    DEFAULT_VERIFICATION_COOLDOWN_SECONDS,
    DEFAULT_VERIFICATION_THRESHOLD,
    DEFAULT_WINDOWS_LOG_COLLECTION_ENABLED,
)

SCHEMA_VERSION = 4
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_UNKNOWN_FACE_ACTIONS = frozenset({"notify_only", "lock_after_grace"})


class SettingsError(ValueError):
    """Raised when the settings file cannot be safely loaded or validated."""


@dataclass(frozen=True, slots=True)
class AppSettings:
    schema_version: int = SCHEMA_VERSION
    log_level: str = DEFAULT_LOG_LEVEL
    log_retention_days: int = DEFAULT_LOG_RETENTION_DAYS
    file_logging_enabled: bool = DEFAULT_FILE_LOGGING_ENABLED
    backup_before_save: bool = DEFAULT_BACKUP_BEFORE_SAVE
    window_geometry: str | None = None
    window_state: str | None = None
    camera_index: int = DEFAULT_CAMERA_INDEX
    camera_width: int = DEFAULT_CAMERA_WIDTH
    camera_height: int = DEFAULT_CAMERA_HEIGHT
    capture_interval_ms: int = DEFAULT_CAPTURE_INTERVAL_MS
    verification_threshold: float = DEFAULT_VERIFICATION_THRESHOLD
    verification_cooldown_seconds: int = DEFAULT_VERIFICATION_COOLDOWN_SECONDS
    liveness_enabled: bool = DEFAULT_LIVENESS_ENABLED
    require_single_face: bool = DEFAULT_REQUIRE_SINGLE_FACE
    identity_event_retention_days: int = DEFAULT_IDENTITY_EVENT_RETENTION_DAYS
    unknown_face_action: str = DEFAULT_UNKNOWN_FACE_ACTION
    presence_loss_action: str = DEFAULT_PRESENCE_LOSS_ACTION
    camera_failure_action: str = DEFAULT_CAMERA_FAILURE_ACTION
    camera_reconnect_seconds: int = DEFAULT_CAMERA_RECONNECT_SECONDS
    multiple_face_policy: str = DEFAULT_MULTIPLE_FACE_POLICY
    identity_failure_limit: int = DEFAULT_FAILURE_LIMIT
    automatic_lock_enabled: bool = DEFAULT_AUTO_LOCK_ENABLED
    lock_grace_period_seconds: int = DEFAULT_LOCK_GRACE_PERIOD_SECONDS
    camera_access_enabled: bool = DEFAULT_CAMERA_ACCESS_ENABLED
    identity_monitoring_enabled: bool = DEFAULT_IDENTITY_MONITORING_ENABLED
    start_monitoring_on_launch: bool = DEFAULT_START_MONITORING_ON_LAUNCH
    identity_notifications_enabled: bool = DEFAULT_IDENTITY_NOTIFICATIONS_ENABLED
    endpoint_poll_interval_seconds: int = DEFAULT_ENDPOINT_POLL_INTERVAL_SECONDS
    process_monitoring_enabled: bool = DEFAULT_PROCESS_MONITORING_ENABLED
    network_monitoring_enabled: bool = DEFAULT_NETWORK_MONITORING_ENABLED
    file_integrity_monitoring_enabled: bool = DEFAULT_FILE_INTEGRITY_MONITORING_ENABLED
    windows_log_collection_enabled: bool = DEFAULT_WINDOWS_LOG_COLLECTION_ENABLED
    event_retention_days: int = DEFAULT_EVENT_RETENTION_DAYS
    process_exclusions: tuple[str, ...] = ()
    file_integrity_roots: tuple[str, ...] = ()
    file_integrity_exclusions: tuple[str, ...] = ()

    def validated(self) -> AppSettings:
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise SettingsError(f"Unsupported settings schema version: {self.schema_version!r}.")
        if not isinstance(self.log_level, str) or self.log_level not in _LOG_LEVELS:
            raise SettingsError(
                f"log_level must be one of {', '.join(sorted(_LOG_LEVELS))}."
            )
        if (
            type(self.log_retention_days) is not int
            or not 1 <= self.log_retention_days <= 3650
        ):
            raise SettingsError("log_retention_days must be an integer from 1 to 3650.")
        if type(self.event_retention_days) is not int or not 1 <= self.event_retention_days <= 3650:
            raise SettingsError("event_retention_days must be an integer from 1 to 3650.")
        for name in (
            "file_logging_enabled",
            "backup_before_save",
            "process_monitoring_enabled",
            "network_monitoring_enabled",
            "file_integrity_monitoring_enabled",
            "windows_log_collection_enabled",
        ):
            if type(getattr(self, name)) is not bool:
                raise SettingsError(f"{name} must be a boolean.")
        for name in (
            "process_exclusions",
            "file_integrity_roots",
            "file_integrity_exclusions",
        ):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(
                not isinstance(item, str) or not item.strip() or len(item) > 2048
                for item in value
            ):
                raise SettingsError(
                    f"{name} must be a tuple of non-empty path or name strings."
                )
        integer_ranges = {
            "camera_index": (0, 31),
            "camera_reconnect_seconds": (1, 60),
            "endpoint_poll_interval_seconds": (1, 3600),
            "camera_width": (320, 3840),
            "camera_height": (240, 2160),
            "capture_interval_ms": (250, 10000),
            "verification_cooldown_seconds": (0, 3600),
            "identity_event_retention_days": (1, 3650),
            "identity_failure_limit": (1, 100),
            "lock_grace_period_seconds": (5, 3600),
        }
        for name, (minimum, maximum) in integer_ranges.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise SettingsError(
                    f"{name} must be an integer from {minimum} to {maximum}."
                )
        if (
            isinstance(self.verification_threshold, bool)
            or not isinstance(self.verification_threshold, (int, float))
            or not 0.05 <= self.verification_threshold <= 0.99
        ):
            raise SettingsError("verification_threshold must be between 0.05 and 0.99.")
        for name in (
            "liveness_enabled",
            "require_single_face",
            "automatic_lock_enabled",
            "camera_access_enabled",
            "identity_monitoring_enabled",
            "start_monitoring_on_launch",
            "identity_notifications_enabled",
        ):
            if type(getattr(self, name)) is not bool:
                raise SettingsError(f"{name} must be a boolean.")
        if self.unknown_face_action not in _UNKNOWN_FACE_ACTIONS:
            raise SettingsError(
                "unknown_face_action must be notify_only or lock_after_grace."
            )
        if self.presence_loss_action not in _UNKNOWN_FACE_ACTIONS:
            raise SettingsError(
                "presence_loss_action must be notify_only or lock_after_grace."
            )
        if self.camera_failure_action not in {
            "notify_only",
            "notify_and_stop_monitoring",
        }:
            raise SettingsError(
                "camera_failure_action must be notify_only or notify_and_stop_monitoring."
            )
        if self.multiple_face_policy not in {
            "pause_and_notify",
            "stop_monitoring",
        }:
            raise SettingsError(
                "multiple_face_policy must be pause_and_notify or stop_monitoring."
            )
        if (
            self.automatic_lock_enabled
            and self.unknown_face_action != "lock_after_grace"
            and self.presence_loss_action != "lock_after_grace"
        ):
            raise SettingsError(
                "Automatic lock requires at least one lock_after_grace response policy."
            )
        if self.identity_monitoring_enabled and not self.camera_access_enabled:
            raise SettingsError(
                "Identity monitoring requires explicit camera access."
            )
        if self.start_monitoring_on_launch and not self.identity_monitoring_enabled:
            raise SettingsError(
                "Startup monitoring requires identity_monitoring_enabled."
            )
        for name in ("window_geometry", "window_state"):
            value = getattr(self, name)
            if value is not None:
                if not isinstance(value, str):
                    raise SettingsError(f"{name} must be a base64 string or null.")
                try:
                    base64.b64decode(value, validate=True)
                except (ValueError, base64.binascii.Error) as exc:
                    raise SettingsError(f"{name} must contain valid base64 data.") from exc
        return self


class SettingsStore:
    """Persists validated settings and creates the application data folder."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def load(self) -> AppSettings:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                settings = AppSettings()
                self._write(settings)
                return settings
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise SettingsError(f"Could not read settings file {self.path}: {exc}") from exc
            migrated = self._migrate(raw)
            migrated["camera_index"] = DEFAULT_CAMERA_INDEX
            settings = self._from_mapping(migrated)
            if migrated != raw:
                self._write(settings)
            return settings

    def save(self, settings: AppSettings) -> AppSettings:
        with self._lock:
            settings = replace(settings, camera_index=DEFAULT_CAMERA_INDEX)
            settings.validated()
            if self.path.exists() and settings.backup_before_save:
                self.backup()
            self._write(settings)
            return settings

    def reset(self) -> AppSettings:
        with self._lock:
            settings = AppSettings()
            self._write(settings)
            return settings

    def backup(self, destination: str | Path | None = None) -> Path:
        with self._lock:
            self.load()
            target = Path(destination) if destination else self.path.parent / "backups" / "settings.backup.json"
            try:
                content = self.path.read_bytes()
                json.loads(content.decode("utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise SettingsError(f"Could not back up settings file {self.path}: {exc}") from exc
            self._atomic_write(target, content)
            return target

    def restore(self, source: str | Path) -> AppSettings:
        source_path = Path(source)
        try:
            raw = json.loads(source_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SettingsError(f"Could not read settings backup {source_path}: {exc}") from exc
        settings = self._from_mapping(self._migrate(raw))
        return self.save(settings)

    def _migrate(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise SettingsError("Settings document must be a JSON object.")
        version = raw.get("schema_version", 1)
        if type(version) is not int:
            raise SettingsError("schema_version must be an integer.")
        if version > SCHEMA_VERSION or version < 1:
            raise SettingsError(f"Unsupported settings schema version: {version}.")
        migrated = dict(raw)
        if version == 1:
            migrated.setdefault("file_logging_enabled", True)
            migrated.setdefault("backup_before_save", False)
            migrated.setdefault("window_geometry", None)
            migrated.setdefault("window_state", None)
            migrated["schema_version"] = 2
            version = 2
        if version == 2:
            migrated.update(
                {
                    "camera_index": DEFAULT_CAMERA_INDEX,
                    "camera_width": DEFAULT_CAMERA_WIDTH,
                    "camera_height": DEFAULT_CAMERA_HEIGHT,
                    "capture_interval_ms": DEFAULT_CAPTURE_INTERVAL_MS,
                    "verification_threshold": DEFAULT_VERIFICATION_THRESHOLD,
                    "verification_cooldown_seconds": DEFAULT_VERIFICATION_COOLDOWN_SECONDS,
                    "liveness_enabled": DEFAULT_LIVENESS_ENABLED,
                    "require_single_face": DEFAULT_REQUIRE_SINGLE_FACE,
                    "identity_event_retention_days": DEFAULT_IDENTITY_EVENT_RETENTION_DAYS,
                    "unknown_face_action": DEFAULT_UNKNOWN_FACE_ACTION,
                    "presence_loss_action": DEFAULT_PRESENCE_LOSS_ACTION,
                    "camera_failure_action": DEFAULT_CAMERA_FAILURE_ACTION,
                    "camera_reconnect_seconds": DEFAULT_CAMERA_RECONNECT_SECONDS,
                    "multiple_face_policy": DEFAULT_MULTIPLE_FACE_POLICY,
                    "identity_failure_limit": DEFAULT_FAILURE_LIMIT,
                    "automatic_lock_enabled": DEFAULT_AUTO_LOCK_ENABLED,
                    "lock_grace_period_seconds": DEFAULT_LOCK_GRACE_PERIOD_SECONDS,
                    "camera_access_enabled": DEFAULT_CAMERA_ACCESS_ENABLED,
                    "identity_monitoring_enabled": DEFAULT_IDENTITY_MONITORING_ENABLED,
                    "start_monitoring_on_launch": DEFAULT_START_MONITORING_ON_LAUNCH,
                    "identity_notifications_enabled": DEFAULT_IDENTITY_NOTIFICATIONS_ENABLED,
                    "schema_version": 3,
                }
            )
            version = 3
        if version == 3:
            migrated.update(
                {
                    "endpoint_poll_interval_seconds": DEFAULT_ENDPOINT_POLL_INTERVAL_SECONDS,
                    "process_monitoring_enabled": DEFAULT_PROCESS_MONITORING_ENABLED,
                    "network_monitoring_enabled": DEFAULT_NETWORK_MONITORING_ENABLED,
                    "file_integrity_monitoring_enabled": DEFAULT_FILE_INTEGRITY_MONITORING_ENABLED,
                    "windows_log_collection_enabled": DEFAULT_WINDOWS_LOG_COLLECTION_ENABLED,
                    "event_retention_days": DEFAULT_EVENT_RETENTION_DAYS,
                    "process_exclusions": [],
                    "file_integrity_roots": [],
                    "file_integrity_exclusions": [],
                    "schema_version": 4,
                }
            )
        migrated["camera_index"] = DEFAULT_CAMERA_INDEX
        return migrated

    @staticmethod
    def _from_mapping(raw: dict[str, Any]) -> AppSettings:
        accepted = {field.name for field in fields(AppSettings)}
        unknown = set(raw) - accepted
        if unknown:
            raise SettingsError(f"Unknown settings keys: {', '.join(sorted(unknown))}.")
        try:
            for name in (
                "process_exclusions",
                "file_integrity_roots",
                "file_integrity_exclusions",
            ):
                if isinstance(raw.get(name), list):
                    raw[name] = tuple(raw[name])
            return AppSettings(**raw).validated()
        except TypeError as exc:
            raise SettingsError(f"Invalid settings fields: {exc}") from exc

    def _write(self, settings: AppSettings) -> None:
        settings.validated()
        payload = json.dumps(
            asdict(settings), indent=2, sort_keys=True, ensure_ascii=False
        ).encode("utf-8") + b"\n"
        self._atomic_write(self.path, payload)

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
                delete=False,
            ) as handle:
                temporary_path = Path(handle.name)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            temporary_path = None
        except OSError as exc:
            raise SettingsError(f"Could not atomically write {path}: {exc}") from exc
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)