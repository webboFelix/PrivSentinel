"""Construction and application of shared local service dependencies."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from pathlib import Path

from src.config.logging_config import configure_logging
from src.config.paths import AppPaths
from src.config.settings import AppSettings, SettingsStore
from src.core.event_pipeline import EventPipeline
from src.identity.service import IdentityService
from src.endpoint.service import EndpointMonitoringService
from src.security.secret_store import WindowsSecretStore
from src.storage.database import SQLiteDatabase
from src.storage.repositories.identity_repository import IdentityRepository
from src.storage.repositories.security_repository import SecurityRepository


@dataclass(slots=True)
class ApplicationServices:
    paths: AppPaths
    settings_store: SettingsStore
    secret_store: WindowsSecretStore
    database: SQLiteDatabase
    identity_repository: IdentityRepository
    identity_service: IdentityService
    security_repository: SecurityRepository
    event_pipeline: EventPipeline
    endpoint_service: EndpointMonitoringService
    settings: AppSettings

    @classmethod
    def create(cls, paths: AppPaths | None = None) -> ApplicationServices:
        app_paths = paths or AppPaths.from_environment()
        app_paths.ensure_directories()
        settings_store = SettingsStore(app_paths.settings_file)
        legacy_settings_file = app_paths.root / "settings.json"
        if not app_paths.settings_file.exists() and legacy_settings_file.exists():
            legacy_settings = SettingsStore(legacy_settings_file).load()
            settings_store.save(legacy_settings)
        settings = settings_store.load()
        database = SQLiteDatabase(app_paths.database_file)
        identity_repository = IdentityRepository(
            database,
            WindowsSecretStore(app_paths.secrets_directory),
        )
        security_repository = SecurityRepository(database)
        event_pipeline = EventPipeline(security_repository)
        identity_service = IdentityService(
            identity_repository,
            app_paths.models_directory,
            settings,
        )
        identity_service.bind_event_publisher(event_pipeline.publish)
        endpoint_service = EndpointMonitoringService(
            database,
            event_pipeline,
            settings,
        )
        services = cls(
            paths=app_paths,
            settings_store=settings_store,
            secret_store=WindowsSecretStore(app_paths.secrets_directory),
            database=database,
            identity_repository=identity_repository,
            identity_service=identity_service,
            security_repository=security_repository,
            event_pipeline=event_pipeline,
            endpoint_service=endpoint_service,
            settings=settings,
        )
        identity_repository.prune_events(settings.identity_event_retention_days)
        services._apply_settings(settings)
        return services

    def save_settings(self, settings: AppSettings) -> AppSettings:
        persisted = self.settings_store.save(settings)
        self._apply_settings(persisted)
        self.settings = persisted
        self.identity_service.set_settings(persisted)
        self.endpoint_service.set_settings(persisted)
        return persisted

    def reset_settings(self) -> AppSettings:
        settings = self.settings_store.reset()
        self._apply_settings(settings)
        self.settings = settings
        self.identity_service.set_settings(settings)
        self.endpoint_service.set_settings(settings)
        return settings

    def backup_settings(self, destination: str | Path | None = None) -> Path:
        return self.settings_store.backup(destination)

    def restore_settings(self, source: str | Path) -> AppSettings:
        settings = self.settings_store.restore(source)
        self._apply_settings(settings)
        self.settings = settings
        self.identity_service.set_settings(settings)
        self.endpoint_service.set_settings(settings)
        return settings

    def save_window_state(self, geometry: bytes, state: bytes) -> None:
        settings = replace(
            self.settings,
            window_geometry=base64.b64encode(geometry).decode("ascii"),
            window_state=base64.b64encode(state).decode("ascii"),
        )
        self.save_settings(settings)

    def _apply_settings(self, settings: AppSettings) -> None:
        configure_logging(
            self.paths.logs_directory,
            settings.log_level,
            settings.log_retention_days,
            settings.file_logging_enabled,
        )