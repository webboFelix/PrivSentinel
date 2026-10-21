"""Per-user application paths rooted under Local AppData."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppPaths:
    root: Path

    @classmethod
    def from_environment(cls, local_app_data: str | Path | None = None) -> "AppPaths":
        base = local_app_data or os.environ.get("LOCALAPPDATA")
        if base is None:
            if os.name == "nt":
                raise OSError("LOCALAPPDATA is not set; cannot initialize PrivSentinel.")
            base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        return cls(Path(base).expanduser() / "PrivSentinel")

    @property
    def settings_file(self) -> Path:
        return self.config_directory / "settings.json"

    @property
    def config_directory(self) -> Path:
        return self.root / "config"

    @property
    def data_directory(self) -> Path:
        return self.root / "data"

    @property
    def database_file(self) -> Path:
        return self.data_directory / "privsentinel.db"

    @property
    def logs_directory(self) -> Path:
        return self.root / "logs"

    @property
    def backups_directory(self) -> Path:
        return self.root / "backups"

    @property
    def secrets_directory(self) -> Path:
        return self.root / "secrets"

    @property
    def models_directory(self) -> Path:
        return self.root / "models"

    @property
    def identity_events_database(self) -> Path:
        return self.database_file

    @property
    def exports_directory(self) -> Path:
        return self.root / "exports"

    @property
    def quarantine_directory(self) -> Path:
        return self.root / "quarantine"

    @property
    def yara_rules_directory(self) -> Path:
        return self.root / "rules"

    def ensure_directories(self) -> None:
        for directory in (
            self.root,
            self.config_directory,
            self.data_directory,
            self.logs_directory,
            self.backups_directory,
            self.secrets_directory,
            self.models_directory,
            self.exports_directory,
            self.quarantine_directory,
            self.yara_rules_directory,
        ):
            directory.mkdir(parents=True, exist_ok=True)