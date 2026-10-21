import json
import logging
import os
import subprocess
import sys
from dataclasses import asdict
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

import pytest

from src.app.dependencies import ApplicationServices
from src.config.logging_config import configure_logging
from src.config.paths import AppPaths
from src.config.settings import AppSettings, SettingsError, SettingsStore


@pytest.fixture(autouse=True)
def close_application_log_handlers():
    yield
    configure_logging(Path.cwd(), "INFO", 30, file_logging_enabled=False)


def test_paths_are_rooted_under_local_appdata_and_created(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    paths = AppPaths.from_environment()
    paths.ensure_directories()

    assert paths.root == tmp_path / "PrivSentinel"
    assert paths.settings_file.parent == paths.config_directory
    assert paths.database_file.parent == paths.data_directory
    for directory in (
        paths.root,
        paths.data_directory,
        paths.logs_directory,
        paths.backups_directory,
        paths.secrets_directory,
        paths.models_directory,
        paths.exports_directory,
        paths.quarantine_directory,
    ):
        assert directory.is_dir()


def test_settings_persist_across_store_instances(tmp_path):
    path = tmp_path / "PrivSentinel" / "settings.json"
    first_run = SettingsStore(path)
    first_run.load()
    saved = first_run.save(
        AppSettings(log_level="DEBUG", log_retention_days=90, camera_index=7)
    )

    restarted = SettingsStore(path)
    assert restarted.load() == saved
    assert saved.camera_index == 7
    assert json.loads(path.read_text(encoding="utf-8"))["camera_index"] == 7
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 6


def test_existing_camera_index_is_preserved(tmp_path):
    path = tmp_path / "settings.json"
    raw_settings = AppSettings(camera_index=3)
    path.write_text(
        json.dumps(asdict(raw_settings)),
        encoding="utf-8",
    )

    settings = SettingsStore(path).load()

    assert settings.camera_index == 3
    assert json.loads(path.read_text(encoding="utf-8"))["camera_index"] == 3


def test_legacy_version_one_settings_are_migrated(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "log_level": "WARNING",
                "log_retention_days": 7,
            }
        ),
        encoding="utf-8",
    )

    migrated = SettingsStore(path).load()

    assert migrated.schema_version == 6
    assert migrated.log_level == "WARNING"
    assert migrated.file_logging_enabled is True
    assert migrated.camera_access_enabled is False
    assert migrated.automatic_lock_enabled is False
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 6
    assert migrated.recognition_model_download_prompted is False
    assert migrated.recognition_model_download_allowed is False


def test_version_four_settings_gain_model_download_preferences(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 4,
                "log_level": "INFO",
                "log_retention_days": 30,
                "file_logging_enabled": True,
                "backup_before_save": False,
            }
        ),
        encoding="utf-8",
    )

    migrated = SettingsStore(path).load()

    assert migrated.schema_version == 6
    assert not migrated.recognition_model_download_prompted
    assert not migrated.recognition_model_download_allowed


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("log_level", "TRACE"),
        ("log_retention_days", 0),
        ("log_retention_days", True),
        ("file_logging_enabled", "yes"),
        ("recognition_model_download_prompted", "yes"),
        ("schema_version", 99),
        ("unexpected", "value"),
    ],
)
def test_invalid_settings_are_rejected(tmp_path, key, value):
    path = tmp_path / "settings.json"
    raw = {
        "schema_version": 5,
        "log_level": "INFO",
        "log_retention_days": 30,
        "file_logging_enabled": True,
        "backup_before_save": False,
        "window_geometry": None,
        "window_state": None,
        key: value,
    }
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(SettingsError):
        SettingsStore(path).load()


def test_malformed_settings_fail_explicitly(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(SettingsError, match="Could not read settings file"):
        SettingsStore(path).load()


def test_reset_restores_defaults(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    store.save(AppSettings(log_level="ERROR", log_retention_days=365))

    assert store.reset() == AppSettings()
    assert store.load() == AppSettings()


def test_backup_and_restore_round_trip(tmp_path):
    path = tmp_path / "settings.json"
    store = SettingsStore(path)
    original = AppSettings(log_level="ERROR", log_retention_days=180)
    store.save(original)
    backup = store.backup()
    store.save(AppSettings(log_level="DEBUG", log_retention_days=7))

    assert backup.is_file()
    assert store.restore(backup) == original


def test_failed_atomic_replace_preserves_previous_file(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    store = SettingsStore(path)
    old = AppSettings(log_level="INFO")
    store.save(old)

    def fail_replace(_source, _target):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(SettingsError, match="atomically write"):
        store.save(AppSettings(log_level="ERROR"))

    monkeypatch.undo()
    assert SettingsStore(path).load() == old
    assert not list(tmp_path.glob(".settings.json.*.tmp"))


def test_auto_backup_precedes_settings_update(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    store.save(AppSettings())
    updated = AppSettings(log_level="ERROR", backup_before_save=True)

    store.save(updated)

    assert (tmp_path / "backups" / "settings.backup.json").is_file()
    backup_settings = SettingsStore(
        tmp_path / "backups" / "settings.backup.json"
    ).load()
    assert backup_settings == AppSettings()


def test_application_services_apply_logging_settings(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    saved = AppSettings(
        log_level="DEBUG",
        log_retention_days=90,
        file_logging_enabled=True,
    )

    services.save_settings(saved)

    logger = logging.getLogger("privsentinel")
    assert logger.level == logging.DEBUG
    handler = next(
        handler
        for handler in logger.handlers
        if getattr(handler, "_privsentinel_managed", False)
    )
    assert isinstance(handler, TimedRotatingFileHandler)
    assert handler.backupCount == 90
    assert handler.baseFilename.startswith(str(services.paths.logs_directory))
    logger = configure_logging(
        services.paths.logs_directory,
        "DEBUG",
        90,
        file_logging_enabled=True,
    )
    logger.info("settings-driven log output")
    handler = next(
        handler
        for handler in logger.handlers
        if getattr(handler, "_privsentinel_managed", False)
    )
    handler.flush()
    assert (services.paths.logs_directory / "privsentinel.log").read_text(
        encoding="utf-8"
    ).find("settings-driven log output") >= 0


def test_application_services_reload_settings_after_restart(tmp_path):
    paths = AppPaths(tmp_path / "local")
    first_run = ApplicationServices.create(paths)
    first_run.save_settings(
        AppSettings(log_level="ERROR", log_retention_days=365)
    )

    restarted = ApplicationServices.create(paths)

    assert restarted.settings.log_level == "ERROR"
    assert restarted.settings.log_retention_days == 365


def test_settings_survive_a_fresh_python_process(tmp_path):
    local_app_data = tmp_path / "LocalAppData"
    paths = AppPaths.from_environment(local_app_data)
    services = ApplicationServices.create(paths)
    services.save_settings(AppSettings(log_level="WARNING", log_retention_days=180))
    repo_root = Path(__file__).resolve().parents[3]
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(local_app_data)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from src.app.dependencies import ApplicationServices; "
                "print(ApplicationServices.create().settings.log_level)"
            ),
        ],
        cwd=repo_root,
        capture_output=True,
        check=True,
        env=environment,
        text=True,
    )

    assert result.stdout.strip() == "WARNING"


def test_application_services_migrates_previous_root_settings_file(tmp_path):
    paths = AppPaths(tmp_path / "local")
    legacy = paths.root / "settings.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "log_level": "ERROR",
                "log_retention_days": 14,
                "file_logging_enabled": True,
                "backup_before_save": False,
                "window_geometry": None,
                "window_state": None,
            }
        ),
        encoding="utf-8",
    )

    services = ApplicationServices.create(paths)

    assert services.settings.log_level == "ERROR"
    assert services.paths.settings_file == (
        paths.root / "config" / "settings.json"
    )
    assert services.paths.settings_file.is_file()


def test_application_entry_point_imports_from_its_own_directory():
    app_directory = Path(__file__).resolve().parents[2] / "app"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import application; assert callable(application.main)",
        ],
        cwd=app_directory,
        capture_output=True,
        check=True,
        text=True,
    )

    assert not result.stdout


@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
def test_dpapi_secret_is_encrypted_and_survives_store_restart(tmp_path):
    paths = AppPaths(tmp_path / "local")
    services = ApplicationServices.create(paths)
    services.secret_store.set("master-key", b"confidential key material")

    encrypted = (paths.secrets_directory / "master-key.dpapi").read_bytes()
    assert b"confidential key material" not in encrypted
    assert b"confidential key material" not in paths.settings_file.read_bytes()
    restarted = ApplicationServices.create(paths)
    assert restarted.secret_store.get("master-key") == (
        b"confidential key material"
    )
