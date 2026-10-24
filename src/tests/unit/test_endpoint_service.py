import os
import time
from dataclasses import replace

import pytest
from PySide6.QtWidgets import QApplication

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.endpoint.integrity_baseline import FileIntegrityMonitor


def test_file_baseline_is_bound_to_roots_and_exclusions(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "tracked.txt").write_text("original", encoding="utf-8")
    roots = (str(watched),)
    exclusions = ("*.tmp",)

    services.endpoint_service.establish_file_baseline(roots, exclusions)

    assert services.endpoint_service.has_file_baseline(roots, exclusions)
    assert not services.endpoint_service.has_file_baseline((str(tmp_path / "other"),), exclusions)
    assert not services.endpoint_service.has_file_baseline(roots, ("*.log",))


def test_empty_folder_can_have_a_current_file_baseline(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "empty-watched"
    watched.mkdir()
    roots = (str(watched),)

    assert services.endpoint_service.establish_file_baseline(roots) == 0
    assert services.endpoint_service.has_file_baseline(roots)


def test_empty_folder_baseline_can_scan_new_files(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "empty-watched"
    watched.mkdir()
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    (watched / "added.txt").write_text("new", encoding="utf-8")
    monitor = FileIntegrityMonitor(services.database, roots)

    events = monitor.scan()

    assert [event.event_type for event in events] == ["file_added"]

    baseline = services.database.fetchone(
        "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
        (str((watched / "added.txt").resolve()),),
    )
    assert baseline is None


def test_file_integrity_scan_keeps_trusted_hashes_and_deduplicates_findings(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("trusted", encoding="utf-8")
    roots = (str(watched),)
    services.save_settings(replace(services.settings, file_integrity_roots=roots))
    services.endpoint_service.establish_file_baseline()
    trusted_hash = services.database.fetchone(
        "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
        (str(tracked.resolve()),),
    )["sha256"]

    tracked.write_text("changed", encoding="utf-8")
    monitor = FileIntegrityMonitor(services.database, roots)

    assert [event.event_type for event in monitor.scan()] == ["file_changed"]
    assert monitor.scan() == []
    assert (
        services.database.fetchone(
            "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
            (str(tracked.resolve()),),
        )["sha256"]
        == trusted_hash
    )


def test_file_integrity_verification_creates_security_alerts(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("trusted", encoding="utf-8")
    roots = (str(watched),)
    services.save_settings(replace(services.settings, file_integrity_roots=roots))
    services.endpoint_service.establish_file_baseline()
    tracked.write_text("changed", encoding="utf-8")

    assert services.endpoint_service.verify_file_integrity() == 1

    alerts = services.security_repository.list_alerts(limit=10)
    assert len(alerts) == 1
    assert alerts[0]["title"] == "Protected file content changed"
    assert alerts[0]["source"] == "file-integrity"


def test_approving_file_change_updates_baseline_and_records_previous_hash(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("trusted", encoding="utf-8")
    roots = (str(watched),)
    services.save_settings(replace(services.settings, file_integrity_roots=roots))
    services.endpoint_service.establish_file_baseline()
    old_hash = services.database.fetchone(
        "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
        (str(tracked.resolve()),),
    )["sha256"]
    tracked.write_text("approved", encoding="utf-8")

    new_hash = services.endpoint_service.approve_file_integrity_change(str(tracked))

    approval = services.database.fetchone(
        "SELECT previous_sha256, approved_sha256 FROM file_integrity_approvals WHERE path = ?",
        (str(tracked.resolve()),),
    )
    assert new_hash != old_hash
    assert approval["previous_sha256"] == old_hash
    assert approval["approved_sha256"] == new_hash
    assert FileIntegrityMonitor(services.database, roots).scan() == []


def test_file_integrity_evidence_records_current_hash_in_evidence_store(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("evidence content", encoding="utf-8")
    roots = (str(watched),)
    services.save_settings(replace(services.settings, file_integrity_roots=roots))

    evidence_id = services.endpoint_service.record_file_integrity_evidence(str(tracked))

    evidence = services.database.fetchone(
        "SELECT title, evidence_type, path, sha256 FROM evidence_items WHERE id = ?",
        (evidence_id,),
    )
    assert evidence["title"] == "tracked.txt"
    assert evidence["evidence_type"] == "file-integrity"
    assert evidence["path"] == str(tracked.resolve())
    assert evidence["sha256"] == FileIntegrityMonitor.hash_file(tracked)


def test_file_integrity_collector_scans_on_watcher_changes_only(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("trusted", encoding="utf-8")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    monitor = FileIntegrityMonitor(services.database, roots)
    try:
        monitor.start()
        assert monitor.collect() == []
        assert monitor.collect() == []

        tracked.write_text("modified", encoding="utf-8")
        detected = []
        deadline = time.monotonic() + 5
        while not detected and time.monotonic() < deadline:
            detected.extend(monitor.collect())
            time.sleep(0.05)

        assert [event.event_type for event in detected] == ["file_changed"]
        assert monitor.collect() == []
    finally:
        monitor.stop()


def test_file_integrity_service_worker_starts_and_stops_watcher(qtbot, tmp_path):
    application = QApplication.instance()
    assert application is not None
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("trusted", encoding="utf-8")
    roots = (str(watched),)
    services.save_settings(
        replace(
            services.settings,
            file_integrity_roots=roots,
            file_integrity_monitoring_enabled=True,
        )
    )
    services.endpoint_service.establish_file_baseline()

    services.endpoint_service.start("file-integrity")
    worker = services.endpoint_service.workers["file-integrity"]
    deadline = time.monotonic() + 5
    while worker.last_successful_collection_at is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert worker.last_successful_collection_at is not None

    tracked.write_text("changed", encoding="utf-8")
    deadline = time.monotonic() + 5
    while (
        services.database.fetchone(
            "SELECT 1 FROM alerts WHERE rule_id = 'file-integrity.content-changed'"
        )
        is None
        and time.monotonic() < deadline
    ):
        application.processEvents()
        time.sleep(0.05)
    application.processEvents()
    services.endpoint_service.stop("file-integrity")

    assert (
        services.database.fetchone(
            "SELECT 1 FROM alerts WHERE rule_id = 'file-integrity.content-changed'"
        )
        is not None
    )
    assert not worker.isRunning()


def test_file_move_with_unique_matching_hash_is_reported_as_inferred_rename(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "rename-watched"
    watched.mkdir()
    original = watched / "before.txt"
    original.write_text("same content", encoding="utf-8")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    original.rename(watched / "after.txt")

    events = FileIntegrityMonitor(services.database, roots).scan()

    assert [event.event_type for event in events] == ["file_renamed"]
    assert os.path.normcase(events[0].attributes["previous_path"]) == os.path.normcase(
        str(original)
    )
    assert "path changed" in events[0].description


def test_baseline_reports_progress_while_hashing_files(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    for index in range(101):
        (watched / f"{index:03}.txt").write_text("data", encoding="utf-8")
    progress = []
    detailed_progress = []

    count = services.endpoint_service.establish_file_baseline(
        (str(watched),),
        progress_callback=progress.append,
        progress_details_callback=lambda processed, total: detailed_progress.append(
            (processed, total)
        ),
    )

    assert count == 101
    assert progress == [25, 50, 75, 100, 101]
    assert detailed_progress == [
        (-1, -1),
        (0, 101),
        (25, 101),
        (50, 101),
        (75, 101),
        (100, 101),
        (101, 101),
    ]


def test_file_integrity_monitor_supports_large_default_baseline(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))

    monitor = FileIntegrityMonitor(services.database, (str(tmp_path),))

    assert monitor.maximum_files == 500000


def test_file_integrity_baseline_still_enforces_configured_file_cap(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    for index in range(3):
        (watched / f"{index}.txt").write_text("data", encoding="utf-8")
    monitor = FileIntegrityMonitor(services.database, (str(watched),), maximum_files=2)

    with pytest.raises(RuntimeError, match="safety cap of 2 files"):
        monitor.establish_baseline()

    assert not services.endpoint_service.has_file_baseline((str(watched),))


def test_missing_baseline_root_is_reported_instead_of_saved_as_empty(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    missing = tmp_path / "missing-folder"

    with pytest.raises(OSError, match="unavailable or not a folder"):
        services.endpoint_service.establish_file_baseline((str(missing),))

    assert not services.endpoint_service.has_file_baseline((str(missing),))


def test_integrity_exclusions_match_windows_and_forward_slash_paths(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    root = tmp_path / "watched"
    nested = root / "subfolder"
    nested.mkdir(parents=True)
    temporary = nested / "pending.tmp"
    temporary.touch()
    pattern = str(root / "**" / "*.tmp").replace("\\", "/")
    monitor = FileIntegrityMonitor(services.database, (str(root),), (pattern,))

    assert monitor._excluded(temporary)


def test_changing_endpoint_settings_restarts_all_enabled_sources(tmp_path, monkeypatch):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    endpoint = services.endpoint_service
    calls = []
    monkeypatch.setattr(endpoint, "stop_all", lambda: calls.append("stop"))
    monkeypatch.setattr(
        endpoint,
        "start_configured",
        lambda *args, **kwargs: calls.append(("start", args, kwargs)),
    )

    endpoint.set_settings(replace(services.settings, network_monitoring_enabled=True))

    assert calls == ["stop", ("start", (), {})]
