import json
import os
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from PySide6.QtWidgets import QApplication

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.core.event_models import SecurityEvent
from src.endpoint.integrity_baseline import FileIntegrityMonitor, ScanCancelledError


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


def test_file_integrity_event_actions_approve_and_track_investigation(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("trusted", encoding="utf-8")
    services.save_settings(
        replace(services.settings, file_integrity_roots=(str(watched),))
    )
    services.endpoint_service.establish_file_baseline((str(watched),))
    tracked.write_text("changed", encoding="utf-8")
    event = SecurityEvent(
        source="file-integrity",
        event_type="file_changed",
        severity="medium",
        description="Tracked file changed",
        attributes={"path": str(tracked.resolve())},
    )
    services.event_pipeline.publish(event)

    approved_hash = services.endpoint_service.acknowledge_file_integrity_event(event.id)

    baseline = services.database.fetchone(
        "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
        (str(tracked.resolve()),),
    )
    status = services.database.fetchone(
        "SELECT status, investigation_id FROM file_integrity_event_status WHERE event_id = ?",
        (event.id,),
    )
    assert approved_hash == baseline["sha256"]
    assert approved_hash == FileIntegrityMonitor.hash_file(tracked)
    assert status["status"] == "acknowledged"

    renamed = watched / "renamed.txt"
    tracked.rename(renamed)
    rename_event = SecurityEvent(
        source="file-integrity",
        event_type="file_renamed",
        severity="low",
        description="File renamed",
        attributes={
            "path": str(renamed.resolve()),
            "previous_path": str(tracked.resolve()),
        },
    )
    services.event_pipeline.publish(rename_event)
    renamed_hash = services.endpoint_service.acknowledge_file_integrity_event(rename_event.id)
    assert renamed_hash == FileIntegrityMonitor.hash_file(renamed)
    assert services.database.fetchone(
        "SELECT 1 FROM file_integrity_baselines WHERE path = ?",
        (str(renamed.resolve()),),
    ) is not None
    assert services.database.fetchone(
        "SELECT 1 FROM file_integrity_baselines WHERE path = ?",
        (str(tracked.resolve()),),
    ) is None

    added = watched / "new.txt"
    added.write_text("new content", encoding="utf-8")
    added_event = SecurityEvent(
        source="file-integrity",
        event_type="file_added",
        severity="low",
        description="New file detected",
        attributes={"path": str(added.resolve())},
    )
    services.event_pipeline.publish(added_event)
    added_hash = services.endpoint_service.acknowledge_file_integrity_event(added_event.id)
    assert added_hash == FileIntegrityMonitor.hash_file(added)
    assert services.database.fetchone(
        "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
        (str(added.resolve()),),
    )["sha256"] == added_hash

    investigation_id = services.endpoint_service.investigate_file_integrity_event(event.id)
    status = services.database.fetchone(
        "SELECT status, investigation_id FROM file_integrity_event_status WHERE event_id = ?",
        (event.id,),
    )
    assert status["status"] == "investigating"
    assert status["investigation_id"] == investigation_id

    services.endpoint_service.close_file_integrity_investigation(event.id)

    status = services.database.fetchone(
        "SELECT status FROM file_integrity_event_status WHERE event_id = ?",
        (event.id,),
    )
    investigation = services.database.fetchone(
        "SELECT status FROM investigations WHERE id = ?",
        (investigation_id,),
    )
    assert status["status"] == "closed"
    assert investigation["status"] == "closed"


def test_acknowledging_new_folder_hashes_and_approves_its_contents(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    services.save_settings(
        replace(services.settings, file_integrity_roots=(str(watched),))
    )
    services.endpoint_service.establish_file_baseline((str(watched),))
    created = watched / "new-folder"
    created.mkdir()
    content = created / "file.txt"
    content.write_text("reviewed folder content", encoding="utf-8")
    event = SecurityEvent(
        source="file-integrity",
        event_type="folder_added",
        severity="low",
        description="Folder added",
        attributes={"path": str(created.resolve()), "is_directory": True},
    )
    services.event_pipeline.publish(event)

    services.endpoint_service.acknowledge_file_integrity_event(event.id)

    baseline = services.database.fetchone(
        "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
        (str(content.resolve()),),
    )
    assert baseline["sha256"] == FileIntegrityMonitor.hash_file(content)


def test_startup_migrates_existing_baseline_to_automatic_exclusions(tmp_path):
    paths = AppPaths(tmp_path / "local")
    services = ApplicationServices.create(paths)
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("tracked", encoding="utf-8")
    generated = watched / ".git"
    generated.mkdir()
    generated_file = generated / "config"
    generated_file.write_text("generated", encoding="utf-8")
    services.save_settings(
        replace(services.settings, file_integrity_roots=(str(watched),))
    )
    FileIntegrityMonitor(services.database, (str(watched),), ()).establish_baseline()

    restarted = ApplicationServices.create(paths)

    assert restarted.database.fetchone(
        "SELECT 1 FROM file_integrity_baselines WHERE path = ?",
        (str(tracked.resolve()),),
    ) is not None
    assert restarted.database.fetchone(
        "SELECT 1 FROM file_integrity_baselines WHERE path = ?",
        (str(generated_file.resolve()),),
    ) is None
    assert restarted.endpoint_service.has_file_baseline((str(watched),))


def test_exclusion_checks_do_not_resolve_every_inventory_path(tmp_path, monkeypatch):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    generated = watched / ".git" / "config"
    watched.mkdir()
    monitor = FileIntegrityMonitor(services.database, (str(watched),))

    def fail_resolve(self, *args, **kwargs):
        raise AssertionError(f"Unexpected filesystem path resolution: {self}")

    monkeypatch.setattr(type(generated), "resolve", fail_resolve)

    assert monitor.is_excluded(generated)


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


def test_deleting_tracked_file_creates_missing_event_and_alert(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "remove-me.txt"
    tracked.write_text("trusted", encoding="utf-8")
    roots = (str(watched),)
    services.save_settings(replace(services.settings, file_integrity_roots=roots))
    services.endpoint_service.establish_file_baseline()
    tracked.unlink()

    assert services.endpoint_service.verify_file_integrity() == 1

    event = services.database.fetchone(
        "SELECT event_type, description, attributes_json FROM security_events "
        "WHERE source = 'file-integrity' ORDER BY occurred_at DESC LIMIT 1"
    )
    alert = services.database.fetchone(
        "SELECT title FROM alerts WHERE rule_id = 'file-integrity.file-missing'"
    )
    assert event["event_type"] == "file_missing"
    assert "remove-me.txt" in event["description"]
    assert json.loads(event["attributes_json"])["path"] == str(tracked.resolve())
    assert alert["title"] == "Protected file deleted"


def test_scan_skips_unchanged_hashes_and_full_verification_catches_same_metadata_tampering(
    tmp_path,
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_bytes(b"trusted")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    original_stat = tracked.stat()
    monitor = FileIntegrityMonitor(services.database, roots)

    tracked.write_bytes(b"changed")
    os.utime(tracked, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    assert monitor.scan() == []

    with services.database.transaction() as connection:
        connection.execute(
            "UPDATE file_integrity_scan_state SET last_full_verified_at = ? WHERE id = 1",
            ((datetime.now(UTC) - timedelta(days=2)).isoformat(),),
        )
    events = monitor.scan()

    assert [event.event_type for event in events] == ["file_changed"]


def test_scan_records_actual_per_folder_file_counts(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "one.txt").write_text("one", encoding="utf-8")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    (watched / "one.txt").unlink()
    (watched / "two.txt").write_text("two", encoding="utf-8")

    FileIntegrityMonitor(services.database, roots).scan()

    stats = services.database.fetchone(
        "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
        (str(watched.resolve()),),
    )
    assert stats["file_count"] == 1


def test_baseline_scan_cancellation_does_not_save_partial_baseline(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "tracked.txt").write_text("data", encoding="utf-8")
    cancellation = threading.Event()
    cancellation.set()

    with pytest.raises(ScanCancelledError):
        services.endpoint_service.establish_file_baseline(
            (str(watched),),
            cancel_event=cancellation,
        )

    assert not services.endpoint_service.has_file_baseline((str(watched),))


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


def test_file_integrity_collector_scans_on_watcher_changes(tmp_path):
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


def test_file_integrity_watcher_detects_create_modify_rename_and_delete_in_real_time(
    tmp_path,
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    modified = watched / "modify.txt"
    rename_source = watched / "rename-source.txt"
    deleted = watched / "delete.txt"
    modified.write_text("original", encoding="utf-8")
    rename_source.write_text("rename me", encoding="utf-8")
    deleted.write_text("delete me", encoding="utf-8")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    monitor = FileIntegrityMonitor(services.database, roots)
    monitor.start()
    try:
        monitor.collect()
        initial_count = services.database.fetchone(
            "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
            (str(watched.resolve()),),
        )["file_count"]

        def wait_for_event(event_type: str) -> None:
            deadline = time.monotonic() + 5
            observed: list[str] = []
            while time.monotonic() < deadline:
                observed.extend(event.event_type for event in monitor.collect())
                if event_type in observed:
                    return
                time.sleep(0.05)
            pytest.fail(
                f"Expected {event_type!r} from real filesystem notifications; "
                f"observed {observed!r}."
            )

        created = watched / "new.txt"
        created.write_text("new file", encoding="utf-8")
        wait_for_event("file_added")
        assert services.database.fetchone(
            "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
            (str(watched.resolve()),),
        )["file_count"] == initial_count + 1

        original_stat = modified.stat()
        modified.write_text("modified", encoding="utf-8")
        os.utime(
            modified,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        wait_for_event("file_changed")
        modified.write_text("original", encoding="utf-8")
        wait_for_event("file_changed")
        assert services.database.fetchone(
            "SELECT 1 FROM file_integrity_findings WHERE path = ?",
            (str(modified.resolve()),),
        ) is None

        renamed = watched / "rename-target.txt"
        rename_source.rename(renamed)
        wait_for_event("file_renamed")
        assert services.database.fetchone(
            "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
            (str(watched.resolve()),),
        )["file_count"] == initial_count + 1

        deleted.unlink()
        wait_for_event("file_missing")
        assert services.database.fetchone(
            "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
            (str(watched.resolve()),),
        )["file_count"] == initial_count
    finally:
        monitor.stop()


def test_file_integrity_watcher_reports_folder_creation_and_deletion(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    monitor = FileIntegrityMonitor(services.database, roots)
    monitor.start()
    try:
        monitor.collect()

        def wait_for_event(event_type: str):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                events = monitor.collect()
                match = next((event for event in events if event.event_type == event_type), None)
                if match is not None:
                    return match
                time.sleep(0.05)
            pytest.fail(f"Expected filesystem notification {event_type!r}.")

        created = watched / "empty-folder"
        created.mkdir()
        added_event = wait_for_event("folder_added")
        assert added_event.attributes["path"] == str(created.resolve())

        created.rmdir()
        deleted_event = wait_for_event("folder_deleted")
        assert deleted_event.attributes["path"] == str(created.resolve())
    finally:
        monitor.stop()


def test_created_folder_indexes_and_counts_files_beneath_it(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    monitor = FileIntegrityMonitor(services.database, roots)
    monitor.start()
    try:
        folder = watched / "new-folder"
        folder.mkdir()
        content = folder / "created.txt"
        content.write_text("new file content", encoding="utf-8")
        monitor._record_change("created", str(folder), None, True)
        time.sleep(monitor.EVENT_SETTLE_SECONDS + 0.05)

        events = monitor.collect()

        assert {event.event_type for event in events} == {"folder_added", "file_added"}
        inventory = services.database.fetchone(
            "SELECT sha256 FROM file_integrity_inventory WHERE path = ?",
            (str(content.resolve()),),
        )
        count = services.database.fetchone(
            "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
            (str(watched.resolve()),),
        )
        assert inventory["sha256"] == FileIntegrityMonitor.hash_file(content)
        assert count["file_count"] == 1
    finally:
        monitor.stop()


def test_file_integrity_watcher_does_not_walk_entire_tree_for_each_file_event(
    tmp_path, monkeypatch
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    existing = watched / "trusted.txt"
    existing.write_text("trusted", encoding="utf-8")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    monitor = FileIntegrityMonitor(services.database, roots)
    try:
        monitor.start()
        monitor.collect()

        def fail_if_full_scan(*args, **kwargs):
            raise AssertionError("A file notification must not trigger a full folder walk.")

        monkeypatch.setattr(monitor, "_snapshot", fail_if_full_scan)
        created = watched / "new.txt"
        created.write_text("new", encoding="utf-8")
        deadline = time.monotonic() + 5
        events = []
        while not events and time.monotonic() < deadline:
            events.extend(monitor.collect())
            time.sleep(0.05)

        assert [event.event_type for event in events] == ["file_added"]
        assert services.database.fetchone(
            "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
            (str(watched.resolve()),),
        )["file_count"] == 2
        created.write_text("modified", encoding="utf-8")
        deadline = time.monotonic() + 5
        changed_events = []
        while not changed_events and time.monotonic() < deadline:
            changed_events.extend(monitor.collect())
            time.sleep(0.05)
        assert [event.event_type for event in changed_events] == ["file_changed"]

        created.unlink()
        deadline = time.monotonic() + 5
        deleted_events = []
        while not deleted_events and time.monotonic() < deadline:
            deleted_events.extend(monitor.collect())
            time.sleep(0.05)
        assert [event.event_type for event in deleted_events] == ["file_missing"]
        assert services.database.fetchone(
            "SELECT file_count FROM file_integrity_folder_stats WHERE root = ?",
            (str(watched.resolve()),),
        )["file_count"] == 1
    finally:
        monitor.stop()


def test_file_integrity_collector_periodically_recovers_missed_watcher_events(tmp_path):
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

        tracked.unlink()
        monitor._pending_changes.clear()
        monitor._pending_changes_queue.clear()
        monitor._last_scan_monotonic = (
            time.monotonic() - monitor.PERIODIC_SCAN_INTERVAL_SECONDS - 1
        )

        events = monitor.collect()

        assert [event.event_type for event in events] == ["file_missing"]
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


def test_full_scan_does_not_infer_rename_from_hash_alone(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "rename-watched"
    watched.mkdir()
    original = watched / "before.txt"
    original.write_text("same content", encoding="utf-8")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    original.rename(watched / "after.txt")

    events = FileIntegrityMonitor(services.database, roots).scan()

    assert {event.event_type for event in events} == {"file_added", "file_missing"}
    assert all(event.event_type != "file_renamed" for event in events)


def test_watcher_create_and_delete_with_matching_hash_are_not_a_rename(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    removed = watched / "removed.txt"
    removed.write_text("same bytes", encoding="utf-8")
    roots = (str(watched),)
    services.endpoint_service.establish_file_baseline(roots)
    monitor = FileIntegrityMonitor(services.database, roots)
    monitor.start()
    try:
        monitor.collect()
        added = watched / "added.txt"
        removed.unlink()
        added.write_text("same bytes", encoding="utf-8")
        monitor._record_change("deleted", str(removed), None, False)
        monitor._record_change("created", str(added), None, False)
        time.sleep(monitor.EVENT_SETTLE_SECONDS + 0.05)

        events = monitor.collect()

        assert {event.event_type for event in events} == {"file_added", "file_missing"}
    finally:
        monitor.stop()


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


def test_excluded_directory_is_pruned_from_integrity_snapshot(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    root = tmp_path / "watched"
    generated = root / "node_modules" / "package"
    generated.mkdir(parents=True)
    (generated / "index.js").write_text("generated", encoding="utf-8")
    (root / "important.txt").write_text("keep", encoding="utf-8")
    monitor = FileIntegrityMonitor(
        services.database,
        (str(root),),
        ("**/node_modules/**",),
    )

    snapshot = monitor._snapshot()

    assert [path.name for path in snapshot] == ["important.txt"]


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
