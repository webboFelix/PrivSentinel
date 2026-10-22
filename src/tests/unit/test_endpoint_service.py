from dataclasses import replace

import pytest

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
    assert not services.endpoint_service.has_file_baseline(
        (str(tmp_path / "other"),), exclusions
    )
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
    assert events[0].attributes["previous_path"] == str(original)
    assert "path changed" in events[0].description


def test_baseline_reports_progress_while_hashing_files(tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    watched = tmp_path / "watched"
    watched.mkdir()
    for index in range(101):
        (watched / f"{index:03}.txt").write_text("data", encoding="utf-8")
    progress = []

    count = services.endpoint_service.establish_file_baseline(
        (str(watched),), progress_callback=progress.append
    )

    assert count == 101
    assert progress == [25, 50, 75, 100, 101]


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


def test_changing_endpoint_settings_restarts_all_enabled_sources(
    tmp_path, monkeypatch
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    endpoint = services.endpoint_service
    calls = []
    monkeypatch.setattr(endpoint, "stop_all", lambda: calls.append("stop"))
    monkeypatch.setattr(
        endpoint,
        "start_configured",
        lambda *args, **kwargs: calls.append(("start", args, kwargs)),
    )

    endpoint.set_settings(
        replace(services.settings, network_monitoring_enabled=True)
    )

    assert calls == ["stop", ("start", (), {})]
