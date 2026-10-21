import socket
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QMessageBox

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.core.event_models import SecurityEvent
from src.endpoint.process_monitor import ProcessSnapshot
from src.storage.models import IdentityEvent
from src.ui.components.search_bar import SearchBar
from src.ui.main_window import MainWindow
from src.ui.navigation import PAGE_DEFINITIONS
from src.ui.pages.dashboard import _ratio_percent


@pytest.fixture
def window(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    main_window = MainWindow(services)
    qtbot.addWidget(main_window)
    return main_window


def test_all_pages_are_registered_and_navigation_updates_active_page(window):
    window.show()

    assert len(window.page_keys) == 16
    assert set(window.page_keys) == {page.key for page in PAGE_DEFINITIONS}
    assert window.current_page_key == "dashboard"

    window.navigate_to("network-monitor")

    assert window.current_page_key == "network-monitor"
    assert window.sidebar.buttons["network-monitor"].isChecked()
    assert not window.sidebar.buttons["dashboard"].isChecked()


def test_sidebar_and_dashboard_shortcuts_navigate(qtbot, window):
    window.show()

    qtbot.mouseClick(
        window.sidebar.buttons["alerts"],
        Qt.MouseButton.LeftButton,
    )
    assert window.current_page_key == "alerts"

    window._pages["dashboard"].identity_card.findChild(
        type(window.sidebar.buttons["dashboard"])
    ).click()
    assert window.current_page_key == "identity-protection"


def test_global_search_completer_navigates_to_selected_page(qtbot, window):
    with qtbot.waitSignal(window.topbar.pageSearchRequested):
        window.topbar.search_bar.pageSelected.emit("reports")

    window.navigate_to("reports")
    assert window.current_page_key == "reports"


def test_global_search_submission_emits_query(qtbot):
    search = SearchBar((("network-monitor", "Network Monitor"),))
    qtbot.addWidget(search)
    search.setText("network")
    with qtbot.waitSignal(search.searchSubmitted) as signal:
        search.returnPressed.emit()

    assert signal.args == ["network"]


def test_dashboard_monitoring_control_requests_explicit_toggle(qtbot, window):
    dashboard = window._pages["dashboard"]

    assert dashboard.monitoring_button.text() == "Start Monitoring"
    dashboard.actionRequested.disconnect(window._handle_page_action)
    with qtbot.waitSignal(dashboard.actionRequested) as signal:
        dashboard.monitoring_button.click()

    assert signal.args == ["toggle-monitoring"]


def test_dashboard_populates_charts_and_feed_from_persisted_events(window):
    dashboard = window._pages["dashboard"]
    assert not dashboard.alert_chart._has_data
    assert not dashboard.integrity_chart._has_data

    window.services.event_pipeline.publish(
        SecurityEvent(
            source="file-integrity",
            event_type="file_modified",
            severity="high",
            description="Tracked file changed",
        )
    )
    dashboard.refresh_security_data()

    assert dashboard.alert_chart._has_data
    assert sum(dashboard.alert_chart.plot._values) == 1
    assert dashboard.alert_chart.plot._severity_counts[-1]["high"] == 1
    assert dashboard.integrity_chart._has_data
    assert dashboard.feed.table.rowCount() == 1
    assert "Tracked file changed" in dashboard.feed.table.item(0, 2).text()


def test_dashboard_summary_cards_show_only_persisted_or_configured_values(window):
    dashboard = window._pages["dashboard"]
    assert dashboard.identity_summary.state_label.text() == "NOT ENROLLED"
    assert dashboard.score_summary.ring._score is None
    assert dashboard.score_summary.risk_label.text() == "NO DATA · ENABLE MONITORS"
    assert dashboard.score_summary.factor_progress["Identity"].value() == 0
    assert dashboard.score_summary.factor_values["Identity"].text() == "N/A"
    assert dashboard.threat_summary.count_label.text() == "0"
    assert dashboard.files_summary.count_label.text() == "0"

    dashboard.set_identity_state(
        "Local user",
        False,
        "recognized",
        "Identity matched.",
        0,
        IdentityEvent(
            "identity-event",
            datetime.now(UTC),
            "verification",
            "recognized",
            0.987,
            "passed",
            "Identity matched.",
        ),
    )
    assert dashboard.identity_summary.state_label.text() == "VERIFIED"
    assert dashboard.identity_summary.confidence_label.text() == "Confidence  98.7%"
    assert dashboard.identity_summary.last_verified_label.text() == "Last verified  0 seconds ago"

    with window.services.database.transaction() as connection:
        connection.execute(
            "INSERT INTO file_integrity_baselines "
            "(path, sha256, modified_ns, size, captured_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("C:\\\\tracked.txt", "hash", 1, 4, "2026-10-12T00:00:00+00:00"),
        )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="file-integrity",
            event_type="file_changed",
            severity="medium",
            description="Tracked file changed",
        )
    )
    dashboard.refresh_security_data()

    assert dashboard.files_summary.count_label.text() == "1"
    assert dashboard.files_summary.changes_label.text() == "Recorded changes  1"
    assert dashboard.files_summary.suspicious_label.text() == "Unresolved file alerts  0"
    assert dashboard.files_summary.quarantined_label.text() == "Quarantined  —"


def test_dashboard_score_card_reports_only_available_measured_ratios(window):
    score_card = window._pages["dashboard"].score_summary
    score_card.set_factors(
        {
            "Identity": (80, "4/5 recognized samples"),
            "Files": (92, "23/25 baseline paths without active alerts"),
            "Processes": (50, "75/150 processes"),
            "Network": (60, "3/5 remote"),
            "Windows": (None, "No successful channel read"),
        }
    )

    assert score_card.ring._score is None
    assert score_card.risk_label.text() == "INCOMPLETE · ENABLE MISSING MONITORS"
    assert {
        name: progress.value()
        for name, progress in score_card.factor_progress.items()
    } == {
        "Identity": 80,
        "Files": 92,
        "Processes": 50,
        "Network": 60,
        "Windows": 0,
    }
    assert {
        name: label.text() for name, label in score_card.factor_values.items()
    } == {
        "Identity": "80%",
        "Files": "92%",
        "Processes": "50%",
        "Network": "60%",
        "Windows": "N/A",
    }
    assert score_card.factor_stats["Processes"].text() == "75/150 processes"

    score_card.set_factors(
        {
            "Identity": (80, "4/5 samples"),
            "Files": (92, "23/25 files"),
            "Processes": (50, "75/150 processes"),
            "Network": (60, "3/5 remote"),
            "Windows": (40, "1/2 channels"),
        }
    )
    assert score_card.ring._score == 64.4
    assert score_card.risk_label.text() == "FAIR · REVIEW WEAK AREAS"
    assert score_card.ring._color.name() == "#f5ad32"
    assert {
        name: label.text() for name, label in score_card.factor_values.items()
    } == {
        "Identity": "80%",
        "Files": "92%",
        "Processes": "50%",
        "Network": "60%",
        "Windows": "40%",
    }


def test_dashboard_scan_action_opens_real_malware_scan_workflow(window):
    dashboard = window._pages["dashboard"]
    dashboard.monitor_button.click()

    assert window.current_page_key == "malware-protection"
    page = window._pages["malware-protection"]
    assert page.yara_scan_button.text() == "Scan all volumes with YARA"
    assert page.defender_scan_button.text() == "Request Defender full scan"


def test_endpoint_state_updates_main_window_status(window):
    window.services.endpoint_service.stateChanged.emit("process", "running")

    assert window.statusBar().currentMessage() == "process: running"


def test_browser_protection_page_shows_extension_install_workflow(window):
    page = window._pages["web-protection"]
    assert page.table.rows == ()
    assert page.status.text_label.text().startswith("0 local browser event")
    assert page.configure_button.text() == "Configure reputation feeds…"


def test_download_scanning_toggle_persists_enabled_state(window, tmp_path):
    window.services.save_settings(
        replace(
            window.services.settings,
            download_scan_directory=str(tmp_path),
            download_scan_enabled=False,
        )
    )
    page = window._pages["malware-protection"]

    page.toggle_download_watcher()

    assert page._download_observer is not None
    assert window.services.settings.download_scan_enabled is True

    page.toggle_download_watcher()

    assert page._download_observer is None
    assert window.services.settings.download_scan_enabled is False


def test_changing_download_folder_restarts_monitor_without_disabling_it(
    window, monkeypatch, tmp_path
):
    old_folder = tmp_path / "old-downloads"
    new_folder = tmp_path / "new-downloads"
    old_folder.mkdir()
    new_folder.mkdir()
    window.services.save_settings(
        replace(
            window.services.settings,
            download_scan_directory=str(old_folder),
            download_scan_enabled=True,
        )
    )
    page = window._pages["malware-protection"]
    page._start_download_watcher()
    monkeypatch.setattr(
        "src.ui.pages.malware_protection.QFileDialog.getExistingDirectory",
        Mock(return_value=str(new_folder)),
    )

    page.choose_download_folder()

    assert page._download_observer is not None
    assert window.services.settings.download_scan_enabled is True
    assert window.services.settings.download_scan_directory == str(new_folder)
    page.toggle_download_watcher()


def test_dashboard_ratios_require_a_real_denominator():
    assert _ratio_percent(0, 0) is None
    assert _ratio_percent(4, 5) == 80
    assert _ratio_percent(8, 5) == 100


def test_dashboard_activity_tables_use_network_events_and_live_process_metrics(
    window, monkeypatch
):
    dashboard = window._pages["dashboard"]
    window.services.settings = replace(
        window.services.settings, process_monitoring_enabled=True
    )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="network",
            event_type="network_connection",
            severity="info",
            description="Connection metadata observed",
            attributes={
                "local_address": "192.168.1.20",
                "remote_address": "8.8.8.8",
                "remote_port": 443,
                "protocol": "TCP",
                "state": "ESTABLISHED",
            },
        )
    )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="process",
            event_type="process_started",
            severity="info",
            description="New process observed: example.exe",
            attributes={"process_name": "example.exe", "pid": 321},
        )
    )
    monkeypatch.setattr(
        dashboard._process_snapshot,
        "snapshot",
        lambda limit: [
            ProcessSnapshot(321, "example.exe", 12.5, 44 * 1024 * 1024)
        ],
    )

    dashboard.refresh_security_data()

    assert dashboard.network_activity.table.rowCount() == 1
    assert dashboard.network_activity.table.item(0, 1).text() == "8.8.8.8"
    assert dashboard.network_activity.connection_count.text() == "1"
    assert dashboard.process_activity.table.rowCount() == 1
    assert dashboard.process_activity.table.item(0, 0).text() == "example.exe"
    assert dashboard.process_activity.table.item(0, 1).text() == "321"
    assert dashboard.process_activity.table.item(0, 2).text() == "12.5%"
    assert dashboard.process_activity.table.item(0, 3).text() == "44.0 MB"
    assert dashboard.feed.table.rowCount() == 2

    dashboard.feed.set_filter("Process")

    assert dashboard.feed.table.rowCount() == 1
    assert dashboard.feed.table.item(0, 3).text() == "Process"


def test_network_monitor_reads_persisted_local_events(window, monkeypatch):
    page = window._pages["network-monitor"]
    window.services.settings = replace(
        window.services.settings, network_monitoring_enabled=True
    )
    def no_reverse_dns(_address):
        raise socket.herror("No PTR record")

    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.socket.gethostbyaddr", no_reverse_dns
    )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="network",
            event_type="network_connection",
            severity="info",
            description="Connection metadata observed",
            attributes={
                "pid": 456,
                "remote_address": "203.0.113.10",
                "remote_port": 443,
                "protocol": "TCP",
                "state": "ESTABLISHED",
            },
        )
    )

    page.refresh_data()

    assert page.table.rows[0][:2] == ("—:—", "203.0.113.10")
    assert page.table.rows[0][3:] == (
        "443",
        "TCP",
        "Process ended",
        "ESTABLISHED",
    )
    assert "1 local records" in page.source_status.text_label.text()


def test_network_monitor_resolves_reverse_and_forward_dns_without_blocking(
    qtbot, window, monkeypatch
):
    page = window._pages["network-monitor"]
    window.services.settings = replace(
        window.services.settings, network_monitoring_enabled=True
    )
    address = "8.8.8.8"
    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.socket.gethostbyaddr",
        lambda _address: ("dns.google", (), [address]),
    )
    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (2, 1, 6, "", (address, 0))
        ],
    )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="network",
            event_type="network_connection",
            severity="info",
            description="Connection metadata observed",
            attributes={"remote_address": address, "remote_port": 443},
        )
    )

    page.refresh_data()

    qtbot.waitUntil(
        lambda: page.table.rows[0][2] == "dns.google (forward-confirmed)",
        timeout=5_000,
    )
    assert page.table.rows[0][1] == address


def test_network_monitor_supports_manual_forward_domain_lookup(
    qtbot, window, monkeypatch
):
    page = window._pages["network-monitor"]
    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.QInputDialog.getText",
        lambda *_args, **_kwargs: ("example.test", True),
    )
    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (2, 1, 6, "", ("192.0.2.10", 0)),
            (10, 1, 6, "", ("2001:db8::10", 0, 0, 0)),
        ],
    )
    dialogs = []
    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.QMessageBox.information",
        lambda _parent, title, text: dialogs.append((title, text)),
    )

    page._lookup_domain()
    qtbot.waitUntil(
        lambda: page.source_status.text_label.text()
        == "Domain lookup complete: example.test",
        timeout=5_000,
    )

    assert "192.0.2.10" in dialogs[0][1]
    assert "2001:db8::10" in dialogs[0][1]


def test_windows_log_level_filter_uses_collected_event_metadata(window):
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="windows-event-log:System",
            event_type="windows_event",
            severity="low",
            description="A warning record",
            attributes={"event_type": "warning", "event_id": 101},
        )
    )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="windows-event-log:Application",
            event_type="windows_event",
            severity="info",
            description="An informational record",
            attributes={"event_type": "info", "event_id": 102},
        )
    )
    page = window._pages["windows-logs"]

    page._refresh()
    assert len(page.table.rows) == 2

    page.windows_level.setCurrentIndex(page.windows_level.findData("warning"))

    assert len(page.table.rows) == 1
    assert page.table.rows[0][3] == "warning"
    assert "1 of 2" in page.source_status.text_label.text()


def test_threat_intelligence_page_matches_analyst_managed_local_iocs(window):
    repository = window.services.security_repository
    repository.add_threat_indicator("bad.example", "domain", "Incident note")
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="network",
            event_type="network_connection",
            severity="info",
            description="Connection to bad.example",
            attributes={"remote_address": "203.0.113.8"},
        )
    )
    page = window._pages["threat-intelligence"]

    page._refresh()

    assert page.table.rows[0][0:3] == (
        "bad.example",
        "domain",
        "Incident note",
    )
    assert page.table.rows[0][4] == "1 local event match(es)"
    assert "URLhaus feed not synchronized" in page.source_status.text_label.text()


def test_process_monitor_page_shows_live_process_snapshot(window, monkeypatch):
    page = window._pages["process-monitor"]
    window.services.settings = replace(
        window.services.settings, process_monitoring_enabled=True
    )
    monkeypatch.setattr(
        page._process_snapshot,
        "snapshot",
        lambda limit: [
            ProcessSnapshot(321, "example.exe", 12.5, 44 * 1024 * 1024, "local-user")
        ],
    )

    page.refresh_data()

    assert page.table.rows == (
        ("example.exe", "321", "local-user", "12.5%", "44.0 MB", "—"),
    )
    assert "risk not assessed" in page.source_status.text_label.text()


def test_file_integrity_page_creates_baseline_and_syncs_configuration(
    qtbot, window, tmp_path
):
    window.show()
    page = window._pages["file-integrity"]
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked_file = watched / "tracked.txt"
    tracked_file.write_text("baseline", encoding="utf-8")
    page.roots.setPlainText(str(watched))

    page.start_baseline()
    qtbot.waitUntil(lambda: page._baseline_worker is None, timeout=10_000)

    assert window.services.settings.file_integrity_roots == (str(watched),)
    assert len(page.table.rows) == 1
    assert page.table.rows[0][0] == str(tracked_file)
    assert page.table.rows[0][1] == "Baseline"
    assert page.table.rows[0][3] == "Unchanged"
    assert "1 baseline files" in page.status.text_label.text()

    window.services.event_pipeline.publish(
        SecurityEvent(
            source="file-integrity",
            event_type="file_changed",
            severity="medium",
            description="Tracked file changed",
            attributes={"path": str(tracked_file)},
        )
    )
    page.refresh_data()

    assert page.table.rows[0][1] == "File Changed"
    assert page.table.rows[0][3] == "Medium"
    window.navigate_to("settings")
    settings = window._pages["settings"]
    assert settings.file_integrity_roots.toPlainText() == str(watched)


def test_settings_create_baseline_button_starts_baseline(qtbot, window, tmp_path):
    settings_page = window._pages["settings"]
    watched = tmp_path / "baseline-from-settings"
    watched.mkdir()
    (watched / "tracked.txt").write_text("baseline", encoding="utf-8")
    settings_page.file_integrity_roots.setPlainText(str(watched))
    settings_page.file_integrity_exclusions.setPlainText("")

    settings_page.file_integrity_baseline_button.click()
    file_page = window._pages["file-integrity"]
    qtbot.waitUntil(lambda: file_page._baseline_worker is None, timeout=10_000)

    assert window.services.endpoint_service.has_file_baseline((str(watched),), ())
    assert "1 baseline files" in file_page.status.text_label.text()


def test_settings_save_persists_other_preferences_before_baseline_setup(
    qtbot, window, tmp_path, monkeypatch
):
    settings_page = window._pages["settings"]
    file_page = window._pages["file-integrity"]
    watched = tmp_path / "new-watched-folder"
    watched.mkdir()

    settings_page.log_level_combo.setCurrentText("DEBUG")
    settings_page.file_integrity_roots.setPlainText(str(watched))
    settings_page.file_integrity_monitoring.setChecked(True)
    monkeypatch.setattr(
        settings_page,
        "_warn_missing_baseline",
        settings_page._open_file_integrity_page,
    )

    settings_page._save()
    qtbot.waitUntil(
        lambda: window._pages["file-integrity"]._baseline_worker is None,
        timeout=10_000,
    )

    assert window.services.settings.log_level == "DEBUG"
    assert window.services.settings.file_integrity_roots == (str(watched),)
    assert window.services.settings.file_integrity_monitoring_enabled
    assert window.services.endpoint_service.has_file_baseline((str(watched),), ())
    assert file_page.roots.toPlainText() == str(watched)
    assert file_page.enabled.isChecked()


def test_empty_directory_baseline_is_shown_as_current(window, tmp_path):
    watched = tmp_path / "empty-watched-folder"
    watched.mkdir()
    roots = (str(watched),)
    window.services.save_settings(
        replace(window.services.settings, file_integrity_roots=roots)
    )
    window.services.endpoint_service.establish_file_baseline(roots)

    page = window._pages["file-integrity"]
    page.refresh_data()

    assert "0 baseline files" in page.status.text_label.text()
    assert "baseline needs refresh" not in page.status.text_label.text()


def test_dashboard_activity_columns_are_visible_and_aligned(qtbot, window):
    dashboard = window._pages["dashboard"]
    window.services.settings = replace(
        window.services.settings, process_monitoring_enabled=True
    )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="network",
            event_type="network_connection",
            severity="info",
            description="Connection metadata observed",
            attributes={
                "local_address": "192.168.1.20",
                "remote_address": "8.8.8.8",
                "remote_port": 443,
                "protocol": "TCP",
            },
        )
    )
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="process",
            event_type="process_started",
            severity="high",
            description="New process observed: example.exe",
            attributes={"process_name": "example.exe", "pid": 321},
        )
    )
    dashboard.refresh_security_data()
    window.show()
    qtbot.wait(30)

    for panel in (
        dashboard.network_activity,
        dashboard.process_activity,
        dashboard.feed,
    ):
        table = panel.table
        assert table.isVisible()
        assert table.horizontalScrollBar().maximum() == 0
        sections = [
            table.horizontalHeader().sectionViewportPosition(index)
            for index in range(table.columnCount())
        ]
        assert sections == sorted(sections)
        assert all(table.horizontalHeader().sectionSize(index) > 0 for index in range(table.columnCount()))
        assert all(
            table.horizontalHeader().sectionViewportPosition(index)
            + table.horizontalHeader().sectionSize(index)
            <= table.viewport().width()
            for index in range(table.columnCount())
        )
    assert [
        dashboard.network_activity.table.horizontalHeaderItem(index).text()
        for index in range(5)
    ] == ["Source", "Destination", "Port", "Protocol", "Risk"]
    assert [
        dashboard.process_activity.table.horizontalHeaderItem(index).text()
        for index in range(5)
    ] == ["Process", "PID", "CPU", "Memory", "Risk"]


def test_window_close_stops_dashboard_and_status_timers(window):
    dashboard = window._pages["dashboard"]
    dashboard.alert_chart.set_data(
        tuple((str(index), 1) for index in range(24)),
        tuple({"low": 1} for _ in range(24)),
    )
    window.show()
    assert dashboard._refresh_timer.isActive()
    assert window._status_timer.isActive()

    window.close()

    assert not dashboard._refresh_timer.isActive()
    assert not window._status_timer.isActive()


def test_window_can_resize_without_crashing(qtbot, window):
    window.show()

    window.resize(1040, 700)
    qtbot.wait(10)

    assert window.width() == 1040
    assert window.height() == 700


def test_dashboard_keeps_reference_column_composition_when_window_resizes(qtbot, window):
    dashboard = window._pages["dashboard"]
    grid = dashboard.layout().itemAt(1).layout()
    assert isinstance(grid, QGridLayout)

    for index, card in enumerate(dashboard.metric_cards):
        row, column, row_span, column_span = grid.getItemPosition(grid.indexOf(card))
        assert (row, column, row_span, column_span) == (0, index * 4, 1, 4)

    for width in (1040, 1440):
        window.resize(width, 700)
        qtbot.wait(10)
        row, column, row_span, column_span = grid.getItemPosition(
            grid.indexOf(dashboard.alert_chart)
        )
        assert (row, column, row_span, column_span) == (1, 0, 1, 8)


def test_dashboard_fits_window_width_without_horizontal_clipping(qtbot, window):
    window.show()
    qtbot.wait(20)

    assert window.scroll_area.horizontalScrollBar().maximum() == 0


def test_settings_page_persists_changes_and_updates_logging(window):
    window.navigate_to("settings")
    settings_page = window._pages["settings"]
    settings_page.log_level_combo.setCurrentText("ERROR")
    settings_page.retention_days.setValue(90)
    settings_page.save_button.click()

    assert window.services.settings.log_level == "ERROR"
    assert window.services.settings.log_retention_days == 90
    assert "updated" in settings_page.status.text_label.text()


def test_window_geometry_is_restored_after_application_restart(qtbot, tmp_path):
    paths = AppPaths(tmp_path / "local")
    first_run = MainWindow(ApplicationServices.create(paths))
    qtbot.addWidget(first_run)
    first_run.show()
    first_run.resize(1100, 740)
    qtbot.wait(10)
    first_run.close()
    saved_geometry = first_run.services.settings.window_geometry
    assert saved_geometry

    restarted = MainWindow(ApplicationServices.create(paths))
    qtbot.addWidget(restarted)

    assert restarted.services.settings.window_geometry == saved_geometry
    assert restarted.width() >= restarted.minimumWidth()
    assert restarted.minimumHeight() <= restarted.height() <= 740


def test_first_launch_model_download_consent_starts_background_preparation(
    qtbot, tmp_path, monkeypatch
):
    window = MainWindow(ApplicationServices.create(AppPaths(tmp_path / "local")))
    qtbot.addWidget(window)
    started = []
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        window,
        "_start_recognition_model_preparation",
        lambda: started.append(True),
    )

    window.prepare_recognition_model()

    assert window.services.settings.recognition_model_download_prompted
    assert window.services.settings.recognition_model_download_allowed
    assert started == [True]


def test_declining_startup_model_download_is_remembered(qtbot, tmp_path, monkeypatch):
    window = MainWindow(ApplicationServices.create(AppPaths(tmp_path / "local")))
    qtbot.addWidget(window)
    started = []
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.No,
    )
    monkeypatch.setattr(
        window,
        "_start_recognition_model_preparation",
        lambda: started.append(True),
    )

    window.prepare_recognition_model()
    window.prepare_recognition_model()

    assert window.services.settings.recognition_model_download_prompted
    assert not window.services.settings.recognition_model_download_allowed
    assert not started


def test_dashboard_monitoring_action_requests_app_camera_consent(
    qtbot, tmp_path, monkeypatch
):
    window = MainWindow(ApplicationServices.create(AppPaths(tmp_path / "local")))
    qtbot.addWidget(window)
    started = []
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        window.services.identity_service,
        "start_monitoring",
        lambda: started.append(True),
    )

    window._handle_page_action("toggle-monitoring")

    assert window.services.settings.camera_access_enabled
    assert window.services.settings.identity_monitoring_enabled
    assert started == [True]
    window.close()


def test_missing_file_integrity_baseline_does_not_crash_application_startup(
    qtbot, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    services.save_settings(
        replace(
            services.settings,
            file_integrity_monitoring_enabled=True,
        )
    )
    window = MainWindow(services)
    qtbot.addWidget(window)

    assert window.services.endpoint_service.workers == {}
    assert "Establish a file integrity baseline" in window.statusBar().currentMessage()

    window.close()
