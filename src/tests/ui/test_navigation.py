import base64
import socket
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QCheckBox, QGridLayout, QLabel, QMessageBox

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.core.event_models import SecurityEvent
from src.endpoint.process_monitor import ProcessSnapshot
from src.storage.models import IdentityEvent
from src.ui.components.search_bar import SearchBar
from src.ui.main_window import MainWindow
from src.ui.navigation import PAGE_DEFINITIONS
from src.ui.pages.dashboard import DashboardPage, _ratio_percent


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


def test_global_search_includes_local_events_and_files(qtbot, monkeypatch, window):
    window.services.event_pipeline.publish(
        SecurityEvent(
            source="test-source",
            event_type="test_event",
            severity="low",
            description="needle event",
        )
    )
    with window.services.database.transaction() as connection:
        connection.execute(
            "INSERT INTO file_integrity_baselines "
            "(path, sha256, modified_ns, size, captured_at) VALUES (?, ?, ?, ?, ?)",
            ("C:\\needle.txt", "hash", 1, 10, "2026-10-21T00:00:00+00:00"),
        )

    captured = {}

    class SearchDialog:
        DialogCode = type("DialogCode", (), {"Accepted": 1})

        def __init__(self, query, pages, parent, records):
            captured["records"] = records
            self.selected_key = None

        def exec(self):
            return 0

    monkeypatch.setattr("src.ui.main_window.SearchResultsDialog", SearchDialog)
    window._search_pages("needle")

    assert any(
        "EVENT" in record[0] and "needle event" in record[0] for record in captured["records"]
    )
    assert any("FILE" in record[0] and "needle.txt" in record[0] for record in captured["records"])


def test_topbar_and_sidebar_show_unreviewed_alert_count(window, monkeypatch):
    with window.services.database.transaction() as connection:
        for index, status in enumerate(("open", "investigating", "resolved")):
            event_id = f"event-{index}"
            connection.execute(
                "INSERT INTO security_events "
                "(id, occurred_at, source, event_type, severity, description, observed, "
                "attributes_json, correlation_id, risk_score) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    "2026-10-21T00:00:00+00:00",
                    "test",
                    "alert_test",
                    "high",
                    "test alert",
                    1,
                    "{}",
                    None,
                    1.0,
                ),
            )
            connection.execute(
                "INSERT INTO alerts "
                "(id, event_id, rule_id, dedupe_key, title, severity, rationale, status, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"alert-{index}",
                    event_id,
                    "test-rule",
                    f"key-{index}",
                    "Test alert",
                    "high",
                    "test",
                    status,
                    "2026-10-21T00:00:00+00:00",
                    "2026-10-21T00:00:00+00:00",
                ),
            )
    window.services.event_pipeline.bus.publish(
        SecurityEvent(
            source="test-source",
            event_type="alert_refresh",
            severity="low",
            description="Refresh alert badges",
        )
    )

    assert window.topbar.alert_count.text() == "1"
    assert not window.topbar.alert_count.isHidden()
    for badge in window.sidebar._alert_badges.values():
        assert badge.text() == "1"
        assert not badge.isHidden()

    window.topbar.set_alert_count(123)
    window.sidebar.set_alert_count(123)
    assert window.topbar.alert_count.text() == "123"
    assert all(badge.text() == "123" for badge in window.sidebar._alert_badges.values())
    window._update_alert_count()

    alerts_page = window._pages["alerts"]
    alerts_page._refresh()
    assert alerts_page.table.select_id("alert-0")
    monkeypatch.setattr(
        "src.ui.pages.base.QMessageBox.information",
        lambda *args: None,
    )
    alerts_page._show_alert_details()

    assert window.topbar.alert_count.isHidden()
    assert all(badge.isHidden() for badge in window.sidebar._alert_badges.values())
    assert (
        next(
            alert
            for alert in window.services.security_repository.list_alerts(limit=10)
            if alert["id"] == "alert-0"
        )["status"]
        == "acknowledged"
    )


def test_lock_warning_cannot_be_cancelled_and_closes_when_identity_is_verified(window):
    window.show()
    window.services.identity_service.current_state = "unknown_face"
    window.services.settings = replace(
        window.services.settings,
        automatic_lock_enabled=True,
        unknown_face_action="lock_after_grace",
    )

    window._warn_before_lock(30)
    warning = window._lock_warning_box
    window._warn_before_lock(30)

    assert warning is not None
    assert window._lock_warning_box is warning
    assert warning.standardButtons() == QMessageBox.StandardButton.NoButton
    assert window._lock_timer.isActive()
    warning.reject()
    warning.close()
    assert warning.isVisible()

    window._on_identity_state_changed("recognized", "Enrolled identity recognized.")

    assert window._lock_warning_box is None
    assert not window._lock_timer.isActive()
    assert not warning.isVisible()


def test_no_face_warning_uses_grace_period_and_camera_failure_dismisses(window):
    window.show()
    window.services.settings = replace(
        window.services.settings,
        automatic_lock_enabled=True,
        presence_loss_action="lock_after_grace",
    )
    window.services.identity_service.current_state = "no_face_detected"

    window._warn_before_lock(30)
    warning = window._lock_warning_box

    assert warning is not None
    assert "No face was detected" in warning.text()
    assert window._lock_timer.isActive()

    window._on_identity_state_changed("camera_unavailable", "Camera disconnected.")

    assert window._lock_warning_box is None
    assert not window._lock_timer.isActive()
    assert not warning.isVisible()


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
    assert dashboard.identity_verification_card.state_label.text() == "NOT ENROLLED"
    assert dashboard.identity_verification_card.live_badge.text() == "● OFFLINE"
    assert dashboard.score_summary.ring._score is None
    assert dashboard.score_summary.risk_label.text() == "NO DATA · IDENTITY / FILES"
    assert dashboard.score_summary.factor_progress["Identity"].value() == 0
    assert dashboard.score_summary.factor_values["Identity"].text() == "N/A"
    assert dashboard.threat_summary.count_label.text() == "0"
    assert dashboard.files_summary.count_label.text() == "0"

    photo = QImage(32, 32, QImage.Format.Format_RGB32)
    photo.fill(0x336699)
    photo_data = QByteArray()
    photo_buffer = QBuffer(photo_data)
    assert photo_buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    assert photo.save(photo_buffer, "PNG")
    photo_buffer.close()
    profile_image = base64.b64encode(photo_data.data()).decode("ascii")

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
        profile_image,
    )
    assert dashboard.identity_summary.state_label.text() == "VERIFIED"
    assert dashboard.identity_summary.confidence_label.text() == "Confidence"
    assert dashboard.identity_summary.confidence_value_label.text() == "98.7%"
    assert dashboard.identity_summary.last_verified_label.text() == "Last verified"
    assert dashboard.identity_summary.last_verified_value_label.text() == "0 seconds ago"
    assert dashboard.identity_verification_card.state_label.text() == "VERIFIED"
    assert dashboard.identity_verification_card.confidence_label.text() == "98.7%"
    assert dashboard.identity_verification_card.last_seen_label.text() == "Last seen  0 seconds ago"
    assert dashboard.identity_verification_card.face_status.text().endswith("Face detected")
    assert dashboard.identity_verification_card.match_status.text().endswith("Identity matched")
    assert dashboard.identity_verification_card.motion_status.isHidden()
    assert not dashboard.identity_summary.avatar.pixmap().isNull()
    assert not dashboard.identity_verification_card.avatar.pixmap().isNull()

    pending_motion = IdentityEvent(
        "pending-motion",
        datetime.now(UTC),
        "liveness_failure",
        "liveness_failure",
        0.987,
        "awaiting_basic_motion",
        "Basic facial movement was not observed in this short sample.",
    )
    dashboard.identity_summary.set_identity(
        "Local user",
        "liveness_failure",
        pending_motion,
        profile_image,
    )
    dashboard.identity_verification_card.set_identity(
        "Local user",
        False,
        "liveness_failure",
        pending_motion,
        profile_image,
    )
    assert dashboard.identity_summary.state_label.text() == "VERIFIED"
    assert dashboard.identity_verification_card.name_label.text() == "Local user"
    assert dashboard.identity_verification_card.state_label.text() == "VERIFIED"
    assert dashboard.identity_verification_card.motion_status.isHidden()

    dashboard.identity_verification_card.history_button.click()
    assert window.current_page_key == "verification-history"

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
            "Processes": (50, "75/150 processes", True),
            "Network": (60, "3/5 remote", True),
            "Windows": (None, "No successful channel read", False),
        }
    )

    assert score_card.ring._score == 86
    assert score_card.risk_label.text() == "HEALTHY · MAINTAIN PROTECTION"
    assert {name: progress.value() for name, progress in score_card.factor_progress.items()} == {
        "Identity": 80,
        "Files": 92,
        "Processes": 50,
        "Network": 60,
        "Windows": 0,
    }
    assert {name: label.text() for name, label in score_card.factor_values.items()} == {
        "Identity": "80%",
        "Files": "92%",
        "Processes": "Active",
        "Network": "Active",
        "Windows": "Inactive",
    }
    assert score_card.factor_progress["Processes"].isHidden()
    assert score_card.factor_indicators["Processes"].text() == "●"
    assert score_card.factor_values["Windows"].styleSheet().find("#f04b67") >= 0
    assert score_card.factor_stats["Processes"].text() == "75/150 processes"

    score_card.set_factors(
        {
            "Identity": (80, "4/5 samples"),
            "Files": (92, "23/25 files"),
            "Processes": (50, "75/150 processes", False),
            "Network": (60, "3/5 remote", True),
            "Windows": (40, "1/2 channels", True),
        }
    )
    assert score_card.ring._score == 86
    assert score_card.risk_label.text() == "HEALTHY · MAINTAIN PROTECTION"
    assert score_card.ring._color.name() == "#18d89b"
    assert {name: label.text() for name, label in score_card.factor_values.items()} == {
        "Identity": "80%",
        "Files": "92%",
        "Processes": "Inactive",
        "Network": "Active",
        "Windows": "Active",
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


def test_dashboard_activity_tables_use_network_events_and_live_process_metrics(window, monkeypatch):
    dashboard = window._pages["dashboard"]
    window.services.settings = replace(window.services.settings, process_monitoring_enabled=True)
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
        lambda limit: [ProcessSnapshot(321, "example.exe", 12.5, 44 * 1024 * 1024)],
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
    window.services.settings = replace(window.services.settings, network_monitoring_enabled=True)

    def no_reverse_dns(_address):
        raise socket.herror("No PTR record")

    monkeypatch.setattr("src.ui.pages.endpoint_data.socket.gethostbyaddr", no_reverse_dns)
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
    window.services.settings = replace(window.services.settings, network_monitoring_enabled=True)
    address = "8.8.8.8"
    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.socket.gethostbyaddr",
        lambda _address: ("dns.google", (), [address]),
    )
    monkeypatch.setattr(
        "src.ui.pages.endpoint_data.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", (address, 0))],
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


def test_network_monitor_supports_manual_forward_domain_lookup(qtbot, window, monkeypatch):
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
        lambda: page.source_status.text_label.text() == "Domain lookup complete: example.test",
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
    window.services.settings = replace(window.services.settings, process_monitoring_enabled=True)
    monkeypatch.setattr(
        page._process_snapshot,
        "snapshot",
        lambda limit: [ProcessSnapshot(321, "example.exe", 12.5, 44 * 1024 * 1024, "local-user")],
    )

    page.refresh_data()

    assert page.table.rows == (("example.exe", "321", "local-user", "12.5%", "44.0 MB", "—"),)
    assert "risk not assessed" in page.source_status.text_label.text()


def test_file_integrity_page_creates_baseline_and_syncs_configuration(qtbot, window, tmp_path):
    window.show()
    page = window._pages["file-integrity"]
    watched = tmp_path / "watched"
    watched.mkdir()
    tracked_file = (watched / "tracked.txt").resolve()
    tracked_file.write_text("baseline", encoding="utf-8")
    page.roots.setPlainText(str(watched))

    page.start_baseline()
    qtbot.waitUntil(lambda: page._baseline_worker is None, timeout=10_000)

    assert window.services.settings.file_integrity_roots == (str(watched),)
    assert page.table.rows == ()
    assert "Trusted baseline created" in page.status.text_label.text()
    assert str(window.services.paths.database_file) in page.status.text_label.text()

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

    assert page.table.rows[0][1].splitlines()[0] == "tracked.txt"
    assert page.table.rows[0][2] == "Modified"
    assert page.table.rows[0][3] == "Review Required"
    window.navigate_to("settings")
    settings = window._pages["settings"]
    assert settings.file_integrity_roots.toPlainText() == str(watched)


def test_file_integrity_reference_dashboard_tabs_and_auto_update_setting(qtbot, window, tmp_path):
    page = window._pages["file-integrity"]

    assert [page.tabs.tabText(index) for index in range(page.tabs.count())] == [
        "Overview",
        "Event History",
        "Baseline",
        "Settings",
    ]
    assert page.tabs.currentIndex() == 2
    assert page.tab_pages.currentIndex() == 0
    assert page.minimumSizeHint().width() <= 906

    watched = tmp_path / "watched"
    watched.mkdir()
    page.roots.setPlainText(str(watched))
    page._save_configuration()
    folder_row = page.settings_folder_layout.itemAt(0).widget()
    folder_option = folder_row.findChild(QCheckBox)
    assert isinstance(folder_option, QCheckBox)
    assert folder_option.isChecked()
    folder_option.setChecked(False)
    assert window.services.settings.file_integrity_roots == ()

    page.view_all_events_button.click()
    assert page.tabs.currentIndex() == 1
    assert page.tab_pages.currentIndex() == 1

    page.automatic_updates.setChecked(False)
    assert window.services.settings.file_integrity_auto_update_enabled is False
    assert not page.update_frequency.isEnabled()
    page.automatic_updates.setChecked(True)
    assert window.services.settings.file_integrity_auto_update_enabled is True
    assert page.update_frequency.isEnabled()


def test_file_integrity_baseline_is_created_once_across_app_launches(qtbot, tmp_path):
    paths = AppPaths(tmp_path / "local")
    watched = tmp_path / "watched-on-launch"
    watched.mkdir()
    tracked = watched / "tracked.txt"
    tracked.write_text("trusted at first launch", encoding="utf-8")
    services = ApplicationServices.create(paths)
    roots = (str(watched),)
    services.save_settings(
        replace(
            services.settings,
            file_integrity_roots=roots,
            file_integrity_monitoring_enabled=True,
        )
    )
    first_window = MainWindow(services)
    qtbot.addWidget(first_window)
    first_page = first_window._pages["file-integrity"]
    qtbot.waitUntil(lambda: first_page._baseline_worker is None, timeout=10_000)
    assert str(services.paths.database_file) in first_window.statusBar().currentMessage()
    assert first_window.file_integrity_progress.isHidden()
    trusted_hash = services.database.fetchone(
        "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
        (str(tracked.resolve()),),
    )["sha256"]
    assert services.endpoint_service.has_file_baseline(roots)
    first_window.close()

    tracked.write_text("changed after baseline", encoding="utf-8")
    restarted_services = ApplicationServices.create(paths)
    restarted_window = MainWindow(restarted_services)
    qtbot.addWidget(restarted_window)
    restarted_page = restarted_window._pages["file-integrity"]
    assert restarted_page._baseline_worker is None
    assert (
        restarted_services.database.fetchone(
            "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
            (str(tracked.resolve()),),
        )["sha256"]
        == trusted_hash
    )
    restarted_window.close()


def test_file_integrity_page_surfaces_baseline_creation_failure(qtbot, window, tmp_path):
    page = window._pages["file-integrity"]
    missing = tmp_path / "missing-baseline-root"
    page.roots.setPlainText(str(missing))

    page.start_baseline()
    qtbot.waitUntil(lambda: page._baseline_worker is None, timeout=10_000)

    assert page.status.text_label.text().startswith("Baseline failed:")
    assert "root is unavailable" in page.status.text_label.text()
    assert page.baseline_button.isEnabled()


def test_settings_create_baseline_button_starts_baseline(qtbot, window, tmp_path):
    settings_page = window._pages["settings"]
    file_page = window._pages["file-integrity"]
    progress_updates = []
    file_page.baselineProgressChanged.connect(
        lambda processed, total: progress_updates.append((processed, total))
    )
    watched = tmp_path / "baseline-from-settings"
    watched.mkdir()
    (watched / "tracked.txt").write_text("baseline", encoding="utf-8")
    settings_page.file_integrity_roots.setPlainText(str(watched))
    settings_page.file_integrity_exclusions.setPlainText("")

    settings_page.file_integrity_baseline_button.click()
    file_page = window._pages["file-integrity"]
    qtbot.waitUntil(lambda: file_page._baseline_worker is None, timeout=10_000)

    assert window.services.endpoint_service.has_file_baseline((str(watched),), ())
    assert "Trusted baseline created" in file_page.status.text_label.text()
    assert str(window.services.paths.database_file) in file_page.status.text_label.text()
    assert (-1, -1) in progress_updates
    assert (0, 1) in progress_updates
    assert (1, 1) in progress_updates
    assert not settings_page.file_integrity_monitoring.isChecked()
    assert window.file_integrity_progress.isHidden()
    assert str(window.services.paths.database_file) in window.statusBar().currentMessage()


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
    assert "monitoring enabled" in settings_page.status.text_label.text()
    assert str(window.services.paths.database_file) in settings_page.status.text_label.text()


def test_settings_reports_baseline_failure_and_keeps_monitoring_disabled(
    qtbot, window, tmp_path, monkeypatch
):
    settings_page = window._pages["settings"]
    missing = tmp_path / "missing-file-integrity-root"
    settings_page.file_integrity_roots.setPlainText(str(missing))
    settings_page.file_integrity_monitoring.setChecked(True)
    monkeypatch.setattr(
        settings_page,
        "_warn_missing_baseline",
        settings_page._open_file_integrity_page,
    )

    settings_page._save()
    file_page = window._pages["file-integrity"]
    qtbot.waitUntil(lambda: file_page._baseline_worker is None, timeout=10_000)

    assert not window.services.settings.file_integrity_monitoring_enabled
    assert not settings_page.file_integrity_monitoring.isChecked()
    assert "Could not enable file-integrity monitoring" in settings_page.status.text_label.text()
    assert "root is unavailable" in settings_page.status.text_label.text()


def test_empty_directory_baseline_is_shown_as_current(window, tmp_path):
    watched = tmp_path / "empty-watched-folder"
    watched.mkdir()
    roots = (str(watched),)
    window.services.save_settings(replace(window.services.settings, file_integrity_roots=roots))
    window.services.endpoint_service.establish_file_baseline(roots)

    page = window._pages["file-integrity"]
    page.refresh_data()

    assert "0 baseline files" in page.status.text_label.text()
    assert "baseline needs refresh" not in page.status.text_label.text()


def test_dashboard_activity_columns_are_visible_and_aligned(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(
        DashboardPage,
        "refresh_host_topology",
        lambda _page: None,
    )
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    window = MainWindow(services)
    qtbot.addWidget(window)
    dashboard = window._pages["dashboard"]
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
    dashboard.process_activity.set_processes(
        (ProcessSnapshot(321, "example.exe", 12.5, 44 * 1024 * 1024, "local-user"),)
    )
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
        assert all(
            table.horizontalHeader().sectionSize(index) > 0 for index in range(table.columnCount())
        )
        assert all(
            table.horizontalHeader().sectionViewportPosition(index)
            + table.horizontalHeader().sectionSize(index)
            <= table.viewport().width()
            for index in range(table.columnCount())
        )
    assert [
        dashboard.network_activity.table.horizontalHeaderItem(index).text() for index in range(5)
    ] == ["Source", "Destination", "Port", "Protocol", "Risk"]
    window.close()
    assert [
        dashboard.process_activity.table.horizontalHeaderItem(index).text() for index in range(5)
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

    collector_layout = dashboard.collector_status.layout()
    assert isinstance(collector_layout, QGridLayout)
    for index, card in enumerate(
        (
            dashboard.camera_card,
            dashboard.process_card,
            dashboard.windows_card,
            dashboard.voice_card,
        )
    ):
        row, column, row_span, column_span = collector_layout.getItemPosition(
            collector_layout.indexOf(card)
        )
        assert (row, column, row_span, column_span) == (
            index // 2,
            index % 2,
            1,
            1,
        )
        assert card.findChild(QLabel, "cardBody").wordWrap()

    for index, card in enumerate(dashboard.metric_cards):
        row, column, row_span, column_span = grid.getItemPosition(grid.indexOf(card))
        assert (row, column, row_span, column_span) == (0, index * 4, 1, 4)

    assert [grid.rowStretch(row) for row in (1, 2, 3)] == [5, 3, 2]

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


def test_dashboard_monitoring_action_requests_app_camera_consent(qtbot, tmp_path, monkeypatch):
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


def test_missing_file_integrity_baseline_does_not_crash_application_startup(qtbot, tmp_path):
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
