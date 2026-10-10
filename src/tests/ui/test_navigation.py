import pytest
from PySide6.QtCore import Qt

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.core.event_models import SecurityEvent
from src.ui.components.search_bar import SearchBar
from src.ui.main_window import MainWindow
from src.ui.navigation import PAGE_DEFINITIONS


@pytest.fixture
def window(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    main_window = MainWindow(services)
    qtbot.addWidget(main_window)
    return main_window


def test_all_pages_are_registered_and_navigation_updates_active_page(window):
    window.show()

    assert len(window.page_keys) == 14
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
    assert dashboard.integrity_chart._has_data
    assert dashboard.feed.events_list.count() == 1
    assert "Tracked file changed" in dashboard.feed.events_list.item(0).text()


def test_window_close_stops_chart_and_status_timers(window):
    dashboard = window._pages["dashboard"]
    dashboard.alert_chart.set_data((("event", 1),))
    window.show()
    assert dashboard.alert_chart._rotation_timer.isActive()
    assert window._status_timer.isActive()

    window.close()

    assert not dashboard.alert_chart._rotation_timer.isActive()
    assert not window._status_timer.isActive()


def test_window_can_resize_without_crashing(qtbot, window):
    window.show()

    window.resize(1040, 700)
    qtbot.wait(10)

    assert window.width() == 1040
    assert window.height() == 700


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
