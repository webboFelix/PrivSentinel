from PySide6.QtOpenGLWidgets import QOpenGLWidget

from src.ui.components.chart_widget import ChartWidget


def test_chart_widget_uses_open_gl_and_shows_truthful_empty_state(qtbot):
    chart = ChartWidget("Security Alerts", "No local alerts recorded.")
    qtbot.addWidget(chart)

    assert isinstance(chart.view, QOpenGLWidget)
    assert not chart._has_data
    assert not chart._rotation_timer.isActive()
    assert chart.empty_label.text() == "No local alerts recorded."


def test_three_dimensional_pie_renders_only_supplied_values(qtbot):
    chart = ChartWidget("Severity", "No alerts.", mode="pie")
    qtbot.addWidget(chart)
    chart.set_data((("Critical", 2), ("High", 1), ("Low", 0)))
    chart.show()
    qtbot.wait(80)

    assert chart._has_data
    assert chart.empty_label.isHidden()
    assert len(chart._items) > 1


def test_empty_chart_clears_previous_data_and_updates_message(qtbot):
    chart = ChartWidget("Activity", "No events.", mode="bar")
    qtbot.addWidget(chart)
    chart.set_data((("12:00", 3), ("13:00", 2)))
    chart.show()
    qtbot.wait(80)
    assert chart._has_data

    chart.set_message("Collector unavailable.")

    assert not chart._has_data
    assert not chart._rotation_timer.isActive()
    assert chart.empty_label.text() == "Collector unavailable."
    assert len(chart._items) == 1


def test_network_chart_uses_real_series_and_rotates_while_visible(qtbot):
    chart = ChartWidget("Threat Landscape", "No events.", mode="network")
    qtbot.addWidget(chart)
    chart.set_data((("critical", 2), ("medium", 1)))
    chart.show()
    initial_azimuth = chart._azimuth

    qtbot.wait(140)

    assert chart._has_data
    assert len(chart._items) > 1
    assert chart._azimuth > initial_azimuth
