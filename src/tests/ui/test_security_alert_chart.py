import pytest
from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QMouseEvent, QPixmap

from src.ui.components.security_alert_chart import SecurityAlertChart


def test_alert_chart_draws_24_hour_series_and_hover_details(qtbot):
    chart = SecurityAlertChart()
    qtbot.addWidget(chart)
    chart.resize(700, 240)
    chart.show()
    values = tuple((f"{index:02}:00", float(index % 7)) for index in range(24))
    severities = tuple(
        {"critical": 1, "high": 2, "medium": 3, "low": 4}
        for _ in range(24)
    )

    chart.set_data(values, severities)
    qtbot.wait(10)
    chart.plot.render(QPixmap(chart.plot.size()))
    local_position = QPoint(chart.plot.width() - 10, chart.plot.height() // 2)
    chart.plot.mouseMoveEvent(
        QMouseEvent(
            QEvent.Type.MouseMove,
            QPointF(local_position),
            QPointF(local_position),
            QPointF(chart.plot.mapToGlobal(local_position)),
            Qt.MouseButton.NoButton,
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
        )
    )

    assert chart._has_data
    assert chart.plot._hover_index == 23
    assert sum(chart.plot._percentages) == pytest.approx(100)
    assert max(chart.plot._percentages) <= 100


def test_alert_chart_uses_zero_percentages_for_an_empty_day(qtbot):
    chart = SecurityAlertChart()
    qtbot.addWidget(chart)

    chart.set_data(
        tuple((f"{index:02}:00", 0) for index in range(24)),
        tuple({"critical": 0, "high": 0, "medium": 0, "low": 0} for _ in range(24)),
    )

    assert chart.plot._percentages == (0.0,) * 24


def test_alert_chart_keeps_time_labels_and_severity_legend_in_separate_rows(qtbot):
    chart = SecurityAlertChart()
    qtbot.addWidget(chart)
    chart.resize(700, 240)
    chart.show()
    qtbot.wait(10)

    assert chart.plot.geometry().bottom() < chart.legend.geometry().top()
    assert set(chart.legend_items) == {"Critical", "High", "Medium", "Low"}


def test_alert_chart_shows_empty_state_without_fabricated_events(qtbot):
    chart = SecurityAlertChart()
    qtbot.addWidget(chart)

    chart.set_message("No local events.")

    assert not chart._has_data
    assert chart.plot._empty_message == "No local events."


def test_alert_chart_requires_a_full_day_of_hourly_data(qtbot):
    chart = SecurityAlertChart()
    qtbot.addWidget(chart)

    with pytest.raises(ValueError, match="24 hourly data points"):
        chart.set_data((("12 AM", 1),), ({"low": 1},))


def test_view_all_emits_navigation_request(qtbot):
    chart = SecurityAlertChart()
    qtbot.addWidget(chart)

    with qtbot.waitSignal(chart.viewAllRequested):
        chart.view_all_button.click()
