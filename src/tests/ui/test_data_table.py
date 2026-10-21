import pytest
from PySide6.QtWidgets import QStackedWidget

from src.ui.components.data_table import DataTable


def test_table_filters_rows_case_insensitively(qtbot):
    table = DataTable(("Process", "Risk"))
    qtbot.addWidget(table)
    table.set_rows((("browser.exe", "Low"), ("powershell.exe", "High")))

    table.filter_input.setText("POWER")

    assert table.table.rowCount() == 1
    assert table.table.item(0, 0).text() == "powershell.exe"
    assert table.pages.currentWidget() is table.table


def test_table_displays_empty_no_match_and_error_states(qtbot):
    table = DataTable(("File",))
    qtbot.addWidget(table)
    states = table.findChild(QStackedWidget)
    assert states is not None
    assert states.currentWidget() is table.state_view

    table.set_rows((("report.txt",),))
    table.filter_input.setText("missing")
    assert table.state_view.title_label.text() == "No matching records"

    table.show_error("Provider unavailable")
    assert table.state_view.title_label.text() == "Unable to load records"
    assert "Provider unavailable" in table.state_view.message_label.text()


def test_table_rejects_malformed_rows(qtbot):
    table = DataTable(("Name", "Status"))
    qtbot.addWidget(table)

    with pytest.raises(ValueError, match="Expected 2 cells"):
        table.set_rows((("single-cell",),))


def test_table_selects_a_visible_record_by_id(qtbot):
    table = DataTable(("Process", "Risk"))
    qtbot.addWidget(table)
    table.set_rows(
        (("browser.exe", "Low"), ("powershell.exe", "High")),
        ("browser", "shell"),
    )
    table.filter_input.setText("browser")

    assert table.select_id("browser")
    assert table.selected_ids == ("browser",)
    assert not table.select_id("shell")
