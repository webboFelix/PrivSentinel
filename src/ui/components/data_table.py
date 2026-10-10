"""Filterable table with explicit loading, empty, and error states."""

from collections.abc import Sequence

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QLineEdit,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.ui.components.state_view import StateView


class DataTable(QFrame):
    def __init__(
        self,
        columns: Sequence[str],
        empty_message: str = "Records will appear here when a local data source is connected.",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self._columns = tuple(columns)
        self._rows: list[tuple[str, ...]] = []
        self._row_ids: tuple[str, ...] = ()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter this table…")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self._apply_filter)
        self.table = QTableWidget(0, len(self._columns))
        self.table.setHorizontalHeaderLabels(list(self._columns))
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setStretchLastSection(True)
        self.state_view = StateView()
        self.state_view.show_empty(message=empty_message)
        self.pages = QStackedWidget()
        self.pages.addWidget(self.table)
        self.pages.addWidget(self.state_view)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        layout.addWidget(self.filter_input)
        layout.addWidget(self.pages, 1)
        self.pages.setCurrentWidget(self.state_view)

    @property
    def rows(self) -> tuple[tuple[str, ...], ...]:
        return tuple(self._rows)

    def set_rows(
        self,
        rows: Sequence[Sequence[object]],
        row_ids: Sequence[str] | None = None,
    ) -> None:
        normalized: list[tuple[str, ...]] = []
        for row in rows:
            if len(row) != len(self._columns):
                raise ValueError(
                    f"Expected {len(self._columns)} cells per row, got {len(row)}."
                )
            normalized.append(tuple(str(value) for value in row))
        if row_ids is not None and len(row_ids) != len(normalized):
            raise ValueError("row_ids must contain one ID for each row.")
        self._rows = normalized
        self._row_ids = tuple(row_ids) if row_ids is not None else ()
        self._apply_filter(self.filter_input.text())

    @property
    def selected_ids(self) -> tuple[str, ...]:
        selected = {
            index.row() for index in self.table.selectionModel().selectedRows()
        }
        return tuple(
            self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            for row in sorted(selected)
            if self.table.item(row, 0) is not None
            and self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        )

    def show_loading(self, message: str = "Loading local records…") -> None:
        self.state_view.show_loading(message)
        self.pages.setCurrentWidget(self.state_view)

    def show_error(self, message: str) -> None:
        self.state_view.show_error(message)
        self.pages.setCurrentWidget(self.state_view)

    def _apply_filter(self, text: str) -> None:
        query = text.strip().casefold()
        visible_rows = [
            (index, row)
            for index, row in enumerate(self._rows)
            if not query or any(query in cell.casefold() for cell in row)
        ]
        self.table.setRowCount(len(visible_rows))
        for row_index, (source_index, row) in enumerate(visible_rows):
            for column_index, value in enumerate(row):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if column_index == 0 and self._row_ids:
                    item.setData(Qt.ItemDataRole.UserRole, self._row_ids[source_index])
                self.table.setItem(row_index, column_index, item)
        if visible_rows:
            self.pages.setCurrentWidget(self.table)
        else:
            message = (
                "No matching records. Try a different filter."
                if self._rows and query
                else None
            )
            self.state_view.show_empty(
                "No matching records" if message else "No records yet",
                message
                or "Records will appear here when a local data source is connected.",
            )
            self.pages.setCurrentWidget(self.state_view)