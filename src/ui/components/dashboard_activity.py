"""Reference-style dashboard tables populated only from persisted local events."""

import ipaddress
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import ClassVar

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.endpoint.process_monitor import ProcessSnapshot
from src.ui.icon_assets import icon_path

EventRow = Mapping[str, object]


class _ActivityPanel(QFrame):
    viewAllRequested = Signal()

    def __init__(
        self,
        title: str,
        icon: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(5)
        heading = QHBoxLayout()
        heading.setSpacing(6)
        icon_label = QLabel()
        icon_label.setPixmap(QIcon(icon_path(icon)).pixmap(17, 17))
        heading.addWidget(icon_label)
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        heading.addWidget(title_label, 1)
        self.view_all_button = QPushButton("View All  →")
        self.view_all_button.setObjectName("activityViewAllButton")
        self.view_all_button.setStyleSheet("font-size: 8pt; padding: 2px 6px;")
        self.view_all_button.clicked.connect(self.viewAllRequested)
        heading.addWidget(self.view_all_button)
        layout.addLayout(heading)
        self.empty_label = QLabel("No local activity recorded.")
        self.empty_label.setObjectName("muted")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty_label, 1)

    def create_table(self, columns: Sequence[str]) -> QTableWidget:
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(list(columns))
        table.setObjectName("dashboardActivityTable")
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(24)
        table.horizontalHeader().setHighlightSections(False)
        table.setShowGrid(False)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        table.hide()
        return table

    def fill_table(self, table: QTableWidget, rows: Sequence[Sequence[str]]) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row_index, column_index, item)
        has_rows = bool(rows)
        table.setVisible(has_rows)
        self.empty_label.setVisible(not has_rows)

    def set_message(self, message: str) -> None:
        self.empty_label.setText(message)
        self.empty_label.show()
        for table in self.findChildren(QTableWidget):
            table.setRowCount(0)
            table.hide()


class DashboardNetworkPanel(_ActivityPanel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Network Activity", "network-nodes.png", parent)
        body = QHBoxLayout()
        body.setSpacing(5)
        summary = QGridLayout()
        summary.setContentsMargins(0, 0, 0, 0)
        summary.setHorizontalSpacing(4)
        summary.setVerticalSpacing(2)
        self.connection_count = self._summary_value(summary, 0, "Connections", "0")
        self.external_count = self._summary_value(summary, 1, "External", "0")
        self.suspicious_count = self._summary_value(summary, 2, "Suspicious", "0")
        self.blocked_count = self._summary_value(summary, 3, "Blocked", "0")
        body.addLayout(summary)
        self.table = self.create_table(("Source", "Destination", "Port", "Protocol", "Risk"))
        self._configure_columns((78, 86, 36, 42, 42))
        body.addWidget(self.table, 1)
        self.layout().addLayout(body, 1)
        self.empty_label.setText("No local connection events recorded.")

    @staticmethod
    def _summary_value(
        layout: QGridLayout, row: int, label: str, value: str
    ) -> QLabel:
        caption = QLabel(label)
        caption.setObjectName("caption")
        caption.setStyleSheet("font-size: 7pt;")
        result = QLabel(value)
        result.setObjectName("metricValue")
        result.setStyleSheet("font-size: 9pt; font-weight: 600;")
        layout.addWidget(caption, row, 0)
        layout.addWidget(result, row, 1)
        return result

    def _configure_columns(self, widths: Sequence[int]) -> None:
        header = self.table.horizontalHeader()
        for index, width in enumerate(widths):
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Fixed)
            self.table.setColumnWidth(index, width)
            if index >= 2:
                header.setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table.setStyleSheet("font-size: 8pt;")

    def set_events(self, events: Sequence[EventRow]) -> None:
        rows: list[tuple[str, ...]] = []
        external = suspicious = blocked = 0
        for event in events:
            attributes = event.get("attributes")
            attrs = attributes if isinstance(attributes, dict) else {}
            source = str(attrs.get("local_address") or "—")
            destination = str(attrs.get("remote_address") or "—")
            port = str(attrs.get("remote_port") or "—")
            protocol = str(attrs.get("protocol") or "—")
            severity = str(event.get("severity") or "info").title()
            try:
                external += int(ipaddress.ip_address(destination).is_global)
            except ValueError:
                pass
            suspicious += int(severity.casefold() in {"high", "critical"})
            blocked += int(str(attrs.get("state", "")).casefold() == "blocked")
            rows.append((source, destination, port, protocol, severity))
        self.connection_count.setText(str(len(events)))
        self.external_count.setText(str(external))
        self.suspicious_count.setText(str(suspicious))
        self.blocked_count.setText(str(blocked))
        self.fill_table(self.table, rows[:4])
        for row in range(self.table.rowCount()):
            for column in range(self.table.columnCount()):
                item = self.table.item(row, column)
                if item is not None:
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignLeft
                        if column < 2
                        else Qt.AlignmentFlag.AlignCenter
                    )
        self._color_risk_cells(self.table, 4)

    @staticmethod
    def _color_risk_cells(table: QTableWidget, column: int) -> None:
        colors = {
            "low": "#18d89b",
            "info": "#18d89b",
            "medium": "#f5ad32",
            "high": "#f5ad32",
            "critical": "#f04b67",
        }
        for row in range(table.rowCount()):
            item = table.item(row, column)
            if item is not None:
                color = colors.get(item.text().casefold())
                if color is not None:
                    item.setForeground(QColor(color))


class DashboardProcessPanel(_ActivityPanel):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Process Monitor", "processor.png", parent)
        self.table = self.create_table(("Process", "PID", "CPU", "Memory", "Risk"))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for index in range(1, 5):
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.ResizeToContents)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignmentFlag.AlignLeft)
        self.table.setStyleSheet("font-size: 8pt;")
        self.layout().addWidget(self.table, 1)
        self.empty_label.setText("No local process events recorded.")

    def set_processes(self, processes: Sequence[ProcessSnapshot]) -> None:
        rows = []
        for process in processes[:4]:
            cpu = f"{process.cpu_percent:.1f}%" if process.cpu_percent is not None else "—"
            memory = (
                f"{process.memory_bytes / (1024 * 1024):.1f} MB"
                if process.memory_bytes is not None
                else "—"
            )
            rows.append((process.name, str(process.pid), cpu, memory, "—"))
        self.fill_table(self.table, rows)
        for row in range(len(rows)):
            item = self.table.item(row, 0)
            if item is not None:
                item.setIcon(QIcon(icon_path("system-activity.png")))
        for row in range(self.table.rowCount()):
            for column in range(1, self.table.columnCount()):
                item = self.table.item(row, column)
                if item is not None:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setText("No readable local processes.")


class DashboardLiveFeed(_ActivityPanel):
    _FILTERS: ClassVar[tuple[str, ...]] = (
        "All",
        "Identity",
        "File",
        "Process",
        "Network",
        "Windows",
    )
    _SOURCES: ClassVar[dict[str, tuple[str, ...]]] = {
        "Identity": ("identity",),
        "File": ("file", "integrity"),
        "Process": ("process",),
        "Network": ("network",),
        "Windows": ("windows", "event-log"),
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Live Security Feed", "network-nodes.png", parent)
        self._events: tuple[EventRow, ...] = ()
        self._active_filter = "All"
        filters = QHBoxLayout()
        filters.setSpacing(5)
        self.filter_buttons: dict[str, QPushButton] = {}
        for name in self._FILTERS:
            button = QPushButton(name)
            button.setCheckable(True)
            button.setChecked(name == "All")
            button.setObjectName("feedFilterButton")
            button.setStyleSheet("font-size: 8pt; padding: 2px 9px;")
            button.clicked.connect(lambda _checked=False, name=name: self.set_filter(name))
            filters.addWidget(button)
            self.filter_buttons[name] = button
        self.layout().addLayout(filters)
        self.table = self.create_table(("Time", "Event", "Details", "Source"))
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.table.horizontalHeader().hide()
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(0, 82)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setIconSize(QSize(16, 16))
        self.layout().addWidget(self.table, 1)
        self.empty_label.setText("No local security events recorded.")

    def set_events(self, events: Sequence[EventRow]) -> None:
        self._events = tuple(events)
        self._render_events()

    def set_message(self, message: str) -> None:
        self._events = ()
        super().set_message(message)

    def set_filter(self, category: str) -> None:
        if category not in self._FILTERS:
            raise ValueError(f"Unknown dashboard security-feed filter: {category}")
        self._active_filter = category
        for name, button in self.filter_buttons.items():
            button.setChecked(name == category)
        self._render_events()

    def _render_events(self) -> None:
        tokens = self._SOURCES.get(self._active_filter, ())
        events = [
            event
            for event in self._events
            if not tokens
            or any(
                token in str(event.get("source", "")).casefold()
                for token in tokens
            )
        ]
        rows: list[tuple[str, str, str, str]] = []
        severities: list[str] = []
        for event in events[:4]:
            timestamp = str(event.get("occurred_at") or "")
            try:
                timestamp = datetime.fromisoformat(timestamp).astimezone().strftime("%H:%M:%S")
            except ValueError:
                timestamp = "—"
            event_name = str(event.get("event_type") or "event").replace("_", " ").title()
            details = str(event.get("description") or "—")
            source = str(event.get("source") or "local").replace("-", " ").title()
            rows.append((timestamp, event_name, details, source))
            severities.append(str(event.get("severity") or "info").casefold())
        self.fill_table(self.table, rows)
        icons = {
            "critical": "critical-alert.png",
            "high": "warning-alert.png",
            "medium": "info-alert.png",
            "low": "identity-verified.png",
            "info": "system-activity.png",
        }
        for row, severity in enumerate(severities):
            item = self.table.item(row, 0)
            if item is not None:
                item.setIcon(QIcon(icon_path(icons.get(severity, "system-activity.png"))))
        self.empty_label.setText(
            "No matching local events." if self._events else "No local security events recorded."
        )
