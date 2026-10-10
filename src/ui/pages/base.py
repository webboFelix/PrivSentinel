"""Shared layout for pages backed by local security records."""

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.ui.components.data_table import DataTable
from src.ui.components.status_indicator import StatusIndicator
from src.ui.navigation import PAGES_BY_KEY


class DataPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)

    page_key = ""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        definition = PAGES_BY_KEY[self.page_key]
        self.setObjectName(f"page-{definition.key}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(14)

        heading = QHBoxLayout()
        title_stack = QVBoxLayout()
        self.title_label = QLabel(definition.title)
        self.title_label.setObjectName("pageTitle")
        self.subtitle_label = QLabel(definition.description)
        self.subtitle_label.setObjectName("subtitle")
        self.subtitle_label.setWordWrap(True)
        title_stack.addWidget(self.title_label)
        title_stack.addWidget(self.subtitle_label)
        heading.addLayout(title_stack, 1)
        self.source_status = StatusIndicator("Waiting for a local data source")
        heading.addWidget(self.source_status)
        layout.addLayout(heading)

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._refresh)
        toolbar.addWidget(self.refresh_button)
        self.primary_button: QPushButton | None = None
        if definition.key in {"identity-protection", "reports", "investigations"}:
            action_label = {
                "identity-protection": "Enroll identity",
                "reports": "Create report",
                "investigations": "New investigation",
            }[definition.key]
            self.primary_button = QPushButton(action_label)
            self.primary_button.setObjectName("primaryButton")
            self.primary_button.clicked.connect(
                lambda: self.actionRequested.emit(definition.key)
            )
            toolbar.addWidget(self.primary_button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        if definition.columns:
            table_title = QLabel("Local records")
            table_title.setObjectName("sectionTitle")
            layout.addWidget(table_title)
            self.table = DataTable(definition.columns)
            self.table.state_view.retryRequested.connect(self._refresh)
            layout.addWidget(self.table, 1)
        else:
            self.table = None
        footer = QLabel(
            "No background monitoring is started by this screen. "
            "Data appears only after a real local integration is configured."
        )
        footer.setObjectName("muted")
        footer.setWordWrap(True)
        layout.addWidget(footer)

    def _refresh(self) -> None:
        if self.table is not None:
            self.table.show_error(
                "No local data provider is configured for this page."
            )
