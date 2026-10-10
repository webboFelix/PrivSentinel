"""Filterable local identity verification history."""

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.ui.components.data_table import DataTable


class VerificationHistoryPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)

    def __init__(
        self, services: ApplicationServices, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.services = services
        self.setObjectName("page-verification-history")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(14)
        title = QLabel("Verification History")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Local verification metadata only; raw camera frames are never included."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        controls = QHBoxLayout()
        self.state_filter = QComboBox()
        self.state_filter.addItems(
            [
                "All states",
                "recognized",
                "unknown_face",
                "low_confidence",
                "multiple_faces",
                "no_face_detected",
                "camera_unavailable",
                "verification_failure",
                "liveness_failure",
                "enrolled",
            ]
        )
        self.state_filter.currentIndexChanged.connect(self._refresh)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._refresh)
        self.delete_button = QPushButton("Delete selected")
        self.delete_button.clicked.connect(self._delete_selected)
        self.retention_button = QPushButton("Apply retention now")
        self.retention_button.clicked.connect(self._apply_retention)
        controls.addWidget(QLabel("State"))
        controls.addWidget(self.state_filter)
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.delete_button)
        controls.addWidget(self.retention_button)
        controls.addStretch(1)
        layout.addLayout(controls)
        self.table = DataTable(
            ("Time", "Result", "Confidence", "Liveness", "Duration", "Details")
        )
        self.table.filter_input.setPlaceholderText("Search verification history…")
        self.table.filter_input.textChanged.connect(self._refresh)
        layout.addWidget(self.table, 1)
        self._refresh()

    def _refresh(self, *_args) -> None:
        selected = self.state_filter.currentText()
        state = "" if selected == "All states" else selected
        try:
            events = self.services.identity_service.recent_events(
                query=self.table.filter_input.text(),
                state=state,
            )
        except Exception as exc:
            self.table.show_error(f"Could not load verification history: {exc}")
            return
        rows = [
            (
                event.occurred_at.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
                event.state.replace("_", " ").title(),
                f"{event.confidence:.1%}" if event.confidence is not None else "—",
                event.liveness.replace("_", " ").title(),
                f"{event.monitoring_seconds:.0f}s",
                event.detail,
            )
            for event in events
        ]
        self.table.set_rows(rows, [event.id for event in events])

    def _delete_selected(self) -> None:
        selected = list(self.table.selected_ids)
        if not selected:
            QMessageBox.information(
                self, "Verification history", "Select one or more event rows first."
            )
            return
        confirmation = QMessageBox.question(
            self,
            "Delete verification history",
            f"Delete {len(selected)} selected event(s)? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return
        try:
            self.services.identity_service.delete_events(selected)
        except Exception as exc:
            QMessageBox.critical(self, "Could not delete events", str(exc))
            return
        self._refresh()

    def _apply_retention(self) -> None:
        try:
            removed = self.services.identity_service.prune_events()
        except Exception as exc:
            QMessageBox.critical(self, "Could not apply retention", str(exc))
            return
        QMessageBox.information(
            self,
            "Retention applied",
            f"Removed {removed} event(s) older than the configured retention period.",
        )
        self._refresh()
