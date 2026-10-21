"""Compact live-feed view backed only by locally persisted events."""

from collections.abc import Mapping, Sequence
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QFrame, QLabel, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from src.ui.icon_assets import icon_path


class NotificationPanel(QFrame):
    def __init__(
        self,
        title: str = "Live security feed",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.setMinimumHeight(120)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 10, 13, 8)
        layout.setSpacing(6)
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading)
        self.message = QLabel("No local events to display.")
        self.message.setObjectName("muted")
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        self.events_list = QListWidget()
        self.events_list.setObjectName("securityFeed")
        self.events_list.setFrameShape(QFrame.Shape.NoFrame)
        self.events_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.events_list.setSpacing(2)
        self.events_list.hide()
        layout.addWidget(self.events_list, 1)

    def set_message(self, message: str) -> None:
        self.events_list.clear()
        self.events_list.hide()
        self.message.setText(message)
        self.message.show()

    def set_events(self, events: Sequence[Mapping[str, object]]) -> None:
        self.events_list.clear()
        if not events:
            self.message.setText("No locally recorded events.")
            self.message.show()
            self.events_list.hide()
            return

        icons = {
            "critical": "critical-alert.png",
            "high": "warning-alert.png",
            "medium": "info-alert.png",
            "low": "identity-verified.png",
        }
        for event in events:
            severity = str(event.get("severity", "info")).casefold()
            timestamp = str(event.get("occurred_at", ""))
            try:
                timestamp = datetime.fromisoformat(timestamp).astimezone().strftime("%H:%M:%S")
            except ValueError:
                timestamp = "—"
            category = str(event.get("event_type", "event")).replace("_", " ").title()
            description = str(event.get("description", ""))
            item = QListWidgetItem(
                QIcon(icon_path(icons.get(severity, "system-activity.png"))),
                f"{timestamp}   {category}   {description}",
            )
            item.setToolTip(
                f"{event.get('source', 'local')} · {severity.title()}\n"
                f"{description}\nRisk score: {event.get('risk_score', '—')}"
            )
            self.events_list.addItem(item)
        self.message.hide()
        self.events_list.show()
