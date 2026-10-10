"""Empty, loading, and error states shared by data-driven pages."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget


class StateView(QWidget):
    retryRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(150)
        self.setObjectName("stateView")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addStretch(1)
        self.title_label = QLabel()
        self.title_label.setObjectName("sectionTitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message_label = QLabel()
        self.message_label.setObjectName("muted")
        self.message_label.setWordWrap(True)
        self.message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.retry_button = QPushButton("Try again")
        self.retry_button.setObjectName("primaryButton")
        self.retry_button.clicked.connect(self.retryRequested)
        layout.addWidget(self.title_label)
        layout.addWidget(self.message_label)
        layout.addWidget(self.retry_button, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)
        self.show_empty()

    def show_empty(
        self,
        title: str = "No records yet",
        message: str = "Records will appear here when a local data source is connected.",
    ) -> None:
        self.title_label.setText(title)
        self.message_label.setText(message)
        self.retry_button.hide()

    def show_loading(self, message: str = "Loading local records…") -> None:
        self.title_label.setText("Loading")
        self.message_label.setText(message)
        self.retry_button.hide()

    def show_error(self, message: str) -> None:
        self.title_label.setText("Unable to load records")
        self.message_label.setText(message)
        self.retry_button.show()
