"""Informational dialog for actions without a configured backend."""

from PySide6.QtWidgets import QDialog, QLabel, QPushButton, QVBoxLayout, QWidget


class NoticeDialog(QDialog):
    def __init__(
        self,
        title: str,
        message: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(380)
        layout = QVBoxLayout(self)
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        body = QLabel(message)
        body.setObjectName("muted")
        body.setWordWrap(True)
        close = QPushButton("Close")
        close.setObjectName("primaryButton")
        close.clicked.connect(self.accept)
        layout.addWidget(heading)
        layout.addWidget(body)
        layout.addWidget(close)
