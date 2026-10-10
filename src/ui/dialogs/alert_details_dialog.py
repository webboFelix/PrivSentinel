"""Read-only dialog for locally available alert details."""

from collections.abc import Mapping

from PySide6.QtWidgets import QDialog, QLabel, QPushButton, QVBoxLayout, QWidget


class AlertDetailsDialog(QDialog):
    def __init__(
        self,
        details: Mapping[str, object],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Alert details")
        self.resize(440, 300)
        layout = QVBoxLayout(self)
        heading = QLabel("Alert details")
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading)
        for name, value in details.items():
            label = QLabel(f"{name}: {value}")
            label.setWordWrap(True)
            layout.addWidget(label)
        if not details:
            empty = QLabel("No alert record was provided.")
            empty.setObjectName("muted")
            layout.addWidget(empty)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        layout.addWidget(close)