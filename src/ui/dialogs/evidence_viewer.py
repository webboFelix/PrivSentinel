"""Read-only text viewer for an evidence item supplied by a caller."""

from PySide6.QtWidgets import QDialog, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget


class EvidenceViewer(QDialog):
    def __init__(
        self, title: str, content: str, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(680, 460)
        layout = QVBoxLayout(self)
        label = QLabel(title)
        label.setObjectName("sectionTitle")
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setPlainText(content)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        layout.addWidget(label)
        layout.addWidget(viewer, 1)
        layout.addWidget(close)