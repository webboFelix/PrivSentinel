"""Small status label used for local integration and privacy states."""

from typing import ClassVar

from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from src.ui.styles import colors


class StatusIndicator(QWidget):
    _COLORS: ClassVar[dict[str, str]] = {
        "info": colors.ACCENT,
        "success": colors.SUCCESS,
        "warning": colors.WARNING,
        "error": colors.DANGER,
    }

    def __init__(
        self, text: str, state: str = "info", parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(7)
        dot = QLabel("●")
        self._dot = dot
        self.set_state(state)
        self.text_label = QLabel(text)
        self.text_label.setObjectName("muted")
        layout.addWidget(dot)
        layout.addWidget(self.text_label)

    def set_text(self, text: str) -> None:
        self.text_label.setText(text)

    def set_state(self, state: str) -> None:
        self._dot.setStyleSheet(
            f"color: {self._COLORS.get(state, colors.ACCENT)};"
        )