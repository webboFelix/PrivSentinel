"""Compact metric card for dashboard summaries."""

from PySide6.QtCore import QEasingCurve, QVariantAnimation
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from src.ui.icon_assets import icon_path


class MetricCard(QFrame):
    def __init__(
        self,
        title: str,
        value: str,
        description: str,
        accent: str = "#00b9e8",
        parent: QWidget | None = None,
        icon: str = "system-activity.png",
    ) -> None:
        super().__init__(parent)
        self.setObjectName("metricCard")
        self.setMinimumHeight(102)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 10, 13, 10)
        layout.setSpacing(4)
        header = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(QIcon(icon_path(icon)).pixmap(18, 18))
        header.addWidget(icon_label)
        title_label = QLabel(title.upper())
        title_label.setObjectName("caption")
        header.addWidget(title_label, 1)
        layout.addLayout(header)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        self.value_label.setStyleSheet(f"font-size: 20pt; font-weight: 600; color: {accent};")
        self.description_label = QLabel(description)
        self.description_label.setObjectName("muted")
        self.description_label.setWordWrap(True)
        layout.addWidget(self.value_label)
        layout.addWidget(self.description_label)
        self._count_animation = QVariantAnimation(self)
        self._count_animation.setDuration(320)
        self._count_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._count_animation.valueChanged.connect(
            lambda value: self.value_label.setText(str(round(value)))
        )

    def set_value(self, value: str) -> None:
        current = self.value_label.text()
        if current.isdecimal() and value.isdecimal() and current != value:
            self._count_animation.stop()
            self._count_animation.setStartValue(int(current))
            self._count_animation.setEndValue(int(value))
            self._count_animation.start()
            return
        self._count_animation.stop()
        self.value_label.setText(value)

    def set_description(self, description: str) -> None:
        self.description_label.setText(description)
