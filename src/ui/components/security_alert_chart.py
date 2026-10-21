"""Compact 24-hour security-alert chart backed by local event data."""

from collections.abc import Sequence

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.ui.icon_assets import icon_path


class _AlertPlot(QWidget):
    _GRID = QColor("#153b5e")
    _TEXT = QColor("#a9c2df")
    _LINE = QColor("#00c7f2")
    _SEVERITIES = (
        ("Critical", "#f04b67"),
        ("High", "#f5ad32"),
        ("Medium", "#f5ad32"),
        ("Low", "#18d89b"),
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(130)
        self.setMouseTracking(True)
        self._values: tuple[float, ...] = ()
        self._percentages: tuple[float, ...] = ()
        self._labels: tuple[str, ...] = ()
        self._severity_counts: tuple[dict[str, int], ...] = ()
        self._hover_index: int | None = None
        self._empty_message = "No locally recorded security alerts in the last 24 hours."

    @property
    def has_data(self) -> bool:
        return any(self._values)

    def set_data(
        self,
        points: Sequence[tuple[str, float]],
        severity_counts: Sequence[dict[str, int]],
    ) -> None:
        if len(points) != 24 or len(severity_counts) != 24:
            raise ValueError("Security alert chart requires 24 hourly data points.")
        self._empty_message = "No locally recorded security alerts in the last 24 hours."
        self._labels = tuple(label for label, _ in points)
        self._values = tuple(max(0.0, float(value)) for _, value in points)
        total = sum(self._values)
        self._percentages = tuple(
            value * 100 / total if total else 0.0 for value in self._values
        )
        self._severity_counts = tuple(dict(counts) for counts in severity_counts)
        self._hover_index = None
        self.update()

    def clear_data(self) -> None:
        self._values = ()
        self._percentages = ()
        self._labels = ()
        self._severity_counts = ()
        self._hover_index = None
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(self.font())
        width, height = self.width(), self.height()
        left, right, top, bottom = 34.0, 14.0, 10.0, 34.0
        plot = QRectF(left, top, max(1.0, width - left - right), max(1.0, height - top - bottom))

        axis_max = 100
        y_ticks = tuple(range(0, axis_max + 1, 20))
        painter.setPen(QPen(self._GRID, 1))
        for value in y_ticks:
            y = plot.bottom() - value / axis_max * plot.height()
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(self._TEXT)
            painter.drawText(
                QRectF(0, y - 8, left - 7, 16),
                Qt.AlignmentFlag.AlignRight,
                f"{value}%",
            )
            painter.setPen(QPen(self._GRID, 1))

        if self._percentages:
            positions = tuple(
                QPointF(
                    plot.left()
                    + index / (len(self._percentages) - 1) * plot.width(),
                    plot.bottom() - value / axis_max * plot.height(),
                )
                for index, value in enumerate(self._percentages)
            )
            line = QPainterPath(positions[0])
            for index in range(1, len(positions)):
                previous = positions[index - 1]
                current = positions[index]
                distance = (current.x() - previous.x()) / 3
                line.cubicTo(
                    previous.x() + distance,
                    previous.y(),
                    current.x() - distance,
                    current.y(),
                    current.x(),
                    current.y(),
                )

            fill = QPainterPath(line)
            fill.lineTo(QPointF(plot.right(), plot.bottom()))
            fill.lineTo(QPointF(plot.left(), plot.bottom()))
            fill.closeSubpath()
            gradient = QLinearGradient(0, plot.top(), 0, plot.bottom())
            gradient.setColorAt(0, QColor(0, 199, 242, 88))
            gradient.setColorAt(1, QColor(0, 199, 242, 5))
            painter.fillPath(fill, gradient)
            painter.setPen(QPen(QColor(0, 199, 242, 55), 7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(line)
            painter.setPen(QPen(self._LINE, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(line)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(self._LINE)
            for position in positions:
                painter.drawEllipse(position, 2.6, 2.6)
            self._draw_hover(painter, positions, plot)
            if not self.has_data:
                painter.setPen(self._TEXT)
                painter.drawText(
                    plot,
                    Qt.AlignmentFlag.AlignCenter,
                    self._empty_message,
                )
        else:
            painter.setPen(self._TEXT)
            painter.drawText(
                plot,
                Qt.AlignmentFlag.AlignCenter,
                self._empty_message,
            )

        for index in range(0, 24, 3):
            x = plot.left() + index / 23 * plot.width()
            painter.setPen(self._TEXT)
            painter.drawText(
                QRectF(x - 28, plot.bottom() + 9, 56, 17),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                self._labels[index] if self._labels else f"{index % 12 or 12} AM",
            )

    def _draw_hover(
        self,
        painter: QPainter,
        positions: tuple[QPointF, ...],
        plot: QRectF,
    ) -> None:
        if self._hover_index is None:
            return
        index = self._hover_index
        point = positions[index]
        painter.setPen(QPen(QColor(0, 199, 242, 100), 1))
        painter.drawLine(QPointF(point.x(), plot.top()), QPointF(point.x(), plot.bottom()))
        counts = self._severity_counts[index]
        tooltip = QRectF(
            min(max(8.0, point.x() - 52), self.width() - 150),
            max(4.0, point.y() - 100),
            132,
            92,
        )
        painter.setPen(QPen(QColor("#176093"), 1))
        painter.setBrush(QColor("#071a33"))
        painter.drawRoundedRect(tooltip, 9, 9)
        painter.setPen(QColor("#a9c2df"))
        painter.drawText(tooltip.adjusted(12, 8, -8, -70), Qt.AlignmentFlag.AlignLeft, self._labels[index])
        total = sum(counts.values())
        painter.setPen(self._LINE)
        painter.drawEllipse(QPointF(tooltip.left() + 14, tooltip.top() + 37), 3, 3)
        painter.setPen(QColor("#a9c2df"))
        painter.drawText(QPointF(tooltip.left() + 24, tooltip.top() + 41), f"{total} Total Alerts")
        for line_number, (label, color) in enumerate(self._SEVERITIES):
            y = tooltip.top() + 58 + line_number * 13
            painter.setPen(QColor(color))
            painter.drawEllipse(QPointF(tooltip.left() + 14, y - 4), 3, 3)
            painter.setPen(QColor("#a9c2df"))
            painter.drawText(QPointF(tooltip.left() + 24, y), f"{counts.get(label.casefold(), 0)} {label}")

    def mouseMoveEvent(self, event) -> None:
        if not self._values:
            self._hover_index = None
            self.update()
            return
        left, right = 34.0, 14.0
        plot_width = max(1.0, self.width() - left - right)
        relative_x = min(1.0, max(0.0, (event.position().x() - left) / plot_width))
        self._hover_index = round(relative_x * (len(self._values) - 1))
        self.update()

    def leaveEvent(self, event) -> None:
        self._hover_index = None
        self.update()
        super().leaveEvent(event)


class SecurityAlertChart(QFrame):
    """Security-alert timeline with reference-matched axes and severity legend."""

    viewAllRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.setMinimumHeight(210)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 7)
        layout.setSpacing(2)
        header = QHBoxLayout()
        header.setSpacing(7)
        icon = QLabel()
        icon.setPixmap(QIcon(icon_path("critical-alert.png")).pixmap(18, 18))
        header.addWidget(icon)
        title = QLabel("Security Alerts — Last 24 Hours")
        title.setObjectName("sectionTitle")
        header.addWidget(title, 1)
        self.view_all_button = QPushButton("View All  →")
        self.view_all_button.setStyleSheet("font-size: 8pt; padding: 3px 8px;")
        self.view_all_button.clicked.connect(self.viewAllRequested)
        header.addWidget(self.view_all_button)
        layout.addLayout(header)
        self.plot = _AlertPlot(self)
        self.plot.setToolTip(
            "Each point is that hour's share of all recorded alerts in this 24-hour window."
        )
        layout.addWidget(self.plot, 1)
        self.legend = QWidget(self)
        self.legend.setObjectName("chartLegendRow")
        legend_layout = QHBoxLayout(self.legend)
        legend_layout.setContentsMargins(0, 0, 0, 0)
        legend_layout.setSpacing(14)
        legend_layout.addStretch(1)
        self.legend_items: dict[str, QWidget] = {}
        for label, color in _AlertPlot._SEVERITIES:
            item = QWidget(self.legend)
            item_layout = QHBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(4)
            marker = QLabel("●")
            marker.setStyleSheet(f"color:{color};font-size:9pt;")
            text = QLabel(label)
            text.setObjectName("chartLegend")
            item_layout.addWidget(marker)
            item_layout.addWidget(text)
            legend_layout.addWidget(item)
            self.legend_items[label] = item
        legend_layout.addStretch(1)
        layout.addWidget(self.legend)

    @property
    def _has_data(self) -> bool:
        return self.plot.has_data

    def set_data(
        self,
        points: Sequence[tuple[str, float]],
        severity_counts: Sequence[dict[str, int]],
    ) -> None:
        self.plot.set_data(points, severity_counts)

    def set_message(self, message: str) -> None:
        self.plot._empty_message = message
        self.plot.clear_data()
        self.plot.update()
