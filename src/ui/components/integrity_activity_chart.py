"""Reference-style stacked chart for observed file-integrity changes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import ClassVar

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from src.ui.icon_assets import icon_path

_CATEGORIES = ("Created", "Modified", "Deleted", "Renamed")
_COLORS = {
    "Created": QColor("#168cf0"),
    "Modified": QColor("#18d89b"),
    "Deleted": QColor("#f5ad32"),
    "Renamed": QColor("#f04b67"),
}
_EVENT_CATEGORIES = {
    "file_added": "Created",
    "file_changed": "Modified",
    "file_modified": "Modified",
    "file_missing": "Deleted",
    "file_renamed": "Renamed",
}


class _StackedActivityPlot(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.labels: tuple[str, ...] = ()
        self.values: dict[str, tuple[int, ...]] = {
            category: () for category in _CATEGORIES
        }
        self.empty_message = "No file-integrity activity recorded."
        self.setMinimumHeight(132)
        self.setMouseTracking(True)

    def set_series(
        self,
        labels: tuple[str, ...],
        values: Mapping[str, tuple[int, ...]],
    ) -> None:
        self.labels = labels
        self.values = {category: values[category] for category in _CATEGORIES}
        self.empty_message = ""
        self.update()

    def paintEvent(self, event) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.fillRect(self.rect(), QColor("#081d37"))
        left, top, right, bottom = 34.0, 8.0, 8.0, 24.0
        plot = QRectF(
            left,
            top,
            max(1.0, self.width() - left - right),
            max(1.0, self.height() - top - bottom),
        )
        bucket_count = len(self.labels)
        if not bucket_count:
            painter.setPen(QColor("#8ea9c8"))
            painter.drawText(
                plot,
                Qt.AlignmentFlag.AlignCenter,
                self.empty_message or "No file-integrity activity recorded.",
            )
            return
        stacked_totals = [
            sum(self.values[category][index] for category in _CATEGORIES)
            for index in range(bucket_count)
        ]
        maximum = max(stacked_totals, default=0)
        if maximum == 0:
            painter.setPen(QColor("#8ea9c8"))
            painter.drawText(
                plot,
                Qt.AlignmentFlag.AlignCenter,
                "No observed changes in this period",
            )
        tick_maximum = max(4, ((maximum + 3) // 4) * 4)
        painter.setFont(self.font())
        for tick in range(5):
            value = tick_maximum * (4 - tick) / 4
            y = plot.top() + plot.height() * tick / 4
            painter.setPen(QPen(QColor("#173b5f"), 1))
            painter.drawLine(int(plot.left()), int(y), int(plot.right()), int(y))
            painter.setPen(QColor("#8ea9c8"))
            painter.drawText(
                QRectF(0, y - 8, left - 5, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(round(value)),
            )
        slot_width = plot.width() / bucket_count
        bar_width = max(2.0, min(14.0, slot_width * 0.62))
        for index, label in enumerate(self.labels):
            x = plot.left() + (index + 0.5) * slot_width
            y_bottom = plot.bottom()
            for category in _CATEGORIES:
                count = self.values[category][index]
                if count <= 0:
                    continue
                height = plot.height() * count / tick_maximum
                y_bottom -= height
                painter.fillRect(
                    QRectF(x - bar_width / 2, y_bottom, bar_width, height),
                    _COLORS[category],
                )
            label_stride = 3 if bucket_count == 24 else 1 if bucket_count == 7 else 5
            if index % label_stride == 0 or index == bucket_count - 1:
                painter.setPen(QColor("#8ea9c8"))
                painter.drawText(
                    QRectF(x - slot_width, plot.bottom() + 4, slot_width * 2, 18),
                    Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                    label,
                )

    def mouseMoveEvent(self, event) -> None:
        if not self.labels:
            return
        plot_left = 34.0
        plot_width = max(1.0, self.width() - plot_left - 8.0)
        index = int((event.position().x() - plot_left) / plot_width * len(self.labels))
        if 0 <= index < len(self.labels):
            counts = " · ".join(
                f"{category}: {self.values[category][index]}"
                for category in _CATEGORIES
            )
            self.setToolTip(f"{self.labels[index]} · {counts}")
        super().mouseMoveEvent(event)


class FileIntegrityActivityChart(QFrame):
    periodChanged = Signal(str)

    _PERIODS: ClassVar[dict[str, tuple[int, str]]] = {
        "24h": (24, "hour"),
        "7d": (7, "day"),
        "30d": (30, "day"),
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.setToolTip(
            "Activity is recorded when a configured integrity scan observes a change. "
            "Rename events are inferred from matching file hashes."
        )
        self._labels: tuple[str, ...] = ()
        self._values: dict[str, tuple[int, ...]] = {
            category: () for category in _CATEGORIES
        }
        self._has_data = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 10, 13, 8)
        layout.setSpacing(4)
        header = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QIcon(icon_path("verified-document.png")).pixmap(18, 18))
        header.addWidget(icon)
        title = QLabel("File Integrity Activity")
        title.setObjectName("sectionTitle")
        header.addWidget(title, 1)
        self.period_selector = QComboBox()
        self.period_selector.addItem("Last 24 Hours", "24h")
        self.period_selector.addItem("Last 7 Days", "7d")
        self.period_selector.addItem("Last 30 Days", "30d")
        self.period_selector.setObjectName("chartPeriod")
        self.period_selector.currentIndexChanged.connect(
            lambda: self.periodChanged.emit(str(self.period_selector.currentData()))
        )
        header.addWidget(self.period_selector)
        layout.addLayout(header)
        self.plot = _StackedActivityPlot()
        layout.addWidget(self.plot, 1)
        legend = QHBoxLayout()
        legend.addStretch(1)
        for category in _CATEGORIES:
            marker = QLabel("■")
            marker.setStyleSheet(f"color: {_COLORS[category].name()};")
            legend.addWidget(marker)
            name = QLabel(category)
            name.setObjectName("chartLegend")
            legend.addWidget(name)
        legend.addStretch(1)
        layout.addLayout(legend)

    @property
    def period(self) -> str:
        return str(self.period_selector.currentData())

    @property
    def series(self) -> dict[str, tuple[int, ...]]:
        return self._values.copy()

    def range_start_utc(self, now: datetime | None = None) -> datetime:
        current = _as_utc(now or datetime.now(UTC))
        period_size, period_unit = self._PERIODS[self.period]
        if period_unit == "hour":
            return current - timedelta(hours=period_size)
        local_current = current.astimezone()
        first_day = local_current.replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=period_size - 1)
        return first_day.astimezone(UTC)

    def set_events(
        self,
        rows: Sequence[Mapping[str, object]],
        now: datetime | None = None,
    ) -> None:
        self._has_data = False
        current = _as_utc(now or datetime.now(UTC))
        period_size, period_unit = self._PERIODS[self.period]
        if period_unit == "hour":
            start = self.range_start_utc(current)
            labels = tuple(
                (start + timedelta(hours=index)).astimezone().strftime("%I %p")
                .lstrip("0")
                .replace(" AM", "A")
                .replace(" PM", "P")
                for index in range(period_size)
            )
            get_bucket = lambda occurred: min(
                period_size - 1,
                int((occurred - start).total_seconds() // 3600),
            )
        else:
            local_current = current.astimezone()
            start_local = local_current.replace(
                hour=0, minute=0, second=0, microsecond=0
            ) - timedelta(days=period_size - 1)
            start = start_local.astimezone(UTC)
            labels = tuple(
                (start_local + timedelta(days=index)).strftime(
                    "%a" if period_size == 7 else "%d"
                )
                for index in range(period_size)
            )
            get_bucket = lambda occurred: (
                occurred.astimezone().date() - start_local.date()
            ).days
        counts = {category: [0] * period_size for category in _CATEGORIES}
        for row in rows:
            category = _EVENT_CATEGORIES.get(str(row.get("event_type", "")))
            if category is None:
                continue
            try:
                occurred = _as_utc(
                    datetime.fromisoformat(str(row["occurred_at"]))
                )
            except (KeyError, ValueError):
                continue
            if occurred < start or occurred > current:
                continue
            index = get_bucket(occurred)
            if 0 <= index < period_size:
                counts[category][index] += 1
                self._has_data = True
        self._labels = labels
        self._values = {
            category: tuple(counts[category]) for category in _CATEGORIES
        }
        self.plot.set_series(self._labels, self._values)

    def set_message(self, message: str) -> None:
        self._has_data = False
        self._labels = ()
        self._values = {category: () for category in _CATEGORIES}
        self.plot.set_series((), self._values)
        self.plot.empty_message = message
        self.plot.update()


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
