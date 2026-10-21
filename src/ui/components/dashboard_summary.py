"""Compact reference-style dashboard summary cards."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import pairwise
from typing import ClassVar

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.storage.models import IdentityEvent
from src.ui.icon_assets import icon_path


class _SummaryCard(QFrame):
    def __init__(
        self,
        title: str,
        icon: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(5)
        self._layout = layout
        header = QHBoxLayout()
        header.setSpacing(5)
        icon_label = QLabel()
        icon_label.setPixmap(QIcon(icon_path(icon)).pixmap(16, 16))
        header.addWidget(icon_label)
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("caption")
        header.addWidget(self.title_label, 1)
        layout.addLayout(header)
        self.body_widget = QWidget()
        self.body_layout = QHBoxLayout(self.body_widget)
        self.body_layout.setContentsMargins(0, 0, 0, 0)
        self.body_layout.setSpacing(8)
        layout.addWidget(self.body_widget, 1)
        self.error_label = QLabel()
        self.error_label.setObjectName("muted")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        layout.addWidget(self.error_label, 1)

    def set_error(self, message: str) -> None:
        self.body_widget.hide()
        self.error_label.setText(message)
        self.error_label.show()

    def clear_error(self) -> None:
        self.error_label.hide()
        self.body_widget.show()


class DashboardIdentityCard(_SummaryCard):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Identity Protection", "face-scan.png", parent)
        self.avatar = QLabel("—")
        self.avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar.setFixedSize(58, 58)
        self.avatar.setStyleSheet(
            "color:#e6f0ff;background:#0a2b4d;border:2px solid #18d89b;"
            "border-radius:29px;font-size:15pt;font-weight:600;"
        )
        self.body_layout.addWidget(self.avatar, 0, Qt.AlignmentFlag.AlignVCenter)

        details = QVBoxLayout()
        details.setSpacing(2)
        self.state_label = QLabel("NOT ENROLLED")
        self.state_label.setStyleSheet("color:#8ea9c8;font-weight:700;")
        self.name_label = QLabel("Consent-based enrollment required")
        self.name_label.setObjectName("muted")
        self.name_label.setWordWrap(True)
        self.confidence_label = QLabel("Confidence  —")
        self.confidence_label.setObjectName("muted")
        self.last_verified_label = QLabel("Last verified  —")
        self.last_verified_label.setObjectName("muted")
        for label in (
            self.state_label,
            self.name_label,
            self.confidence_label,
            self.last_verified_label,
        ):
            details.addWidget(label)
        self.body_layout.addLayout(details, 1)

    def set_identity(
        self,
        display_name: str | None,
        state: str,
        last_event: IdentityEvent | None,
    ) -> None:
        self.clear_error()
        if not display_name:
            self.avatar.setText("—")
            self.state_label.setText("NOT ENROLLED")
            self.state_label.setStyleSheet("color:#8ea9c8;font-weight:700;")
            self.name_label.setText("Consent-based enrollment required")
            self.confidence_label.setText("Confidence  —")
            self.last_verified_label.setText("Last verified  —")
            return

        initials = "".join(
            part[0] for part in display_name.split() if part
        )[:2].upper()
        self.avatar.setText(initials or display_name[:1].upper())
        self.name_label.setText(display_name)
        current = (
            last_event.state
            if last_event is not None
            else state
        ).replace("_", " ").strip().upper()
        verified = current == "RECOGNIZED"
        shown_state = "VERIFIED" if verified else current or "ENROLLED"
        self.state_label.setText(shown_state)
        self.state_label.setStyleSheet(
            "color:#18d89b;font-weight:700;"
            if verified
            else "color:#f5ad32;font-weight:700;"
        )
        if last_event is not None and last_event.confidence is not None:
            self.confidence_label.setText(
                f"Confidence  {last_event.confidence:.1%}"
            )
        else:
            self.confidence_label.setText("Confidence  —")
        if last_event is not None and last_event.state == "recognized":
            self.last_verified_label.setText(
                f"Last verified  {_time_ago(last_event.occurred_at)}"
            )
        else:
            self.last_verified_label.setText("Last verified  —")


class _ScoreRing(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(78, 78)
        self._score: float | None = None
        self._color = QColor("#f5ad32")

    def set_score(self, score: float | None, color: str) -> None:
        self._score = score
        self._color = QColor(color)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#17395c"), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(7, 7, 64, 64, 0, 360 * 16)
        if self._score is not None:
            painter.setPen(
                QPen(
                    self._color,
                    6,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                )
            )
            painter.drawArc(7, 7, 64, 64, 90 * 16, -int(360 * 16 * self._score / 100))
        painter.setPen(QColor("#e6f0ff"))
        painter.drawText(
            self.rect().adjusted(0, -2, 0, -2),
            Qt.AlignmentFlag.AlignCenter,
            f"{round(self._score)}%" if self._score is not None else "—",
        )


class DashboardScoreCard(_SummaryCard):
    _FACTORS = ("Identity", "Files", "Processes", "Network", "Windows")
    _FACTOR_COLORS = ("#05d6b5", "#9fce3b", "#f7a526", "#f29b20", "#ee941d")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Endpoint Security Score", "security-score-gauge.png", parent)
        self.ring = _ScoreRing()
        self.body_layout.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignVCenter)
        factors = QVBoxLayout()
        factors.setSpacing(2)
        self.risk_label = QLabel("MEASURED COVERAGE")
        self.risk_label.setStyleSheet("color:#f5ad32;font-weight:700;")
        factors.addWidget(self.risk_label)
        self.factor_values: dict[str, QLabel] = {}
        self.factor_stats: dict[str, QLabel] = {}
        self.factor_progress: dict[str, QProgressBar] = {}
        for index, name in enumerate(self._FACTORS):
            row = QHBoxLayout()
            row.setSpacing(5)
            label = QLabel(name)
            label.setObjectName("muted")
            label.setFixedWidth(54)
            value = QLabel("—")
            value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            value.setMinimumWidth(31)
            value.setStyleSheet(
                f"color:{self._FACTOR_COLORS[index]};font-weight:700;"
            )
            statistic = QLabel("No sample")
            statistic.hide()
            progress = QProgressBar()
            progress.setRange(0, 100)
            progress.setTextVisible(False)
            progress.setMinimumWidth(30)
            progress.setFixedHeight(6)
            progress.setStyleSheet(
                "QProgressBar { border: 0; background: #17395c; border-radius: 3px; }"
                f"QProgressBar::chunk {{ background: {self._FACTOR_COLORS[index]};"
                " border-radius: 3px; }"
            )
            progress.setToolTip("Measured percentage; hover for the sample details.")
            row.addWidget(label)
            row.addWidget(progress, 1)
            row.addWidget(value)
            factors.addLayout(row)
            self.factor_values[name] = value
            self.factor_stats[name] = statistic
            self.factor_progress[name] = progress
        self.body_layout.addLayout(factors, 1)

    def set_factors(self, values: Mapping[str, tuple[int | None, str]]) -> None:
        self.clear_error()
        coverage_scores = []
        missing_factors = []
        for name, label in self.factor_values.items():
            score, statistic = values.get(name, (None, "No data"))
            if score is not None:
                score = min(100, max(0, score))
                coverage_scores.append(score)
            else:
                missing_factors.append(name)
            self.factor_stats[name].setText(statistic)
            self.factor_stats[name].setToolTip(statistic)
            detail = f"{name}: {statistic}; measured value: {score}%." if score is not None else (
                f"{name}: {statistic}; percentage unavailable."
            )
            label.setToolTip(detail)
            self.factor_progress[name].setToolTip(detail)
            self.factor_values[name].setToolTip(detail)
            self.factor_values[name].setText(f"{score}%" if score is not None else "N/A")
            self.factor_progress[name].setValue(score or 0)
        if len(coverage_scores) == len(self._FACTORS):
            average = sum(coverage_scores) / len(coverage_scores)
            if average >= 80:
                color = "#18d89b"
                status = "HEALTHY · MAINTAIN PROTECTION"
            elif average >= 60:
                color = "#f5ad32"
                status = "FAIR · REVIEW WEAK AREAS"
            else:
                color = "#f04b67"
                status = "AT RISK · TAKE ACTION"
            self.ring.set_score(average, color)
            self.risk_label.setText(status)
            self.risk_label.setStyleSheet(f"color:{color};font-weight:700;")
        else:
            self.ring.set_score(None, "#f5ad32")
            self.risk_label.setText(
                "INCOMPLETE · ENABLE MISSING MONITORS"
                if coverage_scores
                else "NO DATA · ENABLE MONITORS"
            )
            self.risk_label.setStyleSheet("color:#f5ad32;font-weight:700;")
        tooltip = (
            "The equal-weight average is shown only after all five Identity, Files, "
            "Processes, Network, and Windows measurements have real sample denominators. "
            "A partial dataset is not presented as a complete score. This is an "
            "operational indicator, not a malware or protection-effectiveness score."
        )
        if missing_factors:
            tooltip += "\nUnavailable measurements: " + ", ".join(missing_factors)
        self.risk_label.setToolTip(tooltip)


class _ThreatSparkline(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(54, 34)
        self._values: tuple[int, ...] = ()

    def set_values(self, values: Sequence[int]) -> None:
        self._values = tuple(values)
        self.update()

    def paintEvent(self, _event) -> None:
        if not self._values:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        maximum = max(self._values) or 1
        points = [
            (
                round(index * (self.width() - 4) / max(1, len(self._values) - 1)) + 2,
                round(self.height() - 3 - value * (self.height() - 7) / maximum),
            )
            for index, value in enumerate(self._values)
        ]
        pen = QPen(QColor("#f04b67"), 1.6)
        painter.setPen(pen)
        for first, second in pairwise(points):
            painter.drawLine(QPoint(*first), QPoint(*second))


class DashboardThreatCard(_SummaryCard):
    viewAllRequested = Signal()
    _SEVERITIES: ClassVar[tuple[str, ...]] = ("Critical", "High", "Medium", "Low")
    _COLORS: ClassVar[dict[str, str]] = {
        "Critical": "#f04b67",
        "High": "#f5ad32",
        "Medium": "#08b9f3",
        "Low": "#18d89b",
    }

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Active Threats", "critical-alert.png", parent)
        self.view_all = QPushButton("View All  →")
        self.view_all.setObjectName("activityViewAllButton")
        self.view_all.setStyleSheet("font-size:7pt;padding:1px 5px;")
        self.view_all.clicked.connect(self.viewAllRequested)
        self._layout.itemAt(0).layout().addWidget(self.view_all)

        self.count_label = QLabel("0")
        self.count_label.setStyleSheet("color:#f04b67;font-size:23pt;font-weight:600;")
        self.body_layout.addWidget(self.count_label, 0, Qt.AlignmentFlag.AlignVCenter)

        severities = QVBoxLayout()
        severities.setSpacing(2)
        self.severity_labels: dict[str, QLabel] = {}
        for severity in self._SEVERITIES:
            label = QLabel(f"●  0 {severity}")
            label.setStyleSheet(f"color:{self._COLORS[severity]};font-size:8pt;")
            severities.addWidget(label)
            self.severity_labels[severity] = label
        self.body_layout.addLayout(severities, 1)

        self.sparkline = _ThreatSparkline()
        self.body_layout.addWidget(self.sparkline, 1)

    def set_alert_data(
        self,
        severities: Mapping[str, int],
        hourly_counts: Sequence[int],
    ) -> None:
        self.clear_error()
        self.count_label.setText(str(sum(severities.values())))
        for severity, label in self.severity_labels.items():
            label.setText(f"●  {severities.get(severity.casefold(), 0)} {severity}")
        self.sparkline.set_values(hourly_counts)


class DashboardFilesCard(_SummaryCard):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("File Integrity", "locked-file.png", parent)
        details = QVBoxLayout()
        details.setSpacing(4)
        self.count_label = QLabel("0")
        self.count_label.setStyleSheet("font-size:15pt;font-weight:600;")
        self.count_caption = QLabel("files in configured integrity baseline")
        self.count_caption.setObjectName("muted")
        self.changes_label = QLabel("Recorded changes  0")
        self.changes_label.setStyleSheet("color:#f5ad32;font-size:8pt;")
        self.suspicious_label = QLabel("Unresolved file alerts  0")
        self.suspicious_label.setStyleSheet("color:#f04b67;font-size:8pt;")
        self.quarantined_label = QLabel("Quarantined  —")
        self.quarantined_label.setStyleSheet("color:#8ea9c8;font-size:8pt;")
        self.quarantined_label.setToolTip(
            "File quarantine is not currently implemented."
        )
        for label in (
            self.count_label,
            self.count_caption,
            self.changes_label,
            self.suspicious_label,
            self.quarantined_label,
        ):
            details.addWidget(label)
        self.body_layout.addLayout(details, 1)
        self.action_icon = QLabel()
        self.action_icon.setPixmap(QIcon(icon_path("locked-file.png")).pixmap(28, 28))
        self.body_layout.addWidget(self.action_icon, 0, Qt.AlignmentFlag.AlignCenter)

    def set_file_data(
        self,
        protected_count: int,
        changes: int,
        unresolved_alerts: int,
    ) -> None:
        self.clear_error()
        self.count_label.setText(f"{protected_count:,}")
        self.count_label.setToolTip(
            "Files in the current integrity baseline; not a system-wide malware scan."
        )
        self.changes_label.setText(f"Recorded changes  {changes:,}")
        self.suspicious_label.setText(
            f"Unresolved file alerts  {unresolved_alerts:,}"
        )


def _time_ago(occurred_at: datetime) -> str:
    now = datetime.now(UTC)
    instant = (
        occurred_at.replace(tzinfo=UTC)
        if occurred_at.tzinfo is None
        else occurred_at.astimezone(UTC)
    )
    seconds = max(0, int((now - instant).total_seconds()))
    if seconds < 60:
        return f"{seconds} seconds ago"
    if seconds < 3600:
        return f"{seconds // 60} minutes ago"
    if seconds < 86400:
        return f"{seconds // 3600} hours ago"
    return f"{seconds // 86400} days ago"
