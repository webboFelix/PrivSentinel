"""Compact reference-style dashboard summary cards."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from itertools import pairwise
from typing import ClassVar

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap
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
        self.icon_label = icon_label
        header.addWidget(icon_label)
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("caption")
        header.addWidget(self.title_label, 1)
        self.header_layout = header
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


def _set_avatar(
    label: QLabel,
    image_data: str,
    display_name: str,
    size: int,
    *,
    circular: bool,
) -> None:
    fallback = "".join(part[0] for part in display_name.split() if part)[:2].upper()
    label.setPixmap(QPixmap())
    label.setText(fallback or display_name[:1].upper())
    if not image_data:
        return
    try:
        raw_image = base64.b64decode(image_data, validate=True)
    except (binascii.Error, ValueError):
        return
    image = QImage.fromData(raw_image)
    if image.isNull():
        return
    scaled = image.scaled(
        size,
        size,
        Qt.AspectRatioMode.KeepAspectRatioByExpanding,
        Qt.TransformationMode.SmoothTransformation,
    )
    left = (scaled.width() - size) // 2
    top = (scaled.height() - size) // 2
    source = QPixmap.fromImage(scaled.copy(left, top, size, size))
    if circular:
        result = QPixmap(size, size)
        result.fill(Qt.GlobalColor.transparent)
        painter = QPainter(result)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addEllipse(0, 0, size, size)
        painter.setClipPath(path)
        painter.drawPixmap(0, 0, source)
        painter.end()
        source = result
    label.setPixmap(source)
    label.setText("")


class DashboardIdentityCard(_SummaryCard):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Identity Protection", "identity-verified.png", parent)
        self.title_label.setStyleSheet(
            "color:#d7e8fa;background:#102b49;border-radius:9px;"
            "padding:3px 8px;font-weight:700;"
        )
        self.shield = QLabel()
        self.shield.setPixmap(QIcon(icon_path("shield-check.png")).pixmap(22, 22))
        self.header_layout.addWidget(self.shield)
        self.avatar = QLabel("—")
        self.avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar.setFixedSize(62, 62)
        self.avatar.setStyleSheet(
            "color:#e6f0ff;background:#0a2b4d;border:2px solid #05d6a2;"
            "border-radius:31px;font-size:15pt;font-weight:600;"
        )
        self._avatar_key: tuple[str, str] | None = None
        self.body_layout.addWidget(self.avatar, 0, Qt.AlignmentFlag.AlignVCenter)

        details = QVBoxLayout()
        details.setSpacing(2)
        self.state_label = QLabel("NOT ENROLLED")
        self.state_label.setStyleSheet("color:#8ea9c8;font-weight:700;")
        self.name_label = QLabel("Consent-based enrollment required")
        self.name_label.setObjectName("muted")
        self.name_label.setWordWrap(True)
        self.name_label.hide()
        confidence_row = QHBoxLayout()
        confidence_row.setSpacing(4)
        self.confidence_label = QLabel("Confidence")
        self.confidence_label.setObjectName("muted")
        self.confidence_value_label = QLabel("—")
        self.confidence_value_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self.confidence_value_label.setStyleSheet(
            "color:#05d6a2;font-weight:700;"
        )
        confidence_row.addWidget(self.confidence_label)
        confidence_row.addStretch(1)
        confidence_row.addWidget(self.confidence_value_label)
        last_verified_row = QHBoxLayout()
        last_verified_row.setSpacing(4)
        self.last_verified_label = QLabel("Last verified")
        self.last_verified_label.setObjectName("muted")
        self.last_verified_value_label = QLabel("—")
        self.last_verified_value_label.setObjectName("muted")
        self.last_verified_value_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        last_verified_row.addWidget(self.last_verified_label)
        last_verified_row.addStretch(1)
        last_verified_row.addWidget(self.last_verified_value_label)
        for label in (
            self.state_label,
            self.name_label,
        ):
            details.addWidget(label)
        details.addLayout(confidence_row)
        details.addLayout(last_verified_row)
        self.body_layout.addLayout(details, 1)
        self.setMinimumHeight(106)
        self.setMaximumHeight(135)

    def set_identity(
        self,
        display_name: str | None,
        state: str,
        last_event: IdentityEvent | None,
        profile_image: str = "",
    ) -> None:
        self.clear_error()
        if not display_name:
            self._avatar_key = None
            self.avatar.setPixmap(QPixmap())
            self.avatar.setText("—")
            self.avatar.setToolTip("")
            self.state_label.setText("NOT ENROLLED")
            self.state_label.setStyleSheet("color:#8ea9c8;font-weight:700;")
            self.name_label.setText("Consent-based enrollment required")
            self.confidence_value_label.setText("—")
            self.last_verified_value_label.setText("—")
            return

        avatar_key = (profile_image, display_name)
        if avatar_key != self._avatar_key:
            _set_avatar(self.avatar, profile_image, display_name, 62, circular=True)
            self._avatar_key = avatar_key
        self.avatar.setToolTip(display_name)
        self.name_label.setText(display_name)
        self.name_label.hide()
        current = (
            last_event.state
            if last_event is not None
            else state
        ).replace("_", " ").strip().upper()
        verified = current == "RECOGNIZED"
        motion_pending = (
            last_event is not None
            and (
                last_event.state == "liveness_failure"
                or last_event.liveness == "awaiting_basic_motion"
            )
        )
        shown_state = (
            "VERIFIED"
            if verified
            else "MOTION NOT CONFIRMED"
            if motion_pending
            else current or "ENROLLED"
        )
        self.state_label.setText(shown_state)
        self.state_label.setToolTip(
            "Basic facial movement was not observed in this short sample. "
            "Move slightly to continue; this is not proof of spoofing."
            if motion_pending
            else shown_state
        )
        self.state_label.setStyleSheet(
            "color:#18d89b;font-weight:700;"
            if verified
            else "color:#f5ad32;font-weight:700;"
        )
        confidence = last_event.confidence if last_event is not None else None
        self.confidence_value_label.setText(
            f"{confidence:.1%}" if confidence is not None else "—"
        )
        if last_event is not None and last_event.state == "recognized":
            self.last_verified_value_label.setText(
                _time_ago(last_event.occurred_at)
            )
        else:
            self.last_verified_value_label.setText("—")


class IdentityVerificationCard(QFrame):
    viewHistoryRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("identityVerificationCard")
        self.setMinimumHeight(126)
        self.setMaximumHeight(158)
        self.setStyleSheet(
            "QFrame#identityVerificationCard {"
            "background:#071d36;border:1px solid #17456d;border-radius:10px;}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(9, 8, 9, 7)
        layout.setSpacing(5)

        header = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QIcon(icon_path("identity-verified.png")).pixmap(18, 18))
        header.addWidget(icon)
        title = QLabel("Identity Verification")
        title.setStyleSheet("color:#d7e8fa;font-weight:700;")
        header.addWidget(title, 1)
        self.live_badge = QLabel("● OFFLINE")
        self.live_badge.setStyleSheet(
            "color:#88a3c1;background:#102b49;border:1px solid #244c70;"
            "border-radius:8px;padding:2px 7px;font-size:8pt;font-weight:700;"
        )
        header.addWidget(self.live_badge)
        layout.addLayout(header)

        content = QHBoxLayout()
        content.setSpacing(8)
        self.avatar = QLabel("—")
        self.avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar.setFixedSize(52, 52)
        self.avatar.setStyleSheet(
            "color:#e6f0ff;background:#0a2b4d;border:1px solid #05d6a2;"
            "border-radius:5px;font-size:14pt;font-weight:600;"
        )
        self._avatar_key: tuple[str, str] | None = None
        content.addWidget(self.avatar, 0, Qt.AlignmentFlag.AlignVCenter)

        details = QVBoxLayout()
        details.setSpacing(1)
        self.name_label = QLabel("Face Verification")
        self.name_label.setStyleSheet("color:#c8dcf2;font-size:9pt;")
        details.addWidget(self.name_label)
        self.state_label = QLabel("NOT ENROLLED")
        self.state_label.hide()
        self.confidence_label = QLabel("—")
        self.confidence_label.setStyleSheet(
            "color:#05d6a2;font-size:13pt;font-weight:700;"
        )
        details.addWidget(self.confidence_label)
        self.last_seen_label = QLabel("Last seen  —")
        self.last_seen_label.setStyleSheet("color:#9ab1ca;font-size:8pt;")
        details.addWidget(self.last_seen_label)

        self.face_status = QLabel("○  Face detected")
        self.match_status = QLabel("○  Identity matched")
        self.motion_status = QLabel("○  Liveness confirmed")
        for label in (self.face_status, self.match_status, self.motion_status):
            label.setStyleSheet("color:#8ea9c8;font-size:8pt;")
        content.addLayout(details, 1)
        layout.addLayout(content, 1)

        footer = QHBoxLayout()
        checks = QVBoxLayout()
        checks.setSpacing(1)
        for label in (self.face_status, self.match_status, self.motion_status):
            checks.addWidget(label)
        footer.addLayout(checks, 1)
        self.history_button = QPushButton("View History")
        self.history_button.setObjectName("secondaryButton")
        self.history_button.setFixedHeight(23)
        self.history_button.clicked.connect(self.viewHistoryRequested)
        footer.addWidget(self.history_button)
        layout.addLayout(footer)

    def set_identity(
        self,
        display_name: str | None,
        monitoring: bool,
        state: str,
        last_event: IdentityEvent | None,
        profile_image: str = "",
    ) -> None:
        if not display_name:
            self._avatar_key = None
            self.avatar.setPixmap(QPixmap())
            self.avatar.setText("—")
            self.name_label.setText("Face Verification")
            self.state_label.setText("NOT ENROLLED")
            self.confidence_label.setText("—")
            self.last_seen_label.setText("Last seen  —")
            self._set_status(self.face_status, "Face not detected", False)
            self._set_status(self.match_status, "Identity not verified", False)
            self._set_status(self.motion_status, "Liveness not confirmed", False)
            self.live_badge.setText("● OFFLINE")
            self.live_badge.setStyleSheet(
                "color:#88a3c1;background:#102b49;border:1px solid #244c70;"
                "border-radius:8px;padding:2px 7px;font-size:8pt;font-weight:700;"
            )
            return

        avatar_key = (profile_image, display_name)
        if avatar_key != self._avatar_key:
            _set_avatar(self.avatar, profile_image, display_name, 52, circular=False)
            self._avatar_key = avatar_key
        self.name_label.setToolTip(display_name)

        state_value = state.casefold()
        if last_event is not None:
            state_value = last_event.state.casefold()
        verified = state_value == "recognized"
        motion_pending = (
            last_event is not None
            and (
                last_event.state == "liveness_failure"
                or last_event.liveness == "awaiting_basic_motion"
            )
        )
        label = (
            "VERIFIED"
            if verified
            else "MOTION NOT CONFIRMED"
            if motion_pending
            else state_value.replace("_", " ").upper()
        )
        if not label or label == "STOPPED":
            label = "ENROLLED"
        self.state_label.setText(label)
        self.state_label.setToolTip(
            "Basic facial movement was not observed in this short sample. "
            "Move slightly to continue; this is not proof of spoofing."
            if motion_pending
            else label
        )
        confidence = last_event.confidence if last_event is not None else None
        self.confidence_label.setText(
            f"{confidence:.1%}"
            if confidence is not None
            else "—"
        )
        self.last_seen_label.setText(
            f"Last seen  {_time_ago(last_event.occurred_at)}"
            if last_event is not None and verified
            else "Last seen  —"
        )

        face_detected = state_value in {
            "recognized",
            "unknown_face",
            "low_confidence",
            "liveness_failure",
        }
        self._set_status(self.face_status, "Face detected", face_detected)
        self._set_status(self.match_status, "Identity matched", verified)
        motion_observed = (
            last_event is not None
            and last_event.liveness == "basic_motion_observed"
        )
        self._set_status(
            self.motion_status,
            "Liveness confirmed" if motion_observed else "Motion not confirmed",
            motion_observed,
        )
        self.live_badge.setText("● LIVE" if monitoring else "● IDLE")
        self.live_badge.setStyleSheet(
            "color:#05d6a2;background:#073d42;border:1px solid #087d78;"
            "border-radius:8px;padding:2px 7px;font-size:8pt;font-weight:700;"
            if monitoring
            else "color:#f5ad32;background:#3a2c16;border:1px solid #71521c;"
            "border-radius:8px;padding:2px 7px;font-size:8pt;font-weight:700;"
        )

    @staticmethod
    def _set_status(label: QLabel, text: str, passed: bool) -> None:
        marker = "✓" if passed else "○"
        color = "#05d6a2" if passed else "#8ea9c8"
        label.setText(f"{marker}  {text}")
        label.setStyleSheet(f"color:{color};font-size:8pt;")

    def set_error(self, message: str) -> None:
        self.name_label.setText("Identity status unavailable")
        self.name_label.setToolTip(message)


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
        self.factor_indicators: dict[str, QLabel] = {}
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
            indicator = QLabel()
            indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
            indicator.setMinimumWidth(48)
            if name in {"Processes", "Network", "Windows"}:
                progress.hide()
                indicator.show()
            else:
                indicator.hide()
            row.addWidget(label)
            row.addWidget(progress, 1)
            row.addWidget(indicator)
            row.addWidget(value)
            factors.addLayout(row)
            self.factor_values[name] = value
            self.factor_stats[name] = statistic
            self.factor_progress[name] = progress
            self.factor_indicators[name] = indicator
        self.body_layout.addLayout(factors, 1)

    def set_factors(
        self,
        values: Mapping[str, tuple[int | None, str] | tuple[int | None, str, bool]],
    ) -> None:
        self.clear_error()
        coverage_scores = []
        missing_factors = []
        for name, label in self.factor_values.items():
            factor = values.get(name, (None, "No data"))
            score, statistic = factor[:2]
            indicator_active = (
                factor[2]
                if len(factor) == 3
                else None
            )
            if score is not None:
                score = min(100, max(0, score))
                coverage_scores.append(score)
            else:
                missing_factors.append(name)
            self.factor_stats[name].setText(statistic)
            self.factor_stats[name].setToolTip(statistic)
            if indicator_active is not None:
                detail = (
                    f"{name}: {statistic}; collector is "
                    f"{'active' if indicator_active else 'inactive'}."
                )
            elif score is not None:
                detail = f"{name}: {statistic}; measured value: {score}%."
            else:
                detail = f"{name}: {statistic}; percentage unavailable."
            label.setToolTip(detail)
            self.factor_progress[name].setToolTip(detail)
            self.factor_values[name].setToolTip(detail)
            if indicator_active is None:
                self.factor_values[name].setText(
                    f"{score}%" if score is not None else "N/A"
                )
                self.factor_values[name].setStyleSheet(
                    f"color:{self._FACTOR_COLORS[self._FACTORS.index(name)]};"
                    "font-weight:700;"
                )
            else:
                status_text = "Active" if indicator_active else "Inactive"
                status_color = "#18d89b" if indicator_active else "#f04b67"
                self.factor_values[name].setText(status_text)
                self.factor_values[name].setStyleSheet(
                    f"color:{status_color};font-weight:700;"
                )
                self.factor_indicators[name].setText("●")
                self.factor_indicators[name].setStyleSheet(
                    f"color:{status_color};font-size:11pt;"
                )
                self.factor_indicators[name].setToolTip(status_text)
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
