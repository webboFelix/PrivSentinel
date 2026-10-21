"""Live interface throughput and adaptive high-traffic notification."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.network.traffic_monitor import TrafficRateSample, TrafficRateSampler
from src.ui.icon_assets import icon_path


class NetworkTrafficPanel(QFrame):
    reviewConnectionsRequested = Signal()

    def __init__(self, enabled: bool = True, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.enabled = enabled
        self.sampler = TrafficRateSampler()
        self._consecutive_spikes = 0
        self._spike_active = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 9)
        layout.setSpacing(6)
        heading = QLabel("Live network traffic")
        heading.setObjectName("sectionTitle")
        heading.setToolTip(
            "Total upload and download rates from operating-system interface byte "
            "counters. Payloads are not inspected or attributed to individual processes."
        )
        layout.addWidget(heading)
        rates = QHBoxLayout()
        self.upload_label = QLabel("↑ Upload  —")
        self.download_label = QLabel("↓ Download  —")
        for label in (self.upload_label, self.download_label):
            label.setObjectName("metricValue")
            rates.addWidget(label)
        rates.addStretch(1)
        layout.addLayout(rates)
        status = QHBoxLayout()
        self.status_label = QLabel(
            "Collecting interface counters…"
            if enabled
            else "Enable network monitoring in Settings to collect traffic rates."
        )
        self.status_label.setObjectName("muted")
        self.status_label.setWordWrap(True)
        status.addWidget(self.status_label, 1)
        self.review_button = QPushButton("Review connection records")
        self.review_button.setIcon(QIcon(icon_path("network_topology.png")))
        self.review_button.hide()
        self.review_button.clicked.connect(self.reviewConnectionsRequested)
        status.addWidget(self.review_button)
        layout.addLayout(status)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.sample)

    def sample(self) -> None:
        if not self.enabled:
            return
        try:
            sample = self.sampler.sample()
        except OSError as exc:
            self.status_label.setText(f"Traffic counters unavailable: {exc}")
            self.status_label.setStyleSheet("color:#f04b67;")
            self.review_button.hide()
            return
        self.set_sample(sample)

    def set_sample(self, sample: TrafficRateSample) -> None:
        self.upload_label.setText(
            f"↑ Upload  {_format_rate(sample.upload_bytes_per_second)}"
        )
        self.download_label.setText(
            f"↓ Download  {_format_rate(sample.download_bytes_per_second)}"
        )
        if sample.is_spike:
            self._consecutive_spikes += 1
        else:
            self._consecutive_spikes = 0
            self._spike_active = False
        if self._consecutive_spikes >= 3:
            self._spike_active = True
        if self._spike_active:
            self.status_label.setText(
                "Sustained traffic spike detected against the adaptive baseline. "
                "Review connection records before taking action; blocking requires confirmation."
            )
            self.status_label.setStyleSheet("color:#f5ad32;font-weight:700;")
            self.review_button.show()
        else:
            self.status_label.setText(
                "Monitoring total interface throughput · adaptive spike threshold "
                f"{_format_rate(sample.spike_threshold_bytes_per_second)}"
            )
            self.status_label.setStyleSheet("")
            self.review_button.hide()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self.enabled:
            self._timer.start()
            self.sample()

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)


def _format_rate(value: float) -> str:
    units = ("B/s", "KB/s", "MB/s", "GB/s")
    rate = max(0.0, value)
    unit_index = 0
    while rate >= 1024 and unit_index < len(units) - 1:
        rate /= 1024
        unit_index += 1
    return f"{rate:.1f} {units[unit_index]}"
