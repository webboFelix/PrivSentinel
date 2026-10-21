"""Adaptive interface throughput sampling without inspecting packet contents."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from statistics import median

import psutil


@dataclass(frozen=True, slots=True)
class TrafficRateSample:
    upload_bytes_per_second: float
    download_bytes_per_second: float
    spike_threshold_bytes_per_second: float
    is_spike: bool


class TrafficRateSampler:
    """Calculate total interface rates and identify sustained-baseline spikes."""

    _MINIMUM_SPIKE_RATE = 1_048_576.0
    _BASELINE_MULTIPLIER = 3.0

    def __init__(self, history_size: int = 60) -> None:
        if history_size < 3:
            raise ValueError("Traffic history must retain at least three samples.")
        self._history: deque[float] = deque(maxlen=history_size)
        self._previous: tuple[int, int] | None = None
        self._previous_at: float | None = None

    def sample(self) -> TrafficRateSample:
        counters = psutil.net_io_counters()
        if counters is None:
            raise OSError("Network interface byte counters are unavailable.")
        now = time.monotonic()
        elapsed = now - self._previous_at if self._previous_at is not None else 1.0
        self._previous_at = now
        return self._calculate(counters.bytes_sent, counters.bytes_recv, elapsed)

    def update(self, bytes_sent: int, bytes_received: int) -> TrafficRateSample:
        return self._calculate(bytes_sent, bytes_received, 1.0)

    def _calculate(
        self,
        bytes_sent: int,
        bytes_received: int,
        elapsed_seconds: float,
    ) -> TrafficRateSample:
        if bytes_sent < 0 or bytes_received < 0:
            raise ValueError("Network byte counters cannot be negative.")
        if elapsed_seconds <= 0:
            raise ValueError("Traffic sample interval must be positive.")
        upload = download = 0.0
        if self._previous is not None:
            previous_sent, previous_received = self._previous
            upload = max(0, bytes_sent - previous_sent) / elapsed_seconds
            download = max(0, bytes_received - previous_received) / elapsed_seconds
        self._previous = (bytes_sent, bytes_received)

        baseline_rate = median(self._history) if self._history else 0.0
        threshold = max(
            self._MINIMUM_SPIKE_RATE,
            baseline_rate * self._BASELINE_MULTIPLIER,
        )
        total_rate = upload + download
        is_spike = bool(self._history) and total_rate >= threshold
        self._history.append(total_rate)
        return TrafficRateSample(upload, download, threshold, is_spike)
