"""Basic motion-based presentation heuristic; not anti-spoofing."""

from __future__ import annotations

from collections import deque

import numpy as np


class BasicMotionLiveness:
    """Tracks coarse face-box motion and reports only a basic heuristic."""

    def __init__(self, required_samples: int = 5, minimum_motion: float = 0.025) -> None:
        self._landmarks: deque[np.ndarray] = deque(maxlen=required_samples)
        self._minimum_motion = minimum_motion
        self._passed = False

    @property
    def result(self) -> str:
        if self._passed:
            return "basic_motion_observed"
        return "awaiting_basic_motion"

    @property
    def sample_ready(self) -> bool:
        return len(self._landmarks) == self._landmarks.maxlen

    def update(
        self, landmarks: np.ndarray, frame_width: int, frame_height: int
    ) -> str:
        points = np.asarray(landmarks, dtype=np.float32)
        if points.ndim != 2 or points.shape[1] != 2 or points.shape[0] < 5:
            return self.result
        normalized = points / np.array(
            [max(1, frame_width), max(1, frame_height)], dtype=np.float32
        )
        if self._landmarks and normalized.shape != self._landmarks[-1].shape:
            self.reset()
        self._landmarks.append(normalized)
        if len(self._landmarks) == self._landmarks.maxlen:
            displacement = np.linalg.norm(
                self._landmarks[-1] - self._landmarks[0], axis=1
            )
            self._passed = self._passed or (
                float(np.median(displacement)) >= self._minimum_motion
            )
        return self.result

    def reset(self) -> None:
        self._landmarks.clear()
        self._passed = False