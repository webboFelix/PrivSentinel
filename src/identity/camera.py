"""OpenCV camera discovery and frame acquisition primitives."""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np


@dataclass(frozen=True, slots=True)
class CameraDevice:
    index: int
    label: str


class CameraCapture:
    def __init__(
        self,
        index: int,
        width: int,
        height: int,
        backend: int = cv2.CAP_DSHOW,
    ) -> None:
        self.index = index
        self.width = width
        self.height = height
        self.backend = backend
        self._capture: cv2.VideoCapture | None = None

    def open(self) -> None:
        self.release()
        capture = cv2.VideoCapture(self.index, self.backend)
        if not capture.isOpened() and self.backend != cv2.CAP_MSMF:
            capture.release()
            capture = cv2.VideoCapture(self.index, cv2.CAP_MSMF)
        if not capture.isOpened():
            capture.release()
            raise OSError(f"Could not open camera {self.index}.")
        capture.set(cv2.CAP_PROP_FRAME_WIDTH, self.width)
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, self.height)
        self._capture = capture

    def read(self) -> np.ndarray:
        if self._capture is None:
            raise OSError("Camera is not open.")
        ok, frame = self._capture.read()
        if not ok or frame is None or frame.size == 0:
            raise OSError("Camera did not provide a frame.")
        return frame

    def release(self) -> None:
        if self._capture is not None:
            self._capture.release()
            self._capture = None

    @staticmethod
    def available_devices(max_devices: int = 8) -> list[CameraDevice]:
        devices: list[CameraDevice] = []
        for index in range(max_devices):
            for backend in (cv2.CAP_DSHOW, cv2.CAP_MSMF):
                capture = cv2.VideoCapture(index, backend)
                try:
                    if not capture.isOpened():
                        continue
                    ok, frame = capture.read()
                    if ok and frame is not None and frame.size > 0:
                        devices.append(CameraDevice(index, f"Camera {index}"))
                        break
                finally:
                    capture.release()
        return devices