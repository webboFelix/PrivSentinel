"""Single-face detection and enrollment image quality checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np


@dataclass(frozen=True, slots=True)
class DetectedFace:
    x: int
    y: int
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class ImageQuality:
    accepted: bool
    detail: str
    brightness: float
    sharpness: float


class FaceDetector:
    def __init__(self, cascade_path: str | Path | None = None) -> None:
        path = Path(cascade_path) if cascade_path else (
            Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
        )
        self._cascade = cv2.CascadeClassifier(str(path))
        if self._cascade.empty():
            raise RuntimeError(f"Could not load face detector cascade: {path}")

    def detect(self, frame: np.ndarray) -> list[DetectedFace]:
        if frame is None or frame.ndim != 3 or frame.shape[2] < 3:
            raise ValueError("Face detection requires a color image.")
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.equalizeHist(gray)
        faces = self._cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(48, 48),
            flags=cv2.CASCADE_SCALE_IMAGE,
        )
        return [
            DetectedFace(int(x), int(y), int(width), int(height))
            for x, y, width, height in faces
        ]

    @staticmethod
    def validate_enrollment_frame(
        frame: np.ndarray,
        faces: list[DetectedFace],
        require_single_face: bool = True,
    ) -> ImageQuality:
        if not faces:
            return ImageQuality(False, "No face detected.", 0.0, 0.0)
        if require_single_face and len(faces) != 1:
            return ImageQuality(
                False,
                f"Exactly one face is required; detected {len(faces)}.",
                0.0,
                0.0,
            )
        face = max(faces, key=lambda candidate: candidate.width * candidate.height)
        if face.width < 100 or face.height < 100:
            return ImageQuality(
                False, "Move closer so the face is at least 100×100 pixels.", 0.0, 0.0
            )
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        crop = gray[
            face.y : face.y + face.height,
            face.x : face.x + face.width,
        ]
        if crop.size == 0:
            return ImageQuality(False, "Detected face region is invalid.", 0.0, 0.0)
        brightness = float(np.mean(crop))
        sharpness = float(cv2.Laplacian(crop, cv2.CV_64F).var())
        if brightness < 35 or brightness > 225:
            return ImageQuality(
                False, "Face lighting is too dark or too bright.", brightness, sharpness
            )
        if sharpness < 35:
            return ImageQuality(
                False, "Face image is blurry; hold still and refocus.", brightness, sharpness
            )
        return ImageQuality(True, "Image quality is acceptable.", brightness, sharpness)