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
    def glasses_visible(frame: np.ndarray, landmarks: np.ndarray) -> bool:
        points = np.asarray(landmarks, dtype=np.float32)
        if (
            frame is None
            or frame.ndim != 3
            or frame.shape[2] < 3
            or points.shape != (5, 2)
            or not np.isfinite(points).all()
        ):
            return False

        eye_distance = float(np.linalg.norm(points[1] - points[0]))
        if eye_distance < 12:
            return False
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        lens_width = max(12, int(eye_distance * 0.56))
        lens_height = max(10, int(eye_distance * 0.46))
        horizontal_length = 0.0
        vertical_length = 0.0

        for eye_x, eye_y in points[:2]:
            center_x = round(float(eye_x))
            center_y = round(float(eye_y))
            left = center_x - lens_width // 2
            top = center_y - lens_height // 2
            right = left + lens_width
            bottom = top + lens_height
            if left < 0 or top < 0 or right > gray.shape[1] or bottom > gray.shape[0]:
                return False

            eye_region = gray[top:bottom, left:right]
            edges = cv2.Canny(cv2.GaussianBlur(eye_region, (3, 3), 0), 45, 120)
            lines = cv2.HoughLinesP(
                edges,
                rho=1,
                theta=np.pi / 180,
                threshold=max(5, lens_width // 5),
                minLineLength=max(5, lens_width // 5),
                maxLineGap=max(2, lens_width // 8),
            )
            if lines is None:
                return False

            eye_horizontal = 0.0
            eye_vertical = 0.0
            for line in lines[:, 0]:
                x1, y1, x2, y2 = (int(value) for value in line)
                dx = abs(x2 - x1)
                dy = abs(y2 - y1)
                if dx >= lens_width * 0.18 and dy <= max(2, dx * 0.25):
                    eye_horizontal += dx
                elif dy >= lens_height * 0.18 and dx <= max(2, dy * 0.25):
                    eye_vertical += dy
            if (
                eye_horizontal < lens_width * 0.22
                or eye_vertical < lens_height * 0.22
            ):
                return False
            horizontal_length += eye_horizontal
            vertical_length += eye_vertical

        return horizontal_length > 0 and vertical_length > 0

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