"""Offline InsightFace model access and normalized embedding comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cv2
import numpy as np

MODEL_NAME = "buffalo_l"


@dataclass(frozen=True, slots=True)
class FaceObservation:
    embedding: np.ndarray
    bounding_box: tuple[int, int, int, int]
    landmarks: np.ndarray


@dataclass(frozen=True, slots=True)
class HeadPose:
    yaw_degrees: float
    pitch_degrees: float


class RecognitionModelUnavailable(RuntimeError):
    pass


class FaceRecognitionEngine:
    _FACE_MODEL_POINTS = np.asarray(
        [
            (-30.0, 32.0, 30.0),
            (30.0, 32.0, 30.0),
            (0.0, 0.0, 0.0),
            (-25.0, -28.0, 25.0),
            (25.0, -28.0, 25.0),
        ],
        dtype=np.float32,
    )

    def __init__(
        self,
        models_directory: str | Path,
        model_name: str = MODEL_NAME,
        allow_download: bool = False,
    ) -> None:
        self.models_directory = Path(models_directory)
        self.model_name = model_name
        self.allow_download = allow_download
        self._analysis: Any | None = None

    def load(self) -> None:
        if self._analysis is not None:
            return
        model_directory = self.models_directory / "models" / self.model_name
        if not self.allow_download and not model_directory.is_dir():
            raise RecognitionModelUnavailable(
                f"Recognition model '{self.model_name}' is not installed. "
                "Select the explicit model-download consent option to continue."
            )
        try:
            from insightface.app import FaceAnalysis

            analysis = FaceAnalysis(
                name=self.model_name,
                root=str(self.models_directory),
                allowed_modules=["detection", "recognition"],
            )
            analysis.prepare(ctx_id=-1, det_size=(640, 640))
        except Exception as exc:
            raise RecognitionModelUnavailable(
                f"Could not initialize recognition model '{self.model_name}': {exc}"
            ) from exc
        self._analysis = analysis

    def embeddings(self, frame: np.ndarray) -> list[np.ndarray]:
        return [observation.embedding for observation in self.analyze(frame)]

    @staticmethod
    def aggregate_embeddings(
        embeddings: list[np.ndarray],
    ) -> tuple[np.ndarray, float]:
        if not embeddings:
            raise ValueError("At least one face embedding is required.")
        vectors = [np.asarray(embedding, dtype=np.float32) for embedding in embeddings]
        shape = vectors[0].shape
        if any(
            vector.ndim != 1
            or vector.shape != shape
            or not np.isfinite(vector).all()
            or np.linalg.norm(vector) == 0
            for vector in vectors
        ):
            raise ValueError("Face embeddings must be finite, non-zero vectors of equal size.")
        normalized = np.stack(
            [vector / np.linalg.norm(vector) for vector in vectors]
        )
        template = normalized.mean(axis=0)
        template_norm = float(np.linalg.norm(template))
        if template_norm == 0:
            raise ValueError("Face samples do not produce a usable template.")
        template /= template_norm
        consistency = float(np.mean(np.clip(normalized @ template, -1.0, 1.0)))
        return template.astype(np.float32, copy=False), consistency

    def analyze(self, frame: np.ndarray) -> list[FaceObservation]:
        self.load()
        assert self._analysis is not None
        try:
            faces = self._analysis.get(frame, max_num=0)
        except Exception as exc:
            raise RuntimeError(f"Face recognition failed: {exc}") from exc
        observations: list[FaceObservation] = []
        for face in faces:
            vector = getattr(face, "normed_embedding", None)
            if vector is None:
                vector = getattr(face, "embedding", None)
            if vector is None:
                continue
            vector = np.asarray(vector, dtype=np.float32)
            if vector.ndim != 1 or vector.size < 32 or not np.isfinite(vector).all():
                continue
            norm = float(np.linalg.norm(vector))
            if norm > 0:
                bbox = np.asarray(face.bbox, dtype=np.int32).reshape(-1)
                if bbox.size != 4:
                    continue
                points = np.asarray(
                    getattr(face, "kps", np.empty((0, 2))), dtype=np.float32
                )
                observations.append(
                    FaceObservation(
                        embedding=vector / norm,
                        bounding_box=tuple(int(value) for value in bbox),
                        landmarks=points,
                    )
                )
        return observations

    @classmethod
    def estimate_head_pose(
        cls,
        landmarks: np.ndarray,
        frame_width: int,
        frame_height: int,
    ) -> HeadPose:
        points = np.asarray(landmarks, dtype=np.float32)
        if points.shape != (5, 2) or not np.isfinite(points).all():
            raise ValueError("Head pose estimation requires five valid face landmarks.")
        if frame_width < 1 or frame_height < 1:
            raise ValueError("Frame dimensions must be positive.")

        focal_length = float(max(frame_width, frame_height))
        camera_matrix = np.asarray(
            [
                [focal_length, 0.0, frame_width / 2],
                [0.0, focal_length, frame_height / 2],
                [0.0, 0.0, 1.0],
            ],
            dtype=np.float32,
        )
        solved, rotation_vector, _translation = cv2.solvePnP(
            cls._FACE_MODEL_POINTS,
            points,
            camera_matrix,
            np.zeros((4, 1), dtype=np.float32),
            flags=cv2.SOLVEPNP_EPNP,
        )
        if not solved:
            raise ValueError("Could not estimate face direction from landmarks.")
        rotation_matrix, _ = cv2.Rodrigues(rotation_vector)
        angles = cv2.RQDecomp3x3(rotation_matrix)[0]
        return HeadPose(yaw_degrees=float(angles[1]), pitch_degrees=float(angles[0]))

    @staticmethod
    def similarity(first: np.ndarray, second: np.ndarray) -> float:
        left = np.asarray(first, dtype=np.float32)
        right = np.asarray(second, dtype=np.float32)
        if left.shape != right.shape or left.ndim != 1:
            raise ValueError("Face templates have incompatible dimensions.")
        left_norm = float(np.linalg.norm(left))
        right_norm = float(np.linalg.norm(right))
        if left_norm == 0 or right_norm == 0:
            raise ValueError("Cannot compare an empty face template.")
        return float(np.clip(np.dot(left, right) / (left_norm * right_norm), -1.0, 1.0))