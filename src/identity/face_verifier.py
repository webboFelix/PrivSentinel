"""Offline InsightFace model access and normalized embedding comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np


MODEL_NAME = "buffalo_l"


@dataclass(frozen=True, slots=True)
class FaceObservation:
    embedding: np.ndarray
    bounding_box: tuple[int, int, int, int]
    landmarks: np.ndarray


class RecognitionModelUnavailable(RuntimeError):
    pass


class FaceRecognitionEngine:
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