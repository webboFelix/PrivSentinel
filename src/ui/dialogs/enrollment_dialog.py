"""Camera preview and explicitly consented local identity enrollment."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import numpy as np
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.identity.face_detector import ImageQuality
from src.identity.face_verifier import MODEL_NAME
from src.identity.workers import (
    CameraListWorker,
    CameraPreviewWorker,
    EmbeddingWorker,
)
from src.storage.repositories.identity_repository import IdentityRepository


class EnrollmentDialog(QDialog):
    enrollmentCompleted = Signal()

    def __init__(
        self,
        services: ApplicationServices,
        repository: IdentityRepository,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self.repository = repository
        self.setWindowTitle("Identity enrollment")
        self.setMinimumSize(680, 690)
        self._devices_worker: CameraListWorker | None = None
        self._preview_worker: CameraPreviewWorker | None = None
        self._embedding_worker: EmbeddingWorker | None = None
        self._last_frame: np.ndarray | None = None
        self._captured_frame: np.ndarray | None = None
        self._captured_embedding: np.ndarray | None = None
        self._captured_quality: ImageQuality | None = None
        self._last_faces = []
        self._last_quality: ImageQuality | None = None

        layout = QVBoxLayout(self)
        title = QLabel("Enroll your identity")
        title.setObjectName("sectionTitle")
        intro = QLabel(
            "Frames are processed locally and kept in memory only. The application "
            "stores an encrypted face embedding, not the captured photo."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(intro)

        self.preview = QLabel("Camera is off")
        self.preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview.setMinimumSize(480, 320)
        self.preview.setStyleSheet(
            "background:#061326;border:1px solid #163a60;border-radius:8px;"
        )
        layout.addWidget(self.preview, 1)

        camera_row = QHBoxLayout()
        self.camera_combo = QComboBox()
        self.camera_combo.setMinimumWidth(190)
        self.camera_combo.currentIndexChanged.connect(self._camera_changed)
        self.refresh_cameras_button = QPushButton("Find cameras")
        self.refresh_cameras_button.clicked.connect(self._find_cameras)
        self.start_preview_button = QPushButton("Start camera preview")
        self.start_preview_button.clicked.connect(self._start_preview)
        camera_row.addWidget(QLabel("Camera"))
        camera_row.addWidget(self.camera_combo, 1)
        camera_row.addWidget(self.refresh_cameras_button)
        camera_row.addWidget(self.start_preview_button)
        layout.addLayout(camera_row)

        identity_form = QFormLayout()
        self.display_name = QLineEdit()
        self.display_name.setPlaceholderText("Name for this local profile")
        identity_form.addRow("Identity name", self.display_name)
        layout.addLayout(identity_form)

        self.consent_checkbox = QCheckBox(
            "I consent to local encrypted face-template enrollment."
        )
        self.consent_checkbox.setToolTip(
            "I consent to creating and storing an encrypted face template on this device."
        )
        self.model_download_checkbox = QCheckBox(
            "Allow first-use download of the local recognition model (if needed)."
        )
        self.model_download_checkbox.setToolTip(
            "I explicitly allow downloading the InsightFace buffalo_l model to this "
            "device if needed. Camera images will not be uploaded."
        )
        model_path = (
            self.services.paths.models_directory / "models" / MODEL_NAME
        )
        self._model_download_consent_required = not model_path.is_dir()
        if not self._model_download_consent_required:
            self.model_download_checkbox.setChecked(True)
            self.model_download_checkbox.setEnabled(False)
            self.model_download_checkbox.setText(
                "Recognition model is already installed; no model download is needed."
            )
        self.confirm_image_checkbox = QCheckBox(
            "I confirm the captured image is mine and suitable for enrollment."
        )
        self.confirm_image_checkbox.setToolTip(
            "I confirm this captured image is mine and suitable for enrollment."
        )
        layout.addWidget(self.consent_checkbox)
        layout.addWidget(self.model_download_checkbox)
        layout.addWidget(self.confirm_image_checkbox)
        self.enrollment_requirements = QLabel()
        self.enrollment_requirements.setObjectName("muted")
        self.enrollment_requirements.setWordWrap(True)
        layout.addWidget(self.enrollment_requirements)

        buttons = QHBoxLayout()
        self.capture_button = QPushButton("Capture")
        self.capture_button.clicked.connect(self._capture)
        self.retake_button = QPushButton("Retake")
        self.retake_button.clicked.connect(self._retake)
        self.enroll_button = QPushButton("Confirm and enroll")
        self.enroll_button.setObjectName("primaryButton")
        self.enroll_button.clicked.connect(self._enroll)
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.reject)
        buttons.addWidget(self.capture_button)
        buttons.addWidget(self.retake_button)
        buttons.addWidget(self.enroll_button)
        buttons.addStretch(1)
        buttons.addWidget(self.close_button)
        layout.addLayout(buttons)
        self.status = QLabel(self._initial_status())
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.confirm_image_checkbox.stateChanged.connect(self._update_enroll_enabled)
        self.consent_checkbox.stateChanged.connect(self._update_enroll_enabled)
        self.model_download_checkbox.stateChanged.connect(self._update_enroll_enabled)
        self.display_name.textChanged.connect(self._update_enroll_enabled)
        self.capture_button.setEnabled(False)
        self.enroll_button.setEnabled(False)
        self.retake_button.setEnabled(False)
        self.camera_combo.addItem(
            f"Camera {services.settings.camera_index}",
            userData=services.settings.camera_index,
        )
        self._update_enroll_enabled()
        if services.settings.camera_access_enabled:
            QTimer.singleShot(0, self._find_cameras)

    def _find_cameras(self) -> None:
        if not self.services.settings.camera_access_enabled:
            self.status.setText(
                "Camera access is disabled. Enable it in Settings before searching "
                "for cameras."
            )
            return
        if self.services.identity_service.is_monitoring:
            self.status.setText(
                "Stop identity monitoring before starting the enrollment camera preview."
            )
            return
        if self._devices_worker is not None and self._devices_worker.isRunning():
            return
        self.status.setText("Searching for available cameras…")
        worker = CameraListWorker(self)
        self._devices_worker = worker
        worker.devicesReady.connect(self._camera_list_ready)
        worker.failed.connect(self._camera_list_failed)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _initial_status(self) -> str:
        if not self.services.settings.camera_access_enabled:
            return "Camera access is disabled in Settings. Enable it before enrollment."
        return (
            "Camera access is enabled in Settings. Camera discovery will start "
            "automatically. The recognition model may also need explicit download "
            "consent."
        )

    def _camera_list_ready(self, devices: list) -> None:
        selected = self.camera_combo.currentData()
        self.camera_combo.blockSignals(True)
        self.camera_combo.clear()
        for device in devices:
            self.camera_combo.addItem(device.label, userData=device.index)
        if not devices:
            fallback_index = (
                selected
                if selected is not None
                else self.services.settings.camera_index
            )
            self.camera_combo.addItem(
                f"Configured camera {fallback_index} (direct connection test)",
                userData=fallback_index,
            )
        if selected is not None:
            index = self.camera_combo.findData(selected)
            if index >= 0:
                self.camera_combo.setCurrentIndex(index)
        self.camera_combo.blockSignals(False)
        if devices:
            self.status.setText(
                f"Found {len(devices)} camera device(s); starting the selected preview."
            )
        else:
            self.status.setText(
                "No device was enumerated. Trying the configured camera directly "
                "because some Windows camera backends do not enumerate reliably."
            )
        self._start_preview()

    def _camera_list_failed(self, message: str) -> None:
        self.status.setText(
            f"Camera discovery failed ({message}). Trying the configured camera directly."
        )
        self.camera_combo.blockSignals(True)
        self.camera_combo.clear()
        index = self.services.settings.camera_index
        self.camera_combo.addItem(
            f"Configured camera {index} (direct connection test)",
            userData=index,
        )
        self.camera_combo.blockSignals(False)
        self._start_preview()

    def _camera_changed(self, _index: int) -> None:
        if self._preview_worker and self._preview_worker.isRunning():
            self._preview_worker.stop()
            self._preview_worker.finished.connect(self._start_preview)

    def _start_preview(self) -> None:
        if not self.services.settings.camera_access_enabled:
            self.status.setText(
                "Enable camera access in Settings before starting camera preview."
            )
            return
        if self.services.identity_service.is_monitoring:
            self.status.setText(
                "Stop identity monitoring before starting the enrollment camera preview."
            )
            return
        if self._preview_worker and self._preview_worker.isRunning():
            return
        camera_index = self.camera_combo.currentData()
        if camera_index is None:
            self.status.setText("No camera is selected.")
            return
        settings = self.services.settings
        worker = CameraPreviewWorker(
            int(camera_index),
            settings.camera_width,
            settings.camera_height,
            self,
            require_single_face=settings.require_single_face,
        )
        self._preview_worker = worker
        worker.previewReady.connect(self._show_preview)
        worker.cameraError.connect(self._camera_error)
        worker.finished.connect(self._preview_finished)
        self.start_preview_button.setEnabled(False)
        self.status.setText("Opening camera…")
        self.services.identity_service.set_camera_state(
            "connecting", "Opening the camera for identity enrollment."
        )
        worker.start()

    def _preview_finished(self) -> None:
        self.capture_button.setEnabled(False)
        self.start_preview_button.setEnabled(True)
        identity = self.services.identity_service
        if not identity.is_monitoring and identity.camera_state in {
            "connecting",
            "connected",
        }:
            identity.set_camera_state(
                "idle", "Enrollment camera session is not active."
            )

    def _show_preview(self, image, faces, frame, quality) -> None:
        self._last_frame = frame
        self._last_faces = faces
        self._last_quality = quality
        self.services.identity_service.set_camera_state(
            "connected", "Camera is open for identity enrollment."
        )
        self.capture_button.setEnabled(True)
        pixmap = QPixmap.fromImage(image)
        if self._captured_frame is None:
            painter = QPainter(pixmap)
            painter.setPen(QPen(Qt.GlobalColor.green, 3))
            for face in faces:
                painter.drawRect(
                    face.x,
                    face.y,
                    face.width,
                    face.height,
                )
            painter.end()
            self.preview.setPixmap(
                pixmap.scaled(
                    self.preview.size(),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        if len(faces) == 0:
            self.status.setText("No face detected. Center your face in the camera.")
        elif len(faces) > 1:
            self.status.setText(
                f"{len(faces)} faces detected. Enrollment requires one person."
            )
        else:
            self.status.setText(
                f"One face detected. {quality.detail}"
            )

    def _capture(self) -> None:
        if self._last_frame is None:
            self.status.setText("No camera frame is available to capture.")
            return
        quality = self._last_quality
        if quality is None:
            self.status.setText("Waiting for a face-quality check.")
            return
        if not quality.accepted:
            self._captured_frame = None
            self._captured_quality = quality
            self.confirm_image_checkbox.setChecked(False)
            self.enroll_button.setEnabled(False)
            self.retake_button.setEnabled(False)
            self.status.setText(quality.detail)
            return
        self._captured_frame = self._last_frame.copy()
        self._captured_embedding = None
        self._captured_quality = quality
        self.confirm_image_checkbox.setChecked(False)
        self.retake_button.setEnabled(True)
        self.enroll_button.setEnabled(False)
        pixmap = QPixmap.fromImage(self._image_for_frame(self._captured_frame))
        self.preview.setPixmap(
            pixmap.scaled(
                self.preview.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )
        self.status.setText(
            f"Capture accepted: {quality.detail} Review it, confirm the image and consent."
        )
        if self._preview_worker and self._preview_worker.isRunning():
            self._preview_worker.stop()
        self._update_enroll_enabled()
        if self._preview_worker and self._preview_worker.isRunning():
            self._preview_worker.stop()
            self._last_frame = None

    @staticmethod
    def _image_for_frame(frame: np.ndarray):
        from src.identity.workers import frame_to_image

        return frame_to_image(frame)

    def _update_enroll_enabled(self, *_args) -> None:
        requirements = []
        if not self.services.settings.camera_access_enabled:
            requirements.append("enable camera access in Settings")
        if self._captured_frame is None:
            requirements.append("capture an acceptable frame")
        if not self.confirm_image_checkbox.isChecked():
            requirements.append("confirm the captured image")
        if not self.display_name.text().strip():
            requirements.append("enter an identity name")
        if not self.consent_checkbox.isChecked():
            requirements.append("consent to local face-template enrollment")
        if (
            self._model_download_consent_required
            and not self.model_download_checkbox.isChecked()
        ):
            requirements.append("consent to download the local recognition model")
        self.enroll_button.setEnabled(not requirements)
        self.enroll_button.setToolTip(
            "Ready to enroll."
            if not requirements
            else "Complete these steps to enroll: " + "; ".join(requirements) + "."
        )
        self.enrollment_requirements.setText(
            "Ready to enroll."
            if not requirements
            else "To enable enrollment: " + "; ".join(requirements) + "."
        )

    def _retake(self) -> None:
        self._captured_frame = None
        self._captured_embedding = None
        self._captured_quality = None
        self.confirm_image_checkbox.setChecked(False)
        self.enroll_button.setEnabled(False)
        self.retake_button.setEnabled(False)
        self.status.setText("Capture cleared. Take a new image when ready.")
        self._last_frame = None
        if self._preview_worker and self._preview_worker.isRunning():
            self._preview_worker.finished.connect(self._start_preview)
            self._preview_worker.stop()
        else:
            self._start_preview()

    def _enroll(self) -> None:
        if not (
            self._captured_frame is not None
            and self.consent_checkbox.isChecked()
            and self.services.settings.camera_access_enabled
            and (
                not self._model_download_consent_required
                or self.model_download_checkbox.isChecked()
            )
            and self.confirm_image_checkbox.isChecked()
        ):
            self.status.setText("Capture confirmation, consent, and model consent are required.")
            return
        self.enroll_button.setEnabled(False)
        self.capture_button.setEnabled(False)
        self.status.setText("Preparing the local recognition model…")
        worker = EmbeddingWorker(
            self.services.paths.models_directory,
            self._captured_frame,
            self,
            allow_download=(
                self._model_download_consent_required
                and self.model_download_checkbox.isChecked()
            ),
            require_single_face=self.services.settings.require_single_face,
        )
        self._embedding_worker = worker
        worker.status.connect(self.status.setText)
        worker.completed.connect(self._embedding_ready)
        worker.failed.connect(self._enrollment_failed)
        worker.start()

    def _embedding_ready(self, embedding) -> None:
        try:
            self.repository.enroll(
                self.display_name.text(),
                embedding,
                MODEL_NAME,
                datetime.now(UTC),
            )
        except (OSError, TypeError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._enrollment_failed(str(exc))
            return
        self._captured_frame = None
        self._last_frame = None
        self.status.setText(
            "Identity enrolled. The photo was not saved; the template is encrypted."
        )
        self.enrollmentCompleted.emit()
        self.accept()

    def _enrollment_failed(self, message: str) -> None:
        self.status.setText(f"Enrollment failed: {message}")
        self.capture_button.setEnabled(self._last_frame is not None)
        QMessageBox.warning(self, "Identity enrollment failed", message)

    def _camera_error(self, message: str) -> None:
        self.status.setText(f"Camera unavailable: {message}")
        self.capture_button.setEnabled(False)
        self.services.identity_service.set_camera_state("unavailable", message)

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._preview_worker and self._preview_worker.isRunning():
            self._preview_worker.stop()
            self._preview_worker.wait(2000)
        if self._devices_worker and self._devices_worker.isRunning():
            self._devices_worker.wait(2000)
        if self._embedding_worker and self._embedding_worker.isRunning():
            event.ignore()
            self.status.setText(
                "Recognition setup is still running. Close after it finishes."
            )
            self.close_button.setEnabled(False)
            self._embedding_worker.finished.connect(
                lambda: self.close_button.setEnabled(True)
            )
            return
        self._captured_frame = None
        self._last_frame = None
        if not self.services.identity_service.is_monitoring:
            self.services.identity_service.set_camera_state(
                "idle" if self.services.settings.camera_access_enabled else "disabled",
                "Enrollment camera session is not active.",
            )
        super().closeEvent(event)
