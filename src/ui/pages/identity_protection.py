"""Live identity protection controls and enrollment status."""

import sqlite3
from dataclasses import replace

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.security.windows_auth import authenticate_windows_administrator
from src.storage.models import IdentityEvent
from src.ui.dialogs.administrator_confirmation_dialog import (
    AdministratorConfirmationDialog,
)


class IdentityProtectionPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)

    def __init__(
        self,
        services: ApplicationServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self.identity = services.identity_service
        self.setObjectName("page-identity-protection")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(14)
        title = QLabel("Identity Protection")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Local face verification. Camera use requires explicit enablement; "
            "captured frames are not saved."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        profile = QFrame()
        profile.setObjectName("panel")
        profile_layout = QVBoxLayout(profile)
        profile_layout.setContentsMargins(16, 14, 16, 14)
        section = QLabel("Enrolled identity")
        section.setObjectName("sectionTitle")
        self.profile_label = QLabel()
        self.profile_label.setObjectName("muted")
        self.profile_label.setWordWrap(True)
        profile_layout.addWidget(section)
        profile_layout.addWidget(self.profile_label)
        layout.addWidget(profile)

        controls = QHBoxLayout()
        self.enroll_button = QPushButton()
        self.enroll_button.setObjectName("primaryButton")
        self.enroll_button.clicked.connect(self._enroll_or_reenroll)
        self.monitor_button = QPushButton("Start monitoring")
        self.monitor_button.clicked.connect(self._toggle_monitoring)
        self.delete_button = QPushButton("Delete enrolled identity")
        self.delete_button.clicked.connect(self._delete_identity)
        history_button = QPushButton("View verification history")
        history_button.clicked.connect(
            lambda: self.pageRequested.emit("verification-history")
        )
        controls.addWidget(self.enroll_button)
        controls.addWidget(self.monitor_button)
        controls.addWidget(self.delete_button)
        controls.addWidget(history_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        details = QFrame()
        details.setObjectName("panel")
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(16, 14, 16, 14)
        details_heading = QLabel("Live verification status")
        details_heading.setObjectName("sectionTitle")
        self.camera_status = QLabel("Camera: off")
        self.camera_status.setObjectName("muted")
        self.verification_status = QLabel(self.identity.current_detail)
        self.verification_status.setWordWrap(True)
        self.last_success = QLabel("Last successful verification: —")
        self.last_success.setObjectName("muted")
        self.monitor_duration = QLabel("Monitoring duration: 0 seconds")
        self.monitor_duration.setObjectName("muted")
        self.failed_attempts = QLabel("Consecutive failed attempts: 0")
        self.failed_attempts.setObjectName("muted")
        self.liveness_status = QLabel(
            "Liveness: basic face-box motion heuristic (not anti-spoofing)"
        )
        self.liveness_status.setObjectName("muted")
        self.preview = QLabel("Live preview is off")
        self.preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview.setMinimumHeight(220)
        self.preview.setMaximumHeight(280)
        self.preview.setStyleSheet(
            "background:#061326;border:1px solid #163a60;border-radius:8px;"
        )
        details_layout.addWidget(self.preview)
        for widget in (
            details_heading,
            self.camera_status,
            self.verification_status,
            self.last_success,
            self.monitor_duration,
            self.failed_attempts,
            self.liveness_status,
        ):
            details_layout.addWidget(widget)
        layout.addWidget(details)

        recent = QPushButton("Refresh recent status")
        recent.clicked.connect(self._refresh)
        layout.addWidget(recent, 0)
        disclaimer = QLabel(
            "Motion checking is a basic presentation heuristic, not robust anti-spoofing. "
            "A camera failure is recorded as an availability issue and is never treated "
            "as proof of an attack."
        )
        disclaimer.setObjectName("muted")
        disclaimer.setWordWrap(True)
        layout.addWidget(disclaimer)
        layout.addStretch(1)

        self.identity.stateChanged.connect(self._on_state)
        self.identity.cameraStateChanged.connect(self._on_camera_state)
        self.identity.eventRecorded.connect(self._on_event)
        self.identity.profileChanged.connect(self._render_profile)
        self.identity.monitoringChanged.connect(self._on_monitoring_changed)
        self.identity.previewChanged.connect(self._on_preview)
        self._render_profile()
        self._on_camera_state(
            self.identity.camera_state, self.identity.camera_detail
        )
        self._on_monitoring_changed(self.identity.is_monitoring)
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(
            lambda: self._on_state(
                self.identity.current_state,
                self.identity.current_detail,
            )
        )
        self._status_timer.start(1000)

    def _render_profile(self) -> None:
        profile = self.identity.profile
        if profile is None:
            self.profile_label.setText("No identity is enrolled.")
            self.enroll_button.setText("Enroll")
            self.delete_button.setEnabled(False)
            self.monitor_button.setEnabled(False)
        else:
            self.profile_label.setText(
                f"{profile.display_name} · enrolled {profile.enrolled_at.astimezone().strftime('%Y-%m-%d %H:%M %Z')} · "
                f"{profile.model_name} ({profile.template_dimensions}-dimensional encrypted template)"
            )
            self.enroll_button.setText("Re-enroll")
            self.delete_button.setEnabled(True)
            self.monitor_button.setEnabled(
                self.services.settings.camera_access_enabled
            )

    def _toggle_monitoring(self) -> None:
        if self.identity.is_monitoring:
            updated = replace(
                self.services.settings,
                identity_monitoring_enabled=False,
                start_monitoring_on_launch=False,
            )
            try:
                self.services.save_settings(updated)
                self.identity.stop_monitoring()
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                QMessageBox.critical(self, "Could not stop monitoring", str(exc))
            return
        if self.identity.profile is None:
            QMessageBox.information(
                self, "Enrollment required", "Enroll an identity before monitoring."
            )
            return
        if not self.services.settings.camera_access_enabled:
            result = QMessageBox.question(
                self,
                "Enable camera access",
                "Allow continuous camera access for local identity verification?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if result != QMessageBox.StandardButton.Yes:
                return
            try:
                self.services.save_settings(
                    replace(
                        self.services.settings,
                        camera_access_enabled=True,
                        identity_monitoring_enabled=True,
                    )
                )
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                QMessageBox.critical(self, "Could not enable monitoring", str(exc))
                return
        try:
            if not self.services.settings.identity_monitoring_enabled:
                self.services.save_settings(
                    replace(
                        self.services.settings,
                        identity_monitoring_enabled=True,
                    )
                )
            self.identity.start_monitoring()
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            QMessageBox.critical(self, "Could not start monitoring", str(exc))

    def _delete_identity(self) -> None:
        self._remove_identity(start_enrollment=False)

    def _enroll_or_reenroll(self) -> None:
        if self.identity.profile is None:
            self.actionRequested.emit("identity-enrollment")
            return
        self._remove_identity(start_enrollment=True)

    def _remove_identity(self, start_enrollment: bool) -> None:
        action = "re-enroll" if start_enrollment else "delete the enrolled identity"
        dialog = AdministratorConfirmationDialog(
            f"Confirm {action}",
            "This permanently removes the encrypted face templates and identity "
            "profile details. Verification and enrollment history will be retained. "
            "Camera frames are not stored. Enter credentials for a Windows "
            "administrator account to continue.",
            "Verify and continue",
            self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            dialog.clear_password()
            return

        username, password = dialog.credentials()
        try:
            authorized = authenticate_windows_administrator(username, password)
        except OSError as exc:
            QMessageBox.critical(
                self,
                "Could not verify administrator credentials",
                str(exc),
            )
            return
        finally:
            dialog.clear_password()

        if not authorized:
            QMessageBox.warning(
                self,
                "Administrator verification failed",
                "The credentials are invalid or the account is not a Windows "
                "administrator. The identity was not changed.",
            )
            return

        try:
            if self.identity.is_monitoring:
                self.services.save_settings(
                    replace(
                        self.services.settings,
                        identity_monitoring_enabled=False,
                        start_monitoring_on_launch=False,
                    )
                )
                self.identity.stop_monitoring()
                if self.identity.is_monitoring:
                    raise RuntimeError(
                        "Identity monitoring is still shutting down; no identity "
                        "data was removed."
                    )
            if not self.identity.delete_profile():
                raise RuntimeError(
                    "The enrolled identity could not be removed; no new enrollment "
                    "was started."
                )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            QMessageBox.critical(self, "Could not remove identity", str(exc))
            return

        if start_enrollment:
            self.actionRequested.emit("identity-enrollment")

    def _refresh(self) -> None:
        self._render_profile()
        self._on_state(self.identity.current_state, self.identity.current_detail)

    def _on_state(self, state: str, detail: str) -> None:
        self.verification_status.setText(f"{state.replace('_', ' ').title()}: {detail}")
        self.monitor_duration.setText(
            f"Monitoring duration: {self.identity.monitoring_seconds:.0f} seconds"
        )
        self.failed_attempts.setText(
            f"Consecutive failed attempts: {self.identity.failed_attempts}"
        )
        if self.identity.last_recorded is not None:
            self.liveness_status.setText(
                "Liveness: "
                f"{self.identity.last_recorded.liveness.replace('_', ' ')} "
                "(basic heuristic only)"
            )
        if self.identity.is_monitoring:
            self.failed_attempts.setText(
                f"Consecutive failed attempts: {self.identity.failed_attempts}"
            )

    def _on_event(self, event: IdentityEvent) -> None:
        if event.state == "recognized":
            self.last_success.setText(
                f"Last successful verification: "
                f"{event.occurred_at.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} "
                f"({event.confidence:.1%})"
            )
        self._on_state(event.state, event.detail)

    def _on_monitoring_changed(self, running: bool) -> None:
        self.monitor_button.setText("Stop monitoring" if running else "Start monitoring")
        if running and self.identity.camera_state == "idle":
            self._on_camera_state("connecting", "Opening the selected camera.")
        self.monitor_button.setEnabled(
            self.identity.profile is not None
        )
        self._render_profile()

    def _on_camera_state(self, state: str, detail: str) -> None:
        labels = {
            "disabled": "Camera: off · access disabled",
            "idle": "Camera permission enabled · camera idle",
            "connecting": "Camera: connecting",
            "connected": "Camera: connected",
            "unavailable": "Camera: unavailable",
        }
        self.camera_status.setText(labels.get(state, "Camera: status unknown"))
        self.camera_status.setToolTip(
            f"{detail} Camera access permission does not open the camera by itself; "
            f"select {self.enroll_button.text()} to start the enrollment camera session."
            if state == "idle"
            else detail
        )

    def _on_preview(self, image) -> None:
        self.preview.setPixmap(
            QPixmap.fromImage(image).scaled(
                self.preview.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )
