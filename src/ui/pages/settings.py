"""Local application preferences page."""

import sqlite3
from dataclasses import replace
from datetime import datetime

from PySide6.QtCore import QEvent, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.config.settings import AppSettings
from src.endpoint.integrity_baseline import effective_file_integrity_exclusions
from src.ui.components.status_indicator import StatusIndicator
from src.ui.dialogs.administrator_confirmation_dialog import (
    confirm_windows_administrator,
)
from src.ui.dialogs.confirmation_dialog import ConfirmationDialog
from src.ui.icon_assets import icon_path


class SettingsPage(QWidget):
    actionRequested = Signal(str)

    def __init__(self, services: ApplicationServices, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("page-settings")
        self.services = services
        self._file_integrity_enable_pending = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(14)
        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Manage persistent local settings, logs, and configuration backups.")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        preferences = QFrame()
        preferences.setObjectName("panel")
        form = QFormLayout(preferences)
        form.setContentsMargins(18, 16, 18, 16)
        form.setSpacing(12)
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level_combo.setCurrentText(services.settings.log_level)
        form.addRow("Application log level", self.log_level_combo)
        self.retention_days = QSpinBox()
        self.retention_days.setRange(1, 3650)
        self.retention_days.setSuffix(" days")
        self.retention_days.setValue(services.settings.log_retention_days)
        form.addRow("Log retention", self.retention_days)
        self.file_logging = QCheckBox("Write application logs to the local logs folder")
        self.file_logging.setChecked(services.settings.file_logging_enabled)
        form.addRow("File logging", self.file_logging)
        self.backup_before_save = QCheckBox("Create a backup before each settings change")
        self.backup_before_save.setChecked(services.settings.backup_before_save)
        form.addRow("Automatic backup", self.backup_before_save)
        layout.addWidget(preferences)

        identity_panel = QFrame()
        identity_panel.setObjectName("panel")
        identity_form = QFormLayout(identity_panel)
        identity_form.setContentsMargins(18, 16, 18, 16)
        identity_form.setSpacing(10)
        identity_heading = QLabel("Identity and camera privacy")
        identity_heading.setObjectName("sectionTitle")
        identity_form.addRow(identity_heading)
        self.camera_access = QCheckBox("Allow this app to access a camera")
        self.camera_access.setChecked(services.settings.camera_access_enabled)
        identity_form.addRow("Camera access", self.camera_access)
        self.camera_device = QSpinBox()
        self.camera_device.setRange(0, 31)
        self.camera_device.setPrefix("Camera ")
        self.camera_device.setValue(services.settings.camera_index)
        identity_form.addRow("Camera device index", self.camera_device)
        self.identity_monitoring = QCheckBox("Enable continuous identity monitoring")
        self.identity_monitoring.setChecked(services.settings.identity_monitoring_enabled)
        identity_form.addRow("Monitoring", self.identity_monitoring)
        self.start_monitoring = QCheckBox("Start monitoring automatically on application launch")
        self.start_monitoring.setChecked(services.settings.start_monitoring_on_launch)
        identity_form.addRow("Startup", self.start_monitoring)
        self.camera_reconnect = QSpinBox()
        self.camera_reconnect.setRange(1, 60)
        self.camera_reconnect.setSuffix(" seconds")
        self.camera_reconnect.setValue(services.settings.camera_reconnect_seconds)
        identity_form.addRow("Camera reconnection delay", self.camera_reconnect)
        self.camera_failure_action = QComboBox()
        self.camera_failure_action.addItem("Notify and retry (never lock)", "notify_only")
        self.camera_failure_action.addItem(
            "Notify and stop monitoring (never lock)",
            "notify_and_stop_monitoring",
        )
        self.camera_failure_action.setCurrentIndex(
            self.camera_failure_action.findData(services.settings.camera_failure_action)
        )
        identity_form.addRow("Camera failure response", self.camera_failure_action)
        self.multiple_face_policy = QComboBox()
        self.multiple_face_policy.addItem("Pause verification and notify", "pause_and_notify")
        self.multiple_face_policy.addItem("Stop monitoring", "stop_monitoring")
        self.multiple_face_policy.setCurrentIndex(
            self.multiple_face_policy.findData(services.settings.multiple_face_policy)
        )
        identity_form.addRow("Multiple-face response", self.multiple_face_policy)
        self.camera_width = QComboBox()
        self.camera_width.addItems(["320", "640", "800", "1280", "1920", "3840"])
        self.camera_width.setCurrentText(str(services.settings.camera_width))
        identity_form.addRow("Capture width (pixels)", self.camera_width)
        self.camera_height = QComboBox()
        self.camera_height.addItems(["240", "480", "600", "720", "1080", "2160"])
        self.camera_height.setCurrentText(str(services.settings.camera_height))
        identity_form.addRow("Capture height (pixels)", self.camera_height)
        self.capture_interval = QSpinBox()
        self.capture_interval.setRange(250, 10000)
        self.capture_interval.setSingleStep(250)
        self.capture_interval.setSuffix(" ms")
        self.capture_interval.setValue(services.settings.capture_interval_ms)
        identity_form.addRow("Frame-processing interval", self.capture_interval)
        self.verification_threshold = QDoubleSpinBox()
        self.verification_threshold.setRange(0.05, 0.99)
        self.verification_threshold.setSingleStep(0.01)
        self.verification_threshold.setDecimals(2)
        self.verification_threshold.setValue(services.settings.verification_threshold)
        identity_form.addRow("Recognition similarity threshold", self.verification_threshold)
        self.verification_cooldown = QSpinBox()
        self.verification_cooldown.setRange(0, 3600)
        self.verification_cooldown.setSuffix(" seconds")
        self.verification_cooldown.setValue(services.settings.verification_cooldown_seconds)
        identity_form.addRow("Verification event cooldown", self.verification_cooldown)
        self.liveness_enabled = QCheckBox(
            "Enable basic face-box motion heuristic (not anti-spoofing)"
        )
        self.liveness_enabled.setChecked(services.settings.liveness_enabled)
        identity_form.addRow("Basic liveness", self.liveness_enabled)
        self.require_single_face = QCheckBox("Require exactly one face during enrollment")
        self.require_single_face.setChecked(services.settings.require_single_face)
        identity_form.addRow("Enrollment face policy", self.require_single_face)
        self.identity_retention = QSpinBox()
        self.identity_retention.setRange(1, 3650)
        self.identity_retention.setSuffix(" days")
        self.identity_retention.setValue(services.settings.identity_event_retention_days)
        identity_form.addRow("Verification history retention", self.identity_retention)
        self.unknown_face_action = QComboBox()
        self.unknown_face_action.addItem("Notify only (default)", "notify_only")
        self.unknown_face_action.addItem("Warn, then lock after grace period", "lock_after_grace")
        self.unknown_face_action.setCurrentIndex(
            self.unknown_face_action.findData(services.settings.unknown_face_action)
        )
        identity_form.addRow("Repeated unknown-face response", self.unknown_face_action)
        self.presence_loss_action = QComboBox()
        self.presence_loss_action.addItem("Notify only (default)", "notify_only")
        self.presence_loss_action.addItem("Warn, then lock after grace period", "lock_after_grace")
        self.presence_loss_action.setCurrentIndex(
            self.presence_loss_action.findData(services.settings.presence_loss_action)
        )
        identity_form.addRow("No face detected response", self.presence_loss_action)
        self.failure_limit = QSpinBox()
        self.failure_limit.setRange(1, 100)
        self.failure_limit.setValue(services.settings.identity_failure_limit)
        identity_form.addRow("Consecutive failures before warning", self.failure_limit)
        self.automatic_lock = QCheckBox(
            "Opt in to automatic workstation lock after an identity warning"
        )
        self.automatic_lock.setChecked(services.settings.automatic_lock_enabled)
        identity_form.addRow("Automatic lock", self.automatic_lock)
        self.lock_grace = QSpinBox()
        self.lock_grace.setRange(5, 3600)
        self.lock_grace.setSuffix(" seconds")
        self.lock_grace.setValue(services.settings.lock_grace_period_seconds)
        identity_form.addRow("Lock warning grace period", self.lock_grace)
        self.identity_notifications = QCheckBox("Show identity security notifications")
        self.identity_notifications.setToolTip(
            "Basic liveness heuristic results remain in verification history and "
            "the Identity Protection status, but do not generate repeated system "
            "notifications."
        )
        self.identity_notifications.setChecked(services.settings.identity_notifications_enabled)
        identity_form.addRow("Notifications", self.identity_notifications)
        lock_notice = QLabel(
            "Automatic locking is disabled by default. Choose whether repeated unknown "
            "faces, an absent face, or both trigger a warning and lock. Camera failure "
            "never triggers a lock."
        )
        lock_notice.setObjectName("muted")
        lock_notice.setWordWrap(True)
        identity_form.addRow(lock_notice)
        layout.addWidget(identity_panel)

        endpoint_panel = QFrame()
        endpoint_panel.setObjectName("panel")
        endpoint_form = QFormLayout(endpoint_panel)
        endpoint_form.setContentsMargins(18, 16, 18, 16)
        endpoint_form.setSpacing(10)
        endpoint_heading = QLabel("Endpoint monitoring")
        endpoint_heading.setObjectName("sectionTitle")
        endpoint_form.addRow(endpoint_heading)
        self.endpoint_interval = QSpinBox()
        self.endpoint_interval.setRange(1, 3600)
        self.endpoint_interval.setSuffix(" seconds")
        self.endpoint_interval.setValue(services.settings.endpoint_poll_interval_seconds)
        endpoint_form.addRow("Polling interval", self.endpoint_interval)
        self.process_monitoring = QCheckBox("Enable process start monitoring")
        self.process_monitoring.setChecked(services.settings.process_monitoring_enabled)
        endpoint_form.addRow("Processes", self.process_monitoring)
        self.process_exclusions = QPlainTextEdit()
        self.process_exclusions.setPlaceholderText(
            "Excluded process names or paths, one wildcard pattern per line"
        )
        self.process_exclusions.setMaximumHeight(72)
        self.process_exclusions.setPlainText("\n".join(services.settings.process_exclusions))
        endpoint_form.addRow("Process exclusions", self.process_exclusions)
        self.network_monitoring = QCheckBox("Enable network connection metadata collection")
        self.network_monitoring.setChecked(services.settings.network_monitoring_enabled)
        endpoint_form.addRow("Network", self.network_monitoring)
        self.windows_log_monitoring = QCheckBox(
            "Enable Windows System and Application event log collection"
        )
        self.windows_log_monitoring.setChecked(services.settings.windows_log_collection_enabled)
        endpoint_form.addRow("Windows logs", self.windows_log_monitoring)
        self.file_integrity_monitoring = QCheckBox(
            "Enable file-integrity monitoring (requires a baseline)"
        )
        self.file_integrity_monitoring.setChecked(
            services.settings.file_integrity_monitoring_enabled
        )
        self.file_integrity_baseline_button = QPushButton("Create baseline…")
        self.file_integrity_baseline_button.setIcon(QIcon(icon_path("radar-scan.png")))
        self.file_integrity_baseline_button.clicked.connect(self._open_file_integrity_page)
        integrity_monitoring_row = QHBoxLayout()
        integrity_monitoring_row.addWidget(self.file_integrity_monitoring)
        integrity_monitoring_row.addWidget(self.file_integrity_baseline_button)
        integrity_monitoring_row.addStretch(1)
        endpoint_form.addRow("File integrity", integrity_monitoring_row)
        self.file_integrity_roots = QPlainTextEdit()
        self.file_integrity_roots.setPlaceholderText(
            "Monitored directories, one absolute path per line"
        )
        self.file_integrity_roots.setMaximumHeight(76)
        self.file_integrity_roots.setPlainText("\n".join(services.settings.file_integrity_roots))
        add_root = QPushButton("Add folder…")
        add_root.clicked.connect(self._add_integrity_root)
        roots_layout = QVBoxLayout()
        roots_layout.addWidget(self.file_integrity_roots)
        roots_layout.addWidget(add_root, 0)
        endpoint_form.addRow("Integrity roots", roots_layout)
        automatic_exclusions = QLabel(
            "Temporary, cache, dependency, and virtual-environment folders are excluded "
            "automatically from file-integrity monitoring."
        )
        automatic_exclusions.setObjectName("muted")
        automatic_exclusions.setWordWrap(True)
        endpoint_form.addRow("Automatic integrity exclusions", automatic_exclusions)
        self.event_retention = QSpinBox()
        self.event_retention.setRange(1, 3650)
        self.event_retention.setSuffix(" days")
        self.event_retention.setValue(services.settings.event_retention_days)
        endpoint_form.addRow("Security event retention", self.event_retention)
        note = QLabel(
            "All collectors are off by default. Process and network collectors "
            "read metadata only. File monitoring hashes selected files; Windows "
            "logs may contain local account or application details."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        endpoint_form.addRow(note)
        layout.addWidget(endpoint_panel)

        storage = QFrame()
        storage.setObjectName("panel")
        storage_layout = QVBoxLayout(storage)
        storage_layout.setContentsMargins(18, 16, 18, 16)
        storage_heading = QLabel("Local application data")
        storage_heading.setObjectName("sectionTitle")
        self.storage_path = QLabel(str(services.paths.root))
        self.storage_path.setObjectName("muted")
        self.storage_path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        folder_button = QPushButton("Open data folder")
        folder_button.clicked.connect(self._open_data_folder)
        storage_layout.addWidget(storage_heading)
        storage_layout.addWidget(self.storage_path)
        storage_layout.addWidget(folder_button, 0)
        layout.addWidget(storage)

        actions = QHBoxLayout()
        self.save_button = QPushButton("Save settings")
        self.save_button.setObjectName("primaryButton")
        self.save_button.clicked.connect(self._save)
        self.backup_button = QPushButton("Back up settings")
        self.backup_button.clicked.connect(self._backup)
        self.restore_button = QPushButton("Restore backup")
        self.restore_button.clicked.connect(self._restore)
        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self._reset)
        actions.addWidget(self.save_button)
        actions.addWidget(self.backup_button)
        actions.addWidget(self.restore_button)
        actions.addWidget(self.reset_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.status = StatusIndicator("Preferences have not been saved")
        self.status.text_label.setWordWrap(True)
        layout.addWidget(self.status)
        note = QLabel(
            "Settings are validated and saved to settings.json. Secret key material "
            "is stored separately with Windows DPAPI and is never written to that file."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)

    def showEvent(self, event: QEvent) -> None:
        super().showEvent(event)
        self._show_settings(self.services.settings)

    def _open_file_integrity_page(self) -> None:
        window = self.window()
        if window is None or not hasattr(window, "navigate_to"):
            self._file_integrity_enable_pending = False
            self.file_integrity_monitoring.setChecked(False)
            self.status.set_text(
                "Could not open File Integrity Monitoring. Monitoring remains off."
            )
            self.status.set_state("error")
            return
        file_page = getattr(window, "_pages", {}).get("file-integrity")
        if file_page is None:
            self._file_integrity_enable_pending = False
            self.file_integrity_monitoring.setChecked(False)
            self.status.set_text(
                "File Integrity Monitoring is unavailable. Monitoring remains off."
            )
            self.status.set_state("error")
            return
        window.navigate_to("file-integrity")
        file_page.roots.setPlainText(self.file_integrity_roots.toPlainText())
        resume_monitoring = self.file_integrity_monitoring.isChecked()
        file_page.enabled.setChecked(resume_monitoring)
        file_page.enabled.setText(
            "Disable monitoring" if resume_monitoring else "Enable monitoring"
        )
        file_page.start_baseline()

    def _on_file_integrity_baseline_finished(self, succeeded: bool, message: str) -> None:
        if not self._file_integrity_enable_pending:
            return
        self._file_integrity_enable_pending = False
        monitoring_enabled = succeeded and self.services.settings.file_integrity_monitoring_enabled
        self.file_integrity_monitoring.setChecked(monitoring_enabled)
        if monitoring_enabled:
            self.status.set_text(message)
            self.status.set_state("success")
            return
        detail = message if not succeeded else "The baseline is ready, but monitoring remains off."
        self.status.set_text(f"Could not enable file-integrity monitoring: {detail}")
        self.status.set_state("error")

    def _warn_missing_baseline(self) -> None:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Current file baseline required")
        dialog.setIcon(QMessageBox.Warning)
        dialog.setText(
            "Create or refresh the file-integrity baseline for the selected folders "
            "before enabling monitoring."
        )
        create_button = dialog.addButton("Create baseline", QMessageBox.ActionRole)
        dialog.addButton(QMessageBox.StandardButton.Cancel)
        dialog.exec()
        if dialog.clickedButton() is create_button:
            self._open_file_integrity_page()
        else:
            self._file_integrity_enable_pending = False
            self.file_integrity_monitoring.setChecked(False)
            self.status.set_text(
                "Settings saved. File-integrity monitoring remains off until you create a baseline."
            )
            self.status.set_state("warning")

    def _save(self) -> None:
        if self.start_monitoring.isChecked() and not self.identity_monitoring.isChecked():
            QMessageBox.warning(
                self,
                "Monitoring preference required",
                "Enable continuous identity monitoring to start it on launch.",
            )
            return
        if self.identity_monitoring.isChecked() and not self.camera_access.isChecked():
            QMessageBox.warning(
                self,
                "Camera access required",
                "Enable camera access to enable continuous identity monitoring.",
            )
            return
        roots = tuple(
            line.strip()
            for line in self.file_integrity_roots.toPlainText().splitlines()
            if line.strip()
        )
        exclusions = effective_file_integrity_exclusions(
            self.services.settings.file_integrity_exclusions
        )
        monitoring_requested = self.file_integrity_monitoring.isChecked()
        missing_integrity_roots = monitoring_requested and not roots
        try:
            needs_baseline = monitoring_requested and bool(roots) and (
                not self.services.endpoint_service.has_file_baseline(roots, exclusions)
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._show_error("Could not verify the file-integrity baseline", exc)
            return
        if self.automatic_lock.isChecked():
            lock_conditions = []
            if self.unknown_face_action.currentData() == "lock_after_grace":
                lock_conditions.append("repeated unknown-face failures")
            if self.presence_loss_action.currentData() == "lock_after_grace":
                lock_conditions.append("the enrolled face remains undetected")
            if not lock_conditions:
                QMessageBox.warning(
                    self,
                    "Choose a locking response",
                    "Select a warn-then-lock response for unknown faces or no-face "
                    "detection before opting into automatic workstation locking.",
                )
                return
            trigger_text = " or ".join(lock_conditions)
            confirmation = QMessageBox.warning(
                self,
                "Confirm automatic workstation locking",
                "When the configured failure threshold is reached for "
                f"{trigger_text}, the workstation will lock after a "
                f"{self.lock_grace.value()}-second warning. Verification of the "
                "enrolled identity dismisses the warning; camera failure never "
                "causes a lock. Enable this behavior?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if confirmation != QMessageBox.StandardButton.Yes:
                return
        if not self.identity_monitoring.isChecked() and not self._confirm_monitoring_admin(
            "disable continuous identity monitoring"
        ):
            return
        settings = replace(
            self.services.settings,
            log_level=self.log_level_combo.currentText(),
            log_retention_days=self.retention_days.value(),
            file_logging_enabled=self.file_logging.isChecked(),
            backup_before_save=self.backup_before_save.isChecked(),
            camera_index=self.camera_device.value(),
            camera_reconnect_seconds=self.camera_reconnect.value(),
            camera_failure_action=self.camera_failure_action.currentData(),
            multiple_face_policy=self.multiple_face_policy.currentData(),
            camera_width=int(self.camera_width.currentText()),
            camera_height=int(self.camera_height.currentText()),
            capture_interval_ms=self.capture_interval.value(),
            verification_threshold=self.verification_threshold.value(),
            verification_cooldown_seconds=self.verification_cooldown.value(),
            liveness_enabled=self.liveness_enabled.isChecked(),
            require_single_face=self.require_single_face.isChecked(),
            identity_event_retention_days=self.identity_retention.value(),
            unknown_face_action=self.unknown_face_action.currentData(),
            presence_loss_action=self.presence_loss_action.currentData(),
            identity_failure_limit=self.failure_limit.value(),
            automatic_lock_enabled=self.automatic_lock.isChecked(),
            lock_grace_period_seconds=self.lock_grace.value(),
            camera_access_enabled=self.camera_access.isChecked(),
            identity_monitoring_enabled=self.identity_monitoring.isChecked(),
            start_monitoring_on_launch=self.start_monitoring.isChecked(),
            identity_notifications_enabled=self.identity_notifications.isChecked(),
            endpoint_poll_interval_seconds=self.endpoint_interval.value(),
            process_monitoring_enabled=self.process_monitoring.isChecked(),
            network_monitoring_enabled=self.network_monitoring.isChecked(),
            file_integrity_monitoring_enabled=(
                self.file_integrity_monitoring.isChecked() and not needs_baseline
            ),
            windows_log_collection_enabled=self.windows_log_monitoring.isChecked(),
            event_retention_days=self.event_retention.value(),
            process_exclusions=self._lines(self.process_exclusions),
            file_integrity_roots=roots,
            file_integrity_exclusions=exclusions,
        )
        try:
            self.services.save_settings(settings)
        except (OSError, ValueError) as exc:
            self._show_error("Could not save settings", exc)
            return
        if needs_baseline:
            self.status.set_text(
                "Other settings were saved. File-integrity monitoring is off until "
                "a current baseline is created."
            )
            self.status.set_state("warning")
            self._file_integrity_enable_pending = True
            self._warn_missing_baseline()
            return
        self._file_integrity_enable_pending = False
        if missing_integrity_roots:
            self.file_integrity_monitoring.setChecked(False)
            message = (
                "Settings saved. File-integrity monitoring remains off until you "
                "choose at least one protected folder."
            )
            self.status.set_text(message)
            self.status.set_state("warning")
        elif settings.file_integrity_monitoring_enabled:
            message = (
                "Settings saved; file-integrity monitoring is enabled with a current baseline."
            )
        elif self.file_integrity_monitoring.isChecked():
            message = (
                "Settings saved; file-integrity monitoring remains off until a "
                "current baseline is created."
            )
        else:
            message = "Settings saved successfully."
        self.status.set_text(message)
        self.status.set_state("success")

    def _reset(self) -> None:
        if not ConfirmationDialog.confirm(
            self, "Reset settings", "Restore all application settings to safe defaults?"
        ):
            return
        if (
            self.services.settings.identity_monitoring_enabled
            or self.services.identity_service.is_monitoring
        ) and not self._confirm_monitoring_admin("reset settings and stop identity monitoring"):
            return
        try:
            settings = self.services.reset_settings()
        except (OSError, ValueError) as exc:
            self._show_error("Could not reset settings", exc)
            return
        self._show_settings(settings)
        self.status.set_text("Defaults restored and saved")

    def _backup(self) -> None:
        default_name = (
            f"settings.backup.{datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')}.json"
        )
        destination, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Back up settings",
            str(self.services.paths.backups_directory / default_name),
            "JSON files (*.json)",
        )
        if not destination:
            return
        try:
            path = self.services.backup_settings(destination)
        except (OSError, ValueError) as exc:
            self._show_error("Could not create settings backup", exc)
            return
        self.status.set_text(f"Backup saved: {path}")

    def _restore(self) -> None:
        source, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Restore settings",
            str(self.services.paths.backups_directory),
            "JSON files (*.json)",
        )
        if not source:
            return
        if not ConfirmationDialog.confirm(
            self,
            "Restore settings backup",
            "Replace the current settings with the selected backup?",
        ):
            return
        if (
            self.services.settings.identity_monitoring_enabled
            or self.services.identity_service.is_monitoring
        ) and not self._confirm_monitoring_admin(
            "restore settings that may stop identity monitoring"
        ):
            return
        try:
            settings = self.services.restore_settings(source)
        except (OSError, ValueError) as exc:
            self._show_error("Could not restore settings", exc)
            return
        self._show_settings(settings)
        self.status.set_text("Backup restored and applied")

    def _confirm_monitoring_admin(self, action: str) -> bool:
        if not (
            self.services.settings.identity_monitoring_enabled
            or self.services.identity_service.is_monitoring
        ):
            return True
        return confirm_windows_administrator(
            self,
            f"Confirm {action}",
            f"This change may stop or disable identity monitoring. {action.capitalize()} "
            "requires credentials for a Windows administrator account.",
            "Verify and continue",
        )

    def _show_settings(self, settings: AppSettings) -> None:
        self.log_level_combo.setCurrentText(settings.log_level)
        self.retention_days.setValue(settings.log_retention_days)
        self.file_logging.setChecked(settings.file_logging_enabled)
        self.backup_before_save.setChecked(settings.backup_before_save)
        self.camera_access.setChecked(settings.camera_access_enabled)
        self.camera_device.setValue(settings.camera_index)
        self.identity_monitoring.setChecked(settings.identity_monitoring_enabled)
        self.start_monitoring.setChecked(settings.start_monitoring_on_launch)
        self.camera_reconnect.setValue(settings.camera_reconnect_seconds)
        self.camera_failure_action.setCurrentIndex(
            self.camera_failure_action.findData(settings.camera_failure_action)
        )
        self.multiple_face_policy.setCurrentIndex(
            self.multiple_face_policy.findData(settings.multiple_face_policy)
        )
        self.camera_width.setCurrentText(str(settings.camera_width))
        self.camera_height.setCurrentText(str(settings.camera_height))
        self.capture_interval.setValue(settings.capture_interval_ms)
        self.verification_threshold.setValue(settings.verification_threshold)
        self.verification_cooldown.setValue(settings.verification_cooldown_seconds)
        self.liveness_enabled.setChecked(settings.liveness_enabled)
        self.require_single_face.setChecked(settings.require_single_face)
        self.identity_retention.setValue(settings.identity_event_retention_days)
        self.unknown_face_action.setCurrentIndex(
            self.unknown_face_action.findData(settings.unknown_face_action)
        )
        self.presence_loss_action.setCurrentIndex(
            self.presence_loss_action.findData(settings.presence_loss_action)
        )
        self.failure_limit.setValue(settings.identity_failure_limit)
        self.automatic_lock.setChecked(settings.automatic_lock_enabled)
        self.lock_grace.setValue(settings.lock_grace_period_seconds)
        self.identity_notifications.setChecked(settings.identity_notifications_enabled)
        self.endpoint_interval.setValue(settings.endpoint_poll_interval_seconds)
        self.process_monitoring.setChecked(settings.process_monitoring_enabled)
        self.network_monitoring.setChecked(settings.network_monitoring_enabled)
        self.file_integrity_monitoring.setChecked(settings.file_integrity_monitoring_enabled)
        self.windows_log_monitoring.setChecked(settings.windows_log_collection_enabled)
        self.event_retention.setValue(settings.event_retention_days)
        self.process_exclusions.setPlainText("\n".join(settings.process_exclusions))
        self.file_integrity_roots.setPlainText("\n".join(settings.file_integrity_roots))

    @staticmethod
    def _lines(editor: QPlainTextEdit) -> tuple[str, ...]:
        return tuple(line.strip() for line in editor.toPlainText().splitlines() if line.strip())

    def _add_integrity_root(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select file-integrity folder")
        if not directory:
            return
        roots = list(self._lines(self.file_integrity_roots))
        if directory not in roots:
            roots.append(directory)
        self.file_integrity_roots.setPlainText("\n".join(roots))

    def _open_data_folder(self) -> None:
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.services.paths.root))):
            QMessageBox.warning(
                self,
                "Could not open data folder",
                f"Open this directory manually:\n{self.services.paths.root}",
            )

    def _show_error(self, title: str, error: Exception) -> None:
        self.status.set_text(f"Error: {error}")
        QMessageBox.critical(self, title, str(error))
