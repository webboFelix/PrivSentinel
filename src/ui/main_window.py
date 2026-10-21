"""Responsive main window and page navigation for PrivSentinel."""

import base64
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import (
    QByteArray,
    QEvent,
    QProcess,
    QSettings,
    Qt,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import QAction, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLayout,
    QMainWindow,
    QMenu,
    QMessageBox,
    QScrollArea,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.identity.face_verifier import recognition_model_is_installed
from src.response.network_actions import block_ip
from src.ui.components.sidebar import Sidebar
from src.ui.components.topbar import TopBar
from src.ui.components.voice_search_worker import VoiceSearchWorker
from src.ui.dialogs.administrator_confirmation_dialog import (
    confirm_windows_administrator,
)
from src.ui.dialogs.enrollment_dialog import EnrollmentDialog
from src.ui.dialogs.notice_dialog import NoticeDialog
from src.ui.dialogs.search_results_dialog import SearchResultsDialog
from src.ui.navigation import PAGE_DEFINITIONS, PAGES_BY_KEY
from src.ui.pages import PAGE_WIDGETS


class _PageStack(QStackedWidget):
    def sizeHint(self):
        page = self.currentWidget()
        return page.sizeHint() if page is not None else super().sizeHint()

    def minimumSizeHint(self):
        page = self.currentWidget()
        return page.minimumSizeHint() if page is not None else super().minimumSizeHint()


class _LockWarningBox(QMessageBox):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self._allow_close = False

    def accept(self) -> None:
        self._allow_close = True
        super().accept()

    def reject(self) -> None:
        if self._allow_close:
            super().reject()

    def closeEvent(self, event) -> None:
        if self._allow_close:
            super().closeEvent(event)
        else:
            event.ignore()


class MainWindow(QMainWindow):
    recognitionModelPreparationFinished = Signal(bool, str)
    securityEventPublished = Signal()

    def __init__(
        self,
        services: ApplicationServices | None = None,
        parent: QWidget | None = None,
    ) -> None:

        super().__init__(parent)

        self.setWindowTitle("PrivSentinel — Privacy-first endpoint protection")
        self._closing = False

        self.setWindowIcon(
            QIcon(str(Path(__file__).resolve().parent / "resources" / "icons" / "PrivSentinel.png"))
        )

        screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen is not None else None
        if available is None:
            self.setMinimumSize(920, 620)
            self.resize(1440, 900)
        else:
            self.setMinimumSize(
                min(920, max(640, available.width() - 24)),
                min(500, max(420, available.height() - 60)),
            )
            self.resize(
                min(1440, max(self.minimumWidth(), available.width() - 24)),
                min(900, max(self.minimumHeight(), available.height() - 36)),
            )

        self.services = services or ApplicationServices.create()
        self._model_preparation_process: QProcess | None = None
        self._model_preparation_output = bytearray()
        self._voice_search_worker: VoiceSearchWorker | None = None

        self._pages: dict[str, QWidget] = {}

        root = QWidget()

        root.setObjectName("appRoot")

        root_layout = QHBoxLayout(root)

        root_layout.setContentsMargins(0, 0, 0, 0)

        root_layout.setSpacing(0)

        self.sidebar = Sidebar()

        root_layout.addWidget(self.sidebar)

        content = QWidget()

        content_layout = QVBoxLayout(content)

        content_layout.setContentsMargins(0, 0, 0, 0)

        content_layout.setSpacing(0)

        self.topbar = TopBar()

        content_layout.addWidget(self.topbar)

        self.page_stack = _PageStack()

        self.page_stack.setObjectName("pageStack")
        self.page_stack.setMinimumSize(0, 0)
        self.page_stack.layout().setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
        self.page_stack.currentChanged.connect(self.page_stack.updateGeometry)

        self._page_containers: dict[str, QScrollArea] = {}
        self._page_scroll_areas: dict[str, QScrollArea] = {}
        self.scroll_area: QScrollArea
        content_layout.addWidget(self.page_stack, 1)

        root_layout.addWidget(content, 1)

        self.setCentralWidget(root)

        self.statusBar().showMessage("Ready · local data sources are not connected", 5000)

        for definition in PAGE_DEFINITIONS:
            if (
                definition.key == "dashboard"
                or definition.key == "settings"
                or definition.key in {"identity-protection", "verification-history"}
                or definition.key
                in {
                    "process-monitor",
                    "file-integrity",
                    "malware-protection",
                    "web-protection",
                    "network-monitor",
                }
                or definition.key
                in {
                    "windows-logs",
                    "threat-detection",
                    "alerts",
                    "threat-intelligence",
                    "investigations",
                    "reports",
                    "audit-log",
                }
            ):
                page = PAGE_WIDGETS[definition.key](self.services)

            else:
                page = PAGE_WIDGETS[definition.key]()

            page.actionRequested.connect(self._handle_page_action)
            alert_count_signal = getattr(page, "alertCountChanged", None)
            if alert_count_signal is not None:
                alert_count_signal.connect(self._update_alert_count)

            if hasattr(page, "pageRequested"):
                page.pageRequested.connect(self.navigate_to)
            if hasattr(page, "blockIpRequested"):
                page.blockIpRequested.connect(self._block_landscape_ip)
            if hasattr(page, "quarantineRequested"):
                page.quarantineRequested.connect(self._quarantine_landscape_finding)

            self._pages[definition.key] = page

            page_scroll_area = QScrollArea()
            page_scroll_area.setObjectName(f"pageViewport-{definition.key}")
            page_scroll_area.setWidgetResizable(True)
            page_scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
            page_scroll_area.setHorizontalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAsNeeded
            )
            page_scroll_area.setVerticalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAsNeeded
            )
            page_scroll_area.setMinimumSize(0, 0)
            page_scroll_area.setWidget(page)
            self._page_containers[definition.key] = page_scroll_area
            self._page_scroll_areas[definition.key] = page_scroll_area
            self.page_stack.addWidget(page_scroll_area)

        self.sidebar.pageSelected.connect(self.navigate_to)

        self.topbar.pageSearchRequested.connect(self.navigate_to)

        self.topbar.globalSearchRequested.connect(self._search_pages)

        self.topbar.voiceSearchRequested.connect(self._toggle_voice_search)

        self.topbar.notificationsRequested.connect(lambda: self.navigate_to("alerts"))

        self.services.identity_service.lockWarningRequested.connect(self._warn_before_lock)

        self.services.identity_service.serviceError.connect(
            self._show_service_error
        )

        self.services.identity_service.eventRecorded.connect(self._identity_event)

        self.services.identity_service.stateChanged.connect(
            self._on_identity_state_changed
        )

        self.services.identity_service.profileChanged.connect(self._update_dashboard_identity)

        self.services.identity_service.monitoringChanged.connect(
            self._update_dashboard_identity
        )
        self.services.identity_service.cameraStateChanged.connect(
            self._on_camera_state_changed
        )
        self.securityEventPublished.connect(self._update_alert_count)
        self._unsubscribe_security_events = self.services.event_pipeline.bus.subscribe(
            lambda _event: self.securityEventPublished.emit()
        )

        self._lock_timer = QTimer(self)

        self._lock_timer.setSingleShot(True)

        self._lock_timer.timeout.connect(self._complete_lock_warning)

        self._lock_warning_box: QMessageBox | None = None
        self._identity_warning_active = False

        # Native Windows system-tray integration.
        self._tray_available = QSystemTrayIcon.isSystemTrayAvailable()
        self._identity_tray = QSystemTrayIcon(self.windowIcon(), self)
        self._identity_tray.setToolTip("PrivSentinel — Privacy-first endpoint protection")

        self._tray_menu = QMenu(self)

        open_action = QAction("Open PrivSentinel", self)
        open_action.triggered.connect(self._restore_from_tray)
        self._tray_menu.addAction(open_action)

        dashboard_action = QAction("Security Dashboard", self)
        dashboard_action.triggered.connect(lambda: self._open_tray_page("dashboard"))
        self._tray_menu.addAction(dashboard_action)

        identity_action = QAction("Identity Protection", self)
        identity_action.triggered.connect(lambda: self._open_tray_page("identity-protection"))
        self._tray_menu.addAction(identity_action)

        self._tray_menu.addSeparator()

        exit_action = QAction("Exit PrivSentinel", self)
        exit_action.triggered.connect(self.close)
        self._tray_menu.addAction(exit_action)

        self._identity_tray.setContextMenu(self._tray_menu)
        self._identity_tray.activated.connect(self._on_tray_activated)

        if self._tray_available:
            self._identity_tray.show()

        self._status_timer = QTimer(self)

        self._status_timer.timeout.connect(self._update_dashboard_identity)

        self._status_timer.start(5000)
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._stop_background_activity)

        self._search_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)

        self._search_shortcut.activated.connect(self._focus_search)

        self._update_dashboard_identity()
        self._update_alert_count()

        self._restore_preferences()

        self.navigate_to("dashboard")

        self.services.endpoint_service.stateChanged.connect(
            self._on_endpoint_state_changed
        )

        self.services.endpoint_service.serviceError.connect(
            self._show_service_error
        )

        self.services.endpoint_service.start_configured()

        if (
            self.services.settings.start_monitoring_on_launch
            and self.services.identity_service.profile is not None
        ):
            try:
                self.services.identity_service.start_monitoring()

            except (PermissionError, ValueError, OSError, RuntimeError) as exc:
                self.statusBar().showMessage(
                    f"Automatic identity monitoring did not start: {exc}",
                    12000,
                )

    @Slot(str, str)
    def _on_endpoint_state_changed(self, source: str, state: str) -> None:
        if not self._closing:
            self.statusBar().showMessage(f"{source}: {state}", 5000)

    @Slot(str)
    def _show_service_error(self, message: str) -> None:
        if not self._closing:
            self.statusBar().showMessage(message, 10000)

    def _restore_from_tray(self) -> None:
        """Restore and focus the main window from the system tray."""
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _open_tray_page(self, page_key: str) -> None:
        """Open a page selected from the system-tray menu."""
        self._restore_from_tray()
        self.navigate_to(page_key)

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Restore the application when its tray icon is double-clicked."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._restore_from_tray()

    def changeEvent(self, event: QEvent) -> None:
        """Hide the main window in the tray when it is minimized."""
        super().changeEvent(event)
        if (
            event.type() == QEvent.Type.WindowStateChange
            and self.isMinimized()
            and self._tray_available
        ):
            QTimer.singleShot(0, self.hide)

    @property
    def page_keys(self) -> tuple[str, ...]:

        return tuple(self._pages)

    @property
    def current_page_key(self) -> str:

        current = self.page_stack.currentWidget()

        for key in self._pages:
            if self._page_containers[key] is current:
                return key

        raise RuntimeError("No current application page is selected.")

    def navigate_to(self, key: str) -> None:

        if key not in self._pages:
            raise KeyError(f"Unknown page key: {key}")

        self.page_stack.setCurrentWidget(self._page_containers[key])
        self.scroll_area = self._page_scroll_areas[key]

        self.sidebar.set_active_page(key)

        self.topbar.set_page(key)

        self.statusBar().showMessage(f"Viewing {PAGES_BY_KEY[key].title}", 2500)

    def _focus_search(self) -> None:

        self.topbar.search_bar.setFocus(Qt.FocusReason.ShortcutFocusReason)

        self.topbar.search_bar.selectAll()

    def _search_pages(self, query: str) -> None:
        normalized = query.casefold().strip()
        if not normalized:
            self._focus_search()
            return

        matches = [
            page
            for page in PAGE_DEFINITIONS
            if normalized in page.title.casefold()
            or normalized in page.description.casefold()
            or normalized in page.category.casefold()
        ]

        records: list[tuple[str, str]] = []
        try:
            for alert in self.services.security_repository.list_alerts(limit=10000):
                searchable = " ".join(
                    str(alert[key])
                    for key in (
                        "title",
                        "severity",
                        "source",
                        "event_type",
                        "description",
                        "status",
                    )
                )
                if normalized in searchable.casefold():
                    records.append(
                        (
                            f"ALERT · {alert['title']} · {alert['severity']} · {alert['status']}",
                            "alerts",
                        )
                    )
                    if len(records) >= 100:
                        break

            if len(records) < 100:
                for event in self.services.security_repository.list_events(
                    limit=2000,
                    query=query,
                ):
                    records.append(
                        (
                            (
                                f"EVENT · {event['source']} · {event['event_type']} · "
                                f"{event['description']}"
                            ),
                            "audit-log",
                        )
                    )
                    if len(records) >= 100:
                        break

            if len(records) < 100:
                token = f"%{query.strip()}%"
                file_rows = self.services.database.fetchall(
                    "SELECT path FROM file_integrity_baselines "
                    "WHERE path LIKE ? ORDER BY path LIMIT ?",
                    (token, 100 - len(records)),
                )
                records.extend(
                    (f"FILE · {row['path']}", "file-integrity")
                    for row in file_rows
                )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.statusBar().showMessage(f"Global search failed: {exc}", 10000)
            return

        dialog = SearchResultsDialog(query, matches, self, records)

        if dialog.exec() == SearchResultsDialog.DialogCode.Accepted and dialog.selected_key:
            self.navigate_to(dialog.selected_key)

    def _toggle_voice_search(self) -> None:
        worker = self._voice_search_worker
        if worker is not None and worker.isRunning():
            worker.stop()
            self.topbar.set_voice_search_active(False)
            return

        settings = QSettings("PrivSentinel", "PrivSentinel")
        model_directory = str(settings.value("voiceSearch/modelDirectory", ""))
        if not model_directory or not Path(model_directory).is_dir():
            model_directory = QFileDialog.getExistingDirectory(
                self,
                "Select offline Vosk speech model",
                str(self.services.paths.models_directory),
            )
            if not model_directory:
                return
            settings.setValue("voiceSearch/modelDirectory", model_directory)

        worker = VoiceSearchWorker(model_directory, self)
        self._voice_search_worker = worker
        worker.recognized.connect(self._on_voice_search_recognized)
        worker.failed.connect(
            lambda message: self.statusBar().showMessage(message, 12000)
        )
        worker.finished.connect(
            lambda worker=worker: self._voice_search_finished(worker)
        )
        self.topbar.set_voice_search_active(True)
        worker.start()

    def _on_voice_search_recognized(self, phrase: str) -> None:
        self.topbar.search_bar.setText(phrase)
        self._search_pages(phrase)

    def _voice_search_finished(self, worker: VoiceSearchWorker) -> None:
        if self._voice_search_worker is worker:
            self._voice_search_worker = None
            self.topbar.set_voice_search_active(False)

    def _handle_page_action(self, action: str) -> None:

        if action in {"identity-protection", "identity-enrollment", "enrollment"}:
            model_preparation_active = (
                self._model_preparation_process is not None
                and self._model_preparation_process.state()
                != QProcess.ProcessState.NotRunning
            )
            resume_monitoring = self.services.identity_service.is_monitoring
            if resume_monitoring:
                self.services.identity_service.stop_monitoring()
                if self.services.identity_service.is_monitoring:
                    self.statusBar().showMessage(
                        "Could not release the camera for enrollment; monitoring is "
                        "still shutting down.",
                        12000,
                    )
                    return
            dialog = EnrollmentDialog(
                self.services,
                self.services.identity_repository,
                self,
            )
            if model_preparation_active:
                dialog.set_model_preparation_pending()
                self.recognitionModelPreparationFinished.connect(
                    dialog.model_preparation_finished
                )
                dialog.finished.connect(
                    lambda _result, dialog=dialog: self._disconnect_model_preparation(
                        dialog
                    )
                )

            dialog.enrollmentCompleted.connect(self.services.identity_service.record_enrollment)

            dialog.exec()

            if (
                (
                    resume_monitoring
                    or self.services.settings.start_monitoring_on_launch
                )
                and not self.services.identity_service.is_monitoring
                and self.services.identity_service.profile is not None
            ):
                try:
                    self.services.identity_service.start_monitoring()

                except (PermissionError, ValueError, OSError, RuntimeError) as exc:
                    self.statusBar().showMessage(
                        f"Identity was enrolled, but monitoring did not start: {exc}",
                        12000,
                    )
            return

        if action == "scan":
            self.navigate_to("malware-protection")
            return
        if action == "toggle-monitoring":
            identity = self.services.identity_service
            if identity.is_monitoring:
                if not confirm_windows_administrator(
                    self,
                    "Confirm stopping identity monitoring",
                    "Stopping identity monitoring requires credentials for a "
                    "Windows administrator account.",
                    "Verify and stop",
                ):
                    return
                try:
                    self.services.save_settings(
                        replace(
                            self.services.settings,
                            identity_monitoring_enabled=False,
                            start_monitoring_on_launch=False,
                        )
                    )
                    identity.stop_monitoring()
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                    QMessageBox.critical(
                        self,
                        "Could not stop monitoring",
                        str(exc),
                    )
                    return
                self.statusBar().showMessage("Identity monitoring stopped", 5000)
                return
            if not self.services.settings.camera_access_enabled:
                answer = QMessageBox.question(
                    self,
                    "Enable camera access",
                    "Allow PrivSentinel to access the camera for local identity "
                    "verification? This app setting is separate from Windows camera "
                    "privacy permissions.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
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
                    QMessageBox.critical(
                        self,
                        "Could not enable camera access",
                        f"PrivSentinel could not save its camera-access setting:\n{exc}",
                    )
                    return
            try:
                if not self.services.settings.identity_monitoring_enabled:
                    self.services.save_settings(
                        replace(
                            self.services.settings,
                            identity_monitoring_enabled=True,
                        )
                    )
                identity.start_monitoring()
            except (PermissionError, ValueError, OSError, RuntimeError) as exc:
                QMessageBox.warning(
                    self,
                    "Monitoring could not start",
                    f"{exc}\n\nPrivSentinel camera access: "
                    f"{'enabled' if self.services.settings.camera_access_enabled else 'disabled'}"
                    ". Windows camera privacy permissions are a separate setting. "
                    "Also verify identity enrollment and monitoring settings.",
                )
                return
            self.statusBar().showMessage("Identity monitoring started", 5000)
            return
        if action == "export":
            NoticeDialog(
                "Report export unavailable",
                "No report data or export provider is configured. No file was created.",
                self,
            ).exec()
            return

        if action in {"reports", "investigations"}:
            NoticeDialog(
                "Local provider required",
                "This action becomes available after a local data provider is configured.",
                self,
            ).exec()
            return

        QMessageBox.information(
            self, "Action unavailable", f"No local provider is configured for: {action}"
        )

    def _block_landscape_ip(self, address: str) -> None:
        confirmed = QMessageBox.warning(
            self,
            "Block network address?",
            f"Add Windows Firewall rules to block {address} for inbound and "
            "outbound traffic? This may disrupt active connections and may "
            "require administrator access.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmed != QMessageBox.StandardButton.Yes:
            return
        try:
            block_ip(address)
        except (OSError, ValueError, RuntimeError) as exc:
            self.statusBar().showMessage(f"Could not block {address}: {exc}", 12000)
            return
        self.statusBar().showMessage(
            f"Windows Firewall is blocking {address}", 8000
        )

    def _quarantine_landscape_finding(self, finding_id: int) -> None:
        page = self._pages.get("malware-protection")
        if page is None or not hasattr(page, "quarantine_finding"):
            self.statusBar().showMessage(
                "The malware-protection page is unavailable.", 8000
            )
            return
        self.navigate_to("malware-protection")
        page.quarantine_finding(finding_id)

    def _disconnect_model_preparation(self, dialog: EnrollmentDialog) -> None:
        try:
            self.recognitionModelPreparationFinished.disconnect(
                dialog.model_preparation_finished
            )
        except RuntimeError:
            pass

    def prepare_recognition_model(self) -> None:
        if recognition_model_is_installed(self.services.paths.models_directory):
            return
        settings = self.services.settings
        if not settings.recognition_model_download_prompted:
            answer = QMessageBox.question(
                self,
                "Prepare local face recognition?",
                "PrivSentinel can download its approximately 300 MB face-recognition "
                "model now in the background, so enrollment will not have to wait for "
                "it later. The model is stored locally; camera images are not uploaded. "
                "You can continue using the app while it downloads.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            allowed = answer == QMessageBox.StandardButton.Yes
            try:
                self.services.save_settings(
                    replace(
                        settings,
                        recognition_model_download_prompted=True,
                        recognition_model_download_allowed=allowed,
                    )
                )
            except (OSError, ValueError, RuntimeError) as exc:
                self.statusBar().showMessage(
                    f"Could not save model-download preference: {exc}",
                    12000,
                )
                return
            settings = self.services.settings
        if settings.recognition_model_download_allowed:
            self._start_recognition_model_preparation()

    def _start_recognition_model_preparation(self) -> None:
        if (
            self._model_preparation_process is not None
            and self._model_preparation_process.state()
            != QProcess.ProcessState.NotRunning
        ):
            return
        process = QProcess(self)
        process.setProgram(sys.executable)
        if getattr(sys, "frozen", False):
            process.setArguments(
                [
                    "--privsentinel-prepare-recognition-model",
                    str(self.services.paths.models_directory),
                ]
            )
        else:
            process.setArguments(
                [
                    "-m",
                    "src",
                    "--privsentinel-prepare-recognition-model",
                    str(self.services.paths.models_directory),
                ]
            )
        self._model_preparation_output.clear()
        self._model_preparation_process = process
        process.readyReadStandardError.connect(self._read_model_preparation_output)
        process.readyReadStandardOutput.connect(self._read_model_preparation_output)
        process.errorOccurred.connect(self._model_preparation_error)
        process.finished.connect(self._model_preparation_finished)
        self.statusBar().showMessage(
            "Preparing the local face-recognition model in the background…"
        )
        process.start()

    def _read_model_preparation_output(self) -> None:
        process = self._model_preparation_process
        if process is None:
            return
        self._model_preparation_output.extend(process.readAllStandardError().data())
        self._model_preparation_output.extend(process.readAllStandardOutput().data())
        if len(self._model_preparation_output) > 8192:
            del self._model_preparation_output[:-8192]

    def _model_preparation_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            process = self._model_preparation_process
            self._model_preparation_process = None
            if process is not None:
                process.deleteLater()
            message = "Could not start background face-model preparation."
            self.statusBar().showMessage(message, 12000)
            self.recognitionModelPreparationFinished.emit(
                False,
                message,
            )

    def _model_preparation_finished(
        self,
        exit_code: int,
        _exit_status: QProcess.ExitStatus,
    ) -> None:
        process = self._model_preparation_process
        if process is None:
            return
        self._read_model_preparation_output()
        self._model_preparation_process = None
        if process is not None:
            process.deleteLater()
        if exit_code == 0 and recognition_model_is_installed(
            self.services.paths.models_directory
        ):
            message = "Local face-recognition model is ready for enrollment."
            self.statusBar().showMessage(
                message,
                10000,
            )
            self.recognitionModelPreparationFinished.emit(True, message)
            return
        details = self._model_preparation_output.decode(
            "utf-8",
            errors="replace",
        ).strip()
        message = "Background face-model preparation failed."
        if details:
            message = f"{message} {details[-1500:]}"
        self.statusBar().showMessage(message, 15000)
        self.recognitionModelPreparationFinished.emit(False, message)

    def _warn_before_lock(self, grace_seconds: int) -> None:
        if (
            not self.services.settings.automatic_lock_enabled
            or self.services.identity_service.current_state != "unknown_face"
            or self._lock_warning_box is not None
        ):
            return

        box = _LockWarningBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Identity security warning")
        box.setText(
            "An unknown face was detected. "
            f"The workstation will lock in {grace_seconds} seconds."
        )
        box.setInformativeText(
            "This is a basic face-motion check, not robust anti-spoofing. "
            "Camera failure never triggers this response."
        )
        box.setStandardButtons(QMessageBox.StandardButton.NoButton)
        box.setEscapeButton(QMessageBox.StandardButton.NoButton)
        box.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self._lock_warning_box = box
        box.show()
        self._lock_timer.start(grace_seconds * 1000)

    def _complete_lock_warning(self) -> None:
        if (
            not self.services.settings.automatic_lock_enabled
            or self.services.identity_service.current_state
            in {"recognized", "stopped"}
        ):
            self._dismiss_lock_warning()
            return

        self._dismiss_lock_warning()

        try:
            import ctypes

            if not ctypes.windll.user32.LockWorkStation():
                raise OSError("Windows declined the workstation lock request.")

        except (AttributeError, OSError) as exc:
            self.services.identity_service.serviceError.emit(f"Could not lock workstation: {exc}")

    def _dismiss_lock_warning(self) -> None:
        self._lock_timer.stop()
        box = self._lock_warning_box
        self._lock_warning_box = None
        if box is not None:
            box.accept()

    def _on_identity_state_changed(self, state: str, _detail: str) -> None:
        if state in {"recognized", "stopped"}:
            self._identity_warning_active = False
            self._dismiss_lock_warning()
        self._update_dashboard_identity()

    def _identity_event(self, event) -> None:
        self._update_dashboard_identity()

        if event.state == "recognized":
            self._identity_warning_active = False
            return
        if not self.services.settings.identity_notifications_enabled:
            return
        if event.state in {
            "unknown_face",
            "multiple_faces",
            "camera_unavailable",
        }:
            if self._identity_warning_active:
                return
            self._identity_warning_active = True
            self._identity_tray.showMessage(
                "PrivSentinel identity protection",
                event.detail,
                QSystemTrayIcon.MessageIcon.Warning,
                7000,
            )

    def _update_alert_count(self) -> None:
        if self._closing:
            return
        try:
            alerts = self.services.security_repository.list_alerts(limit=10000)
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.statusBar().showMessage(f"Could not read alert count: {exc}", 10000)
            return
        count = sum(
            alert["status"] in {"open", "acknowledged", "investigating"}
            for alert in alerts
        )
        self.topbar.set_alert_count(count)
        self.sidebar.set_alert_count(count)

    def _update_dashboard_identity(self) -> None:
        if self._closing:
            return

        dashboard = self._pages.get("dashboard")

        identity = self.services.identity_service

        if dashboard is None or not hasattr(dashboard, "set_identity_state"):
            return

        try:
            profile = identity.profile

            unknown_faces = identity.event_count("unknown_face")

            recent = identity.recent_events(limit=1)

        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.statusBar().showMessage(f"Could not read identity event count: {exc}", 10000)

            dashboard.set_identity_error(str(exc))

            return

        dashboard.set_identity_state(
            profile.display_name if profile else None,
            identity.is_monitoring,
            identity.current_state,
            identity.current_detail,
            unknown_faces,
            recent[0] if recent else None,
            profile.profile_image if profile else "",
        )

        endpoint_running = any(
            worker.isRunning() for worker in self.services.endpoint_service.workers.values()
        )

        self.sidebar.set_monitoring_active(identity.is_monitoring or endpoint_running)

    def _on_camera_state_changed(self, state: str, detail: str) -> None:
        dashboard = self._pages.get("dashboard")
        if dashboard is not None and hasattr(dashboard, "set_camera_state"):
            dashboard.set_camera_state(state, detail)

    def _stop_background_activity(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._unsubscribe_security_events()
        self._status_timer.stop()
        self._lock_timer.stop()
        voice_worker = self._voice_search_worker
        if voice_worker is not None and voice_worker.isRunning():
            voice_worker.stop()
            voice_worker.wait(1500)
        for timer in self.findChildren(QTimer):
            timer.stop()
        integrity_page = self._pages.get("file-integrity")
        baseline_worker = getattr(integrity_page, "_baseline_worker", None)
        if baseline_worker is not None and baseline_worker.isRunning():
            baseline_worker.wait()
        for page in self._pages.values():
            stop_workers = getattr(page, "stop_workers", None)
            if stop_workers is not None:
                stop_workers()
        self.services.identity_service.stop_monitoring()
        self.services.endpoint_service.stop_all()
        process = self._model_preparation_process
        if process is not None and process.state() != QProcess.ProcessState.NotRunning:
            process.terminate()
            if not process.waitForFinished(1500):
                process.kill()
                process.waitForFinished(1500)

    def _restore_preferences(self) -> None:

        geometry = self.services.settings.window_geometry

        if geometry is not None:
            self.restoreGeometry(QByteArray(base64.b64decode(geometry)))

        state = self.services.settings.window_state

        if state is not None:

            self.restoreState(QByteArray(base64.b64decode(state)))

        screen = QApplication.primaryScreen()
        if screen is not None:
            available = screen.availableGeometry()
            maximum_width = max(self.minimumWidth(), available.width() - 24)
            maximum_height = max(self.minimumHeight(), available.height() - 36)
            if self.width() > maximum_width or self.height() > maximum_height:
                self.resize(
                    min(self.width(), maximum_width),
                    min(self.height(), maximum_height),
                )

    def closeEvent(self, event: QEvent) -> None:
        self._stop_background_activity()

        try:
            self.services.save_window_state(
                bytes(self.saveGeometry().data()),
                bytes(self.saveState().data()),
            )

        except (OSError, ValueError) as exc:
            QMessageBox.critical(
                self,
                "Could not save window state",
                f"Window state was not persisted:\n{exc}",
            )

        super().closeEvent(event)
