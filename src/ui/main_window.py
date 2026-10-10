"""Responsive main window and page navigation for PrivSentinel."""

import base64
import sqlite3
from pathlib import Path

from PySide6.QtCore import QByteArray, QEvent, Qt, QTimer
from PySide6.QtGui import QAction, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
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
from src.ui.components.sidebar import Sidebar
from src.ui.components.topbar import TopBar
from src.ui.dialogs.enrollment_dialog import EnrollmentDialog
from src.ui.dialogs.notice_dialog import NoticeDialog
from src.ui.dialogs.search_results_dialog import SearchResultsDialog
from src.ui.navigation import PAGE_DEFINITIONS, PAGES_BY_KEY
from src.ui.pages import PAGE_WIDGETS


class MainWindow(QMainWindow):
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

        self.setMinimumSize(920, 620)

        self.resize(1440, 900)

        self.services = services or ApplicationServices.create()

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

        self.page_stack = QStackedWidget()

        self.page_stack.setObjectName("pageStack")

        self.scroll_area = QScrollArea()

        self.scroll_area.setObjectName("pageViewport")

        self.scroll_area.setWidgetResizable(True)

        self.scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)

        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self.scroll_area.setWidget(self.page_stack)

        content_layout.addWidget(self.scroll_area, 1)

        root_layout.addWidget(content, 1)

        self.setCentralWidget(root)

        self.statusBar().showMessage("Ready · local data sources are not connected", 5000)

        for definition in PAGE_DEFINITIONS:
            if (
                definition.key == "dashboard"
                or definition.key == "settings"
                or definition.key in {"identity-protection", "verification-history"}
            ):
                page = PAGE_WIDGETS[definition.key](self.services)

            else:
                page = PAGE_WIDGETS[definition.key]()

            page.actionRequested.connect(self._handle_page_action)

            if hasattr(page, "pageRequested"):
                page.pageRequested.connect(self.navigate_to)

            self._pages[definition.key] = page

            self.page_stack.addWidget(page)

        self.sidebar.pageSelected.connect(self.navigate_to)

        self.topbar.pageSearchRequested.connect(self.navigate_to)

        self.topbar.globalSearchRequested.connect(self._search_pages)

        self.topbar.notificationsRequested.connect(lambda: self.navigate_to("alerts"))

        self.services.identity_service.lockWarningRequested.connect(self._warn_before_lock)

        self.services.identity_service.serviceError.connect(
            lambda message: self.statusBar().showMessage(message, 10000)
        )

        self.services.identity_service.eventRecorded.connect(self._identity_event)

        self.services.identity_service.stateChanged.connect(
            lambda *_args: self._update_dashboard_identity()
        )

        self.services.identity_service.profileChanged.connect(self._update_dashboard_identity)

        self.services.identity_service.monitoringChanged.connect(
            lambda *_args: self._update_dashboard_identity()
        )
        self.services.identity_service.cameraStateChanged.connect(
            self._on_camera_state_changed
        )

        self._lock_timer = QTimer(self)

        self._lock_timer.setSingleShot(True)

        self._lock_timer.timeout.connect(self._complete_lock_warning)

        self._lock_warning_box: QMessageBox | None = None

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

        self._status_timer.start(1000)
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._stop_background_activity)

        self._search_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)

        self._search_shortcut.activated.connect(self._focus_search)

        self._update_dashboard_identity()

        self._restore_preferences()

        self.navigate_to("dashboard")

        self.services.endpoint_service.stateChanged.connect(
            lambda source, state: self.statusBar().showMessage(f"{source}: {state}", 5000)
        )

        self.services.endpoint_service.serviceError.connect(
            lambda message: self.statusBar().showMessage(message, 10000)
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

        for key, page in self._pages.items():
            if page is current:
                return key

        raise RuntimeError("No current application page is selected.")

    def navigate_to(self, key: str) -> None:

        if key not in self._pages:
            raise KeyError(f"Unknown page key: {key}")

        self.page_stack.setCurrentWidget(self._pages[key])

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

        dialog = SearchResultsDialog(query, matches, self)

        if dialog.exec() == SearchResultsDialog.DialogCode.Accepted and dialog.selected_key:
            self.navigate_to(dialog.selected_key)

    def _handle_page_action(self, action: str) -> None:

        if action in {"identity-protection", "identity-enrollment", "enrollment"}:
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
            NoticeDialog(
                "Scan unavailable",
                "No local scan provider is configured. No processes or files were scanned.",
                self,
            ).exec()
            return
        if action == "toggle-monitoring":
            identity = self.services.identity_service
            if identity.is_monitoring:
                identity.stop_monitoring()
                self.statusBar().showMessage("Identity monitoring paused", 5000)
                return
            try:
                identity.start_monitoring()
            except (PermissionError, ValueError, OSError, RuntimeError) as exc:
                QMessageBox.warning(
                    self,
                    "Monitoring could not start",
                    f"{exc}\n\nReview camera consent, monitoring settings, and "
                    "identity enrollment before starting.",
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

    def _warn_before_lock(self, grace_seconds: int) -> None:

        if not self.services.settings.automatic_lock_enabled:
            return

        box = QMessageBox(self)

        box.setIcon(QMessageBox.Icon.Warning)

        box.setWindowTitle("Identity security warning")

        box.setText(
            "The configured identity response policy was triggered. "
            f"The workstation will lock in {grace_seconds} seconds unless cancelled."
        )

        box.setInformativeText(
            "This is a basic face-motion check, not robust anti-spoofing. "
            "Camera failure never triggers this response."
        )

        box.setStandardButtons(QMessageBox.StandardButton.Cancel)

        box.setDefaultButton(QMessageBox.StandardButton.Cancel)

        box.button(QMessageBox.StandardButton.Cancel).setText("Cancel lock")

        box.finished.connect(lambda _result: self._lock_timer.stop())

        self._lock_warning_box = box

        box.show()

        self._lock_timer.start(grace_seconds * 1000)

    def _complete_lock_warning(self) -> None:

        if not self.services.settings.automatic_lock_enabled:
            return

        if self._lock_warning_box is not None:
            self._lock_warning_box.accept()

            self._lock_warning_box = None

        try:
            import ctypes

            if not ctypes.windll.user32.LockWorkStation():
                raise OSError("Windows declined the workstation lock request.")

        except (AttributeError, OSError) as exc:
            self.services.identity_service.serviceError.emit(f"Could not lock workstation: {exc}")

    def _identity_event(self, event) -> None:

        self._update_dashboard_identity()

        if not self.services.settings.identity_notifications_enabled:
            return

        if event.state in {
            "unknown_face",
            "multiple_faces",
            "liveness_failure",
            "camera_unavailable",
        }:
            self._identity_tray.showMessage(
                "PrivSentinel identity protection",
                event.detail,
                QSystemTrayIcon.MessageIcon.Warning,
                7000,
            )

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
        self._status_timer.stop()
        self._lock_timer.stop()
        for timer in self.findChildren(QTimer):
            timer.stop()
        self.services.identity_service.stop_monitoring()
        self.services.endpoint_service.stop_all()

    def _restore_preferences(self) -> None:

        geometry = self.services.settings.window_geometry

        if geometry is not None:
            self.restoreGeometry(QByteArray(base64.b64decode(geometry)))

        state = self.services.settings.window_state

        if state is not None:
            self.restoreState(QByteArray(base64.b64decode(state)))

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
