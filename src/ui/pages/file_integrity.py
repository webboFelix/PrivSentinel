"""File-integrity dashboard, trusted baseline management, and audit history."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QEvent, QPoint, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTabBar,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.ui.components.data_table import DataTable
from src.ui.components.status_indicator import StatusIndicator
from src.ui.dialogs.confirmation_dialog import ConfirmationDialog
from src.ui.icon_assets import icon_path

_LOGGER = logging.getLogger(__name__)


class _BaselineWorker(QThread):
    baselineCreated = Signal(int)
    baselineFailed = Signal(str)
    progressChanged = Signal(int, int)

    def __init__(
        self,
        services: ApplicationServices,
        roots: tuple[str, ...],
        exclusions: tuple[str, ...],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self.roots = roots
        self.exclusions = exclusions

    def run(self) -> None:
        try:
            count = self.services.endpoint_service.establish_file_baseline(
                self.roots,
                self.exclusions,
                progress_details_callback=self.progressChanged.emit,
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.baselineFailed.emit(str(exc))
            return
        except Exception as exc:
            _LOGGER.exception("Unexpected error while updating file-integrity baseline")
            self.baselineFailed.emit(f"Unexpected {type(exc).__name__}: {exc}")
            return
        self.baselineCreated.emit(count)


class _VerifyWorker(QThread):
    completed = Signal(int)
    failed = Signal(str)

    def __init__(self, services: ApplicationServices, parent: QWidget) -> None:
        super().__init__(parent)
        self.services = services

    def run(self) -> None:
        try:
            self.completed.emit(self.services.endpoint_service.verify_file_integrity())
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            _LOGGER.exception("Unexpected error during file-integrity verification")
            self.failed.emit(f"Unexpected {type(exc).__name__}: {exc}")


class _EvidenceWorker(QThread):
    completed = Signal(str)
    failed = Signal(str)

    def __init__(self, services: ApplicationServices, file_path: str, parent: QWidget) -> None:
        super().__init__(parent)
        self.services = services
        self.file_path = file_path

    def run(self) -> None:
        try:
            evidence_id = self.services.endpoint_service.record_file_integrity_evidence(
                self.file_path
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.failed.emit(str(exc))
            return
        except Exception as exc:
            _LOGGER.exception("Unexpected error capturing file-integrity evidence")
            self.failed.emit(f"Unexpected {type(exc).__name__}: {exc}")
            return
        self.completed.emit(evidence_id)


class FileIntegrityPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)
    baselineProgressChanged = Signal(int, int)
    baselineSetupFinished = Signal(bool, str)

    def __init__(
        self,
        services: ApplicationServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self._baseline_worker: _BaselineWorker | None = None
        self._verify_worker: _VerifyWorker | None = None
        self._evidence_worker: _EvidenceWorker | None = None
        self._resume_after_baseline = False
        self._baseline_started_at: float | None = None
        self._baseline_progress_count = 0
        self._baseline_total_count = -1
        self._baseline_was_existing = False
        self._row_path_by_id: dict[str, str] = {}
        self._rendered_roots: tuple[str, ...] | None = None
        self.setObjectName("page-file-integrity")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 7, 14, 12)
        layout.setSpacing(5)

        heading = QHBoxLayout()
        heading.setContentsMargins(0, 0, 0, 0)
        heading.setSpacing(9)
        icon = QLabel()
        icon.setPixmap(self._icon_pixmap("page", 35))
        heading.addWidget(icon, 0, Qt.AlignmentFlag.AlignVCenter)
        title_stack = QVBoxLayout()
        title_stack.setSpacing(0)
        title = QLabel("File Integrity Monitoring")
        title.setObjectName("pageTitle")
        title.setStyleSheet("font-size: 12pt;font-weight:700;")
        subtitle = QLabel(
            "Monitor important files and folders for unauthorized changes, deletions or tampering."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setStyleSheet("font-size:8pt;")
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        heading.addLayout(title_stack, 1)
        self.status = StatusIndicator("Checking trusted baseline", "info")
        self.status.text_label.setWordWrap(True)
        self.status.hide()
        layout.addLayout(heading)
        layout.addWidget(self.status)
        self.baseline_progress = QProgressBar()
        self.baseline_progress.setObjectName("fimBaselineProgress")
        self.baseline_progress.setTextVisible(True)
        self.baseline_progress.setFormat("Hashing files: %v / %m")
        self.baseline_progress.hide()
        layout.addWidget(self.baseline_progress)

        content = QGridLayout()
        content.setContentsMargins(0, 3, 0, 0)
        content.setHorizontalSpacing(12)
        content.setVerticalSpacing(0)

        left_column = QWidget()
        left_layout = QVBoxLayout(left_column)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        self.tabs = QTabBar()
        self.tabs.setObjectName("fimTabs")
        for tab in ("Overview", "Event History", "Baseline", "Settings"):
            self.tabs.addTab(tab)
        self.tabs.setExpanding(False)
        self.tabs.setDrawBase(False)
        self.tabs.setFixedHeight(30)
        left_layout.addWidget(self.tabs)

        self.tab_pages = QStackedWidget()
        self.tab_pages.addWidget(self._build_overview())
        self.tab_pages.addWidget(self._build_event_history())
        baseline_scroll = QScrollArea()
        baseline_scroll.setWidgetResizable(True)
        baseline_scroll.setFrameShape(QFrame.Shape.NoFrame)
        baseline_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        baseline_scroll.setMinimumSize(0, 0)
        baseline_scroll.setWidget(self._build_baseline())
        self.tab_pages.addWidget(baseline_scroll)
        self.tab_pages.addWidget(self._build_settings())
        left_layout.addWidget(self.tab_pages, 1)
        content.addWidget(left_column, 0, 0)

        right_column = QWidget()
        right_layout = QVBoxLayout(right_column)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        right_layout.addWidget(self._build_baseline_management())
        right_layout.addWidget(self._build_update_settings(), 1)
        content.addWidget(right_column, 0, 1)
        content.setColumnStretch(0, 70)
        content.setColumnStretch(1, 30)
        layout.addLayout(content, 1)

        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.tabs.setCurrentIndex(2)
        self.tab_pages.setCurrentIndex(0)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(
            max(3000, services.settings.endpoint_poll_interval_seconds * 1000)
        )
        self._refresh_timer.timeout.connect(self.refresh_data)
        self._baseline_status_timer = QTimer(self)
        self._baseline_status_timer.setInterval(1000)
        self._baseline_status_timer.timeout.connect(self._refresh_baseline_progress)
        self.refresh_data()

    def _build_overview(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 5, 0, 0)
        layout.setSpacing(10)
        metrics = QGridLayout()
        metrics.setContentsMargins(0, 0, 0, 0)
        metrics.setHorizontalSpacing(9)
        self.protected_count = self._metric_card(
            "Protected Folders", "0", "Folders monitored", "folder", "#15c28b"
        )
        self.tracked_count = self._metric_card(
            "Total Files Tracked", "0", "0 trusted · 0 new", "fingerprint", "#087ee5"
        )
        self.violation_count = self._metric_card(
            "Integrity Violations", "0", "No recent violations", "shield", "#e53167"
        )
        self.monitoring_count = self._metric_card(
            "Monitoring Status", "Inactive", "Watching for changes", "pulse", "#087ee5"
        )
        for column, card in enumerate(
            (
                self.protected_count,
                self.tracked_count,
                self.violation_count,
                self.monitoring_count,
            )
        ):
            metrics.addWidget(card, 0, column)
            metrics.setColumnStretch(column, 1)
        layout.addLayout(metrics)

        folders_panel, folders_layout = self._panel("Protected Folders", "folder-outline")
        folders_panel.setFixedHeight(172)
        folder_description = QLabel("These folders are monitored for file integrity changes.")
        folder_description.setObjectName("fimPanelDescription")
        self.folder_summary = folder_description
        folders_layout.addWidget(folder_description)
        manage = QPushButton("Manage Folders")
        manage.setObjectName("fimOutlineButton")
        manage.setIcon(self._icon("gear", 16))
        manage.clicked.connect(lambda: self.tabs.setCurrentIndex(3))
        header_layout = folders_panel.layout().itemAt(0).layout()
        header_layout.insertWidget(header_layout.count() - 1, manage)
        self.protected_folder_layout = QVBoxLayout()
        self.protected_folder_layout.setContentsMargins(0, 0, 0, 0)
        self.protected_folder_layout.setSpacing(0)
        folders_layout.addLayout(self.protected_folder_layout)
        layout.addWidget(folders_panel)

        events_panel, events_layout = self._panel("Recent File Integrity Events", "event-document")
        self.view_all_events_button = QPushButton("View All Events")
        self.view_all_events_button.setObjectName("fimOutlineButton")
        self.view_all_events_button.setIcon(self._icon("search", 14))
        self.view_all_events_button.clicked.connect(lambda: self.tabs.setCurrentIndex(1))
        event_heading = events_layout.itemAt(0).layout()
        event_heading.addStretch(1)
        event_heading.addWidget(self.view_all_events_button)
        self.table = DataTable(
            ("Time", "File", "Event Type", "Status", "Details"),
            empty_message="No file-integrity events have been recorded.",
        )
        self.table.setObjectName("fimTableHost")
        self._configure_compact_table(self.table)
        self.table.table.setObjectName("fimEventTable")
        self.table.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.table.customContextMenuRequested.connect(self._show_selected_action_menu)
        self.table.setMinimumHeight(185)
        self.table.state_view.setMinimumHeight(70)
        self.table.state_view.layout().setContentsMargins(8, 6, 8, 6)
        self.table.state_view.title_label.setStyleSheet("font-size:8pt;")
        self.table.state_view.message_label.setStyleSheet("font-size:7pt;")
        events_layout.addWidget(self.table, 1)
        events_panel.setMinimumHeight(250)
        layout.addWidget(events_panel, 1)

        self.investigate_button = QPushButton("Investigate Selected")
        self.investigate_button.setIcon(self._icon("search", 16))
        self.investigate_button.clicked.connect(self.investigate_selected)
        self.approve_button = QPushButton("Approve Selected Change")
        self.approve_button.setIcon(self._icon("check", 16))
        self.approve_button.clicked.connect(self.approve_selected)
        self.details_button = QPushButton("View Details")
        self.details_button.clicked.connect(self.show_selected_details)
        self.open_folder_button = QPushButton("Open Folder")
        self.open_folder_button.clicked.connect(self.open_selected_folder)
        self.evidence_button = QPushButton("Record Evidence")
        self.evidence_button.clicked.connect(self.record_selected_evidence)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setIcon(QIcon(icon_path("refresh.png")))
        self.refresh_button.clicked.connect(self.refresh_data)
        self.verify_button = QPushButton("Verify Now")
        self.verify_button.clicked.connect(self.verify_now)
        self.verify_button.hide()
        return page

    def _build_baseline_management(self) -> QFrame:
        panel, panel_layout = self._panel("Baseline Management", "baseline-shield")
        panel.setFixedHeight(196)
        panel_layout.addSpacing(1)
        status_row = QHBoxLayout()
        self.baseline_status_icon = QLabel()
        self.baseline_status_icon.setPixmap(self._icon_pixmap("check-circle", 32))
        status_row.addWidget(self.baseline_status_icon, 0, Qt.AlignmentFlag.AlignTop)
        status_text = QVBoxLayout()
        self.baseline_state_title = QLabel("Baseline is up to date")
        self.baseline_state_title.setObjectName("fimBaselineTitle")
        self.baseline_summary = QLabel("Last updated automatically:\nNot yet created")
        self.baseline_summary.setObjectName("fimBaselineSummary")
        status_text.addWidget(self.baseline_state_title)
        status_text.addWidget(self.baseline_summary)
        status_row.addLayout(status_text, 1)
        panel_layout.addLayout(status_row)
        update_frame = QFrame()
        update_frame.setObjectName("fimUpdateCard")
        update_layout = QHBoxLayout(update_frame)
        update_layout.setContentsMargins(10, 3, 8, 3)
        update_layout.setSpacing(8)
        refresh_icon = QLabel()
        refresh_icon.setPixmap(self._icon_pixmap("refresh-blue", 22))
        update_layout.addWidget(refresh_icon)
        update_text = QVBoxLayout()
        update_text.setSpacing(0)
        self.baseline_button = QPushButton("Update Baseline Now")
        self.baseline_button.setObjectName("fimUpdateButton")
        self.baseline_button.setToolTip(
            "Review detected changes first. This explicitly approves the current state."
        )
        self.baseline_button.clicked.connect(self._confirm_baseline_update)
        update_subtitle = QLabel("(Scans for legitimate changes)")
        update_subtitle.setObjectName("fimUpdateSubtitle")
        update_text.addWidget(self.baseline_button)
        update_text.addWidget(update_subtitle)
        update_layout.addLayout(update_text, 1)
        panel_layout.addWidget(update_frame)
        self.baseline_update_button = self.baseline_button
        auto_row = QHBoxLayout()
        auto_labels = QVBoxLayout()
        auto_title = QLabel("Automatic Baseline Updates  ⓘ")
        auto_title.setObjectName("fimAutoTitle")
        auto_subtitle = QLabel("Update baseline on approved changes only")
        auto_subtitle.setObjectName("fimPanelDescription")
        auto_labels.addWidget(auto_title)
        auto_labels.addWidget(auto_subtitle)
        auto_row.addLayout(auto_labels, 1)
        self.automatic_updates = QCheckBox()
        self.automatic_updates.setObjectName("fimSwitch")
        self.automatic_updates.setChecked(self.services.settings.file_integrity_auto_update_enabled)
        self.automatic_updates.toggled.connect(self._save_auto_update_setting)
        auto_row.addWidget(self.automatic_updates)
        panel_layout.addLayout(auto_row)
        self.auto_update_policy = QLabel(
            "Approval remains explicit; new files are never trusted automatically."
        )
        self.auto_update_policy.setObjectName("muted")
        self.auto_update_policy.setWordWrap(True)
        self.auto_update_policy.hide()
        return panel

    def _build_update_settings(self) -> QFrame:
        panel, settings_layout = self._panel("Auto Baseline & Update Settings", "gear")
        how_it_works = QLabel("How it works")
        how_it_works.setObjectName("fimSubheading")
        settings_layout.addWidget(how_it_works)
        for number, text in (
            (
                "1",
                "On first launch, PrivSentinel creates a trusted baseline from your selected folders.",
            ),
            (
                "2",
                "The baseline is updated automatically when you approve legitimate changes (e.g. new files or updates).",
            ),
            (
                "3",
                "New or modified files are flagged for review and not trusted until you approve them.",
            ),
        ):
            row = QHBoxLayout()
            badge = QLabel(number)
            badge.setObjectName("fimStepNumber")
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setFixedSize(21, 21)
            description = QLabel(text)
            description.setObjectName("fimStepText")
            description.setWordWrap(True)
            row.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
            row.addWidget(description, 1)
            settings_layout.addLayout(row)
        separator = QFrame()
        separator.setObjectName("fimDivider")
        separator.setFixedHeight(1)
        settings_layout.addWidget(separator)
        frequency_row = QHBoxLayout()
        frequency_label = QLabel("Update Frequency  ⓘ")
        frequency_label.setObjectName("fimSubheading")
        self.update_frequency = QComboBox()
        self.update_frequency.setObjectName("fimUpdateFrequency")
        self.update_frequency.addItem("On approved changes only", "approved")
        self.update_frequency.setToolTip(
            "Baseline changes require explicit approval; new files are never auto-trusted."
        )
        self.update_frequency.setEnabled(self.automatic_updates.isChecked())
        self.automatic_updates.toggled.connect(self.update_frequency.setEnabled)
        frequency_row.addWidget(frequency_label, 1)
        settings_layout.addLayout(frequency_row)
        settings_layout.addWidget(self.update_frequency)
        protected_header = QHBoxLayout()
        protected_icon = QLabel()
        protected_icon.setPixmap(self._icon_pixmap("folder-outline", 18))
        protected_header.addWidget(protected_icon)
        protected_label = QLabel("Protected Folders")
        protected_label.setObjectName("fimSubheading")
        protected_header.addWidget(protected_label)
        protected_header.addStretch(1)
        edit = QPushButton("Edit")
        edit.setObjectName("fimOutlineButton")
        edit.clicked.connect(lambda: self.tabs.setCurrentIndex(3))
        protected_header.addWidget(edit)
        settings_layout.addLayout(protected_header)
        self.settings_folder_layout = QVBoxLayout()
        self.settings_folder_layout.setSpacing(2)
        settings_layout.addLayout(self.settings_folder_layout)
        secure_note = QLabel(
            "ⓘ   SHA-256 hashes are stored in the local application database and "
            "the baseline is protected from automatic recreation."
        )
        secure_note.setObjectName("fimSecureNote")
        secure_note.setWordWrap(True)
        settings_layout.addWidget(secure_note)
        return panel

    def _panel(self, title: str, icon: str | None = None) -> tuple[QFrame, QVBoxLayout]:
        panel = QFrame()
        panel.setObjectName("fimPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 9, 12, 9)
        layout.setSpacing(5)
        heading = QHBoxLayout()
        heading.setContentsMargins(0, 0, 0, 0)
        heading.setSpacing(8)
        if icon is not None:
            icon_label = QLabel()
            icon_label.setPixmap(self._icon_pixmap(icon, 24))
            heading.addWidget(icon_label)
        title_label = QLabel(title)
        title_label.setObjectName("fimPanelTitle")
        heading.addWidget(title_label)
        heading.addStretch(1)
        layout.addLayout(heading)
        divider = QFrame()
        divider.setObjectName("fimDivider")
        divider.setFixedHeight(1)
        layout.addWidget(divider)
        return panel, layout

    @staticmethod
    def _configure_compact_table(table: DataTable) -> None:
        table.filter_input.hide()
        table.layout().setContentsMargins(0, 0, 0, 0)
        table.layout().setSpacing(0)
        table.table.verticalHeader().setDefaultSectionSize(44)
        table.table.horizontalHeader().setMinimumHeight(31)
        table.table.setShowGrid(False)
        table.table.setWordWrap(True)
        for column, width in enumerate((118, 178, 116, 92, 110)):
            table.table.setColumnWidth(column, width)
        table.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

    def _build_folder_rows(self) -> None:
        roots = self.services.settings.file_integrity_roots
        if roots == self._rendered_roots:
            return
        self._rendered_roots = roots
        while self.protected_folder_layout.count():
            item = self.protected_folder_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        while self.settings_folder_layout.count():
            item = self.settings_folder_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for root in roots:
            row = QHBoxLayout()
            row.setContentsMargins(2, 3, 2, 3)
            row.setSpacing(9)
            icon = QLabel()
            icon.setPixmap(self._icon_pixmap("folder-yellow", 25))
            text_layout = QVBoxLayout()
            text_layout.setContentsMargins(0, 0, 0, 0)
            text_layout.setSpacing(0)
            name = QLabel(Path(root).name or root)
            name.setObjectName("fimFolderName")
            path = QLabel(root)
            path.setObjectName("fimFolderPath")
            path.setToolTip(root)
            text_layout.addWidget(name)
            text_layout.addWidget(path)
            monitored = QLabel("Monitored")
            monitored.setObjectName("fimMonitoredPill")
            folder_menu_button = QPushButton("⋯")
            folder_menu_button.setObjectName("fimFolderMenu")
            folder_menu_button.setFixedSize(28, 28)
            folder_menu_button.clicked.connect(
                lambda _checked=False, folder=root, button=folder_menu_button: (
                    self._show_folder_menu(folder, button)
                )
            )
            row.addWidget(icon)
            row.addLayout(text_layout, 1)
            row.addWidget(monitored)
            row.addWidget(folder_menu_button)
            folder_widget = QWidget()
            folder_widget.setObjectName("fimFolderRow")
            folder_widget.setLayout(row)
            self.protected_folder_layout.addWidget(folder_widget)
            if root != roots[-1]:
                divider = QFrame()
                divider.setObjectName("fimDivider")
                divider.setFixedHeight(1)
                self.protected_folder_layout.addWidget(divider)

            monitored = QCheckBox(Path(root).name or root)
            monitored.setObjectName("fimFolderOption")
            monitored.setChecked(True)
            monitored.setToolTip(root)
            monitored.toggled.connect(
                lambda checked, folder=root: self._set_folder_enabled(folder, checked)
            )
            settings_row = QHBoxLayout()
            settings_row.addWidget(monitored)
            settings_row.addStretch(1)
            settings_state = QLabel("(Monitored)")
            settings_state.setObjectName("fimSettingsFolderState")
            settings_row.addWidget(settings_state)
            settings_widget = QWidget()
            settings_widget.setLayout(settings_row)
            self.settings_folder_layout.addWidget(settings_widget)
        if not roots:
            self.folder_summary.setText(
                "No protected folders configured. Select Manage Folders to add one."
            )
            settings_empty = QLabel("No protected folders configured.")
            settings_empty.setObjectName("muted")
            self.settings_folder_layout.addWidget(settings_empty)

    def _show_folder_menu(self, folder: str, button: QPushButton) -> None:
        menu = QMenu(self)
        open_action = menu.addAction("Open Folder")
        open_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(folder)))
        remove_action = menu.addAction("Stop Monitoring")
        remove_action.triggered.connect(lambda: self._set_folder_enabled(folder, False))
        menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    @staticmethod
    def _icon_pixmap(kind: str, size: int) -> QPixmap:
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.scale(size / 64, size / 64)
        cyan = QColor("#128dff")
        line_pen = QPen(cyan, 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        line_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(line_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        if kind == "folder":
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#0ec68b"))
            painter.drawRoundedRect(4, 4, 56, 56, 12, 12)
            path = QPainterPath()
            path.moveTo(13, 22)
            path.lineTo(13, 17)
            path.quadTo(13, 13, 18, 13)
            path.lineTo(28, 13)
            path.lineTo(34, 20)
            path.lineTo(47, 20)
            path.quadTo(52, 20, 52, 25)
            path.lineTo(52, 45)
            path.quadTo(52, 50, 47, 50)
            path.lineTo(18, 50)
            path.quadTo(13, 50, 13, 45)
            path.closeSubpath()
            painter.setBrush(QColor("#063c43"))
            painter.drawPath(path)
        elif kind == "fingerprint":
            painter.setPen(
                QPen(
                    QColor("#0b8aff"),
                    4,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            paths = (
                ((15, 45), (11, 19), (34, 9), (48, 19)),
                ((9, 37), (9, 22), (23, 12), (34, 12)),
                ((16, 51), (9, 36), (16, 19), (30, 17)),
                ((25, 56), (17, 39), (21, 25), (33, 23)),
                ((37, 54), (47, 39), (44, 28), (37, 22)),
                ((47, 45), (54, 33), (49, 21), (41, 16)),
                ((30, 43), (28, 32), (30, 28), (35, 28)),
                ((31, 50), (36, 38), (37, 32), (34, 28)),
            )
            for start, c1, c2, end in paths:
                path = QPainterPath()
                path.moveTo(*start)
                path.cubicTo(*c1, *c2, *end)
                painter.drawPath(path)
        elif kind == "shield":
            path = QPainterPath()
            path.moveTo(32, 5)
            path.lineTo(54, 14)
            path.lineTo(51, 37)
            path.quadTo(48, 52, 32, 60)
            path.quadTo(16, 52, 13, 37)
            path.lineTo(10, 14)
            path.closeSubpath()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#df2d67"))
            painter.drawPath(path)
            inner = QPainterPath()
            inner.moveTo(32, 14)
            inner.lineTo(45, 19)
            inner.lineTo(43, 36)
            inner.quadTo(41, 46, 32, 51)
            inner.quadTo(23, 46, 21, 36)
            inner.lineTo(19, 19)
            inner.closeSubpath()
            painter.setBrush(QColor("#8e1948"))
            painter.drawPath(inner)
            painter.setPen(
                QPen(
                    QColor("#ff8aaa"),
                    3,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            painter.drawLine(25, 31, 30, 36)
            painter.drawLine(30, 36, 40, 25)
        elif kind == "pulse":
            painter.setPen(
                QPen(
                    QColor("#078cff"),
                    5,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            path = QPainterPath()
            path.moveTo(4, 34)
            path.lineTo(17, 34)
            path.lineTo(24, 13)
            path.lineTo(31, 52)
            path.lineTo(39, 25)
            path.lineTo(45, 36)
            path.lineTo(60, 36)
            painter.drawPath(path)
        elif kind in {"folder-outline", "folder-yellow"}:
            path = QPainterPath()
            path.moveTo(7, 19)
            path.quadTo(7, 14, 12, 14)
            path.lineTo(27, 14)
            path.lineTo(33, 21)
            path.lineTo(52, 21)
            path.quadTo(57, 21, 57, 26)
            path.lineTo(57, 48)
            path.quadTo(57, 53, 52, 53)
            path.lineTo(12, 53)
            path.quadTo(7, 53, 7, 48)
            path.closeSubpath()
            if kind == "folder-yellow":
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#ffbd45"))
                painter.drawPath(path)
            else:
                painter.setPen(
                    QPen(
                        QColor("#249cff"),
                        5,
                        Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap,
                        Qt.PenJoinStyle.RoundJoin,
                    )
                )
                painter.drawPath(path)
        elif kind in {"event-document", "page", "file-pdf", "file-code", "file-text"}:
            color = QColor("#219bff")
            if kind == "file-pdf":
                color = QColor("#f43c78")
            elif kind == "file-code":
                color = QColor("#12a9f4")
            elif kind == "file-text":
                color = QColor("#31a4ff")
            painter.setPen(
                QPen(
                    color,
                    4,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            path = QPainterPath()
            path.moveTo(18, 8)
            path.lineTo(39, 8)
            path.lineTo(51, 20)
            path.lineTo(51, 53)
            path.quadTo(51, 57, 47, 57)
            path.lineTo(17, 57)
            path.quadTo(13, 57, 13, 53)
            path.lineTo(13, 13)
            path.quadTo(13, 8, 18, 8)
            path.closeSubpath()
            painter.drawPath(path)
            painter.drawLine(39, 9, 39, 20)
            painter.drawLine(39, 20, 50, 20)
            painter.drawLine(22, 31, 41, 31)
            painter.drawLine(22, 40, 41, 40)
            if kind == "page":
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#06162b"))
                painter.drawEllipse(37, 37, 26, 26)
                painter.setPen(QPen(QColor("#10a9ff"), 3))
                painter.setBrush(QColor("#06264a"))
                painter.drawEllipse(39, 39, 22, 22)
                painter.drawLine(45, 50, 49, 54)
                painter.drawLine(49, 54, 56, 46)
        elif kind in {"baseline-shield", "gear"}:
            if kind == "gear":
                painter.setPen(
                    QPen(QColor("#158bdb"), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
                )
                painter.drawEllipse(19, 19, 26, 26)
                painter.setPen(
                    QPen(QColor("#158bdb"), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
                )
                for x1, y1, x2, y2 in (
                    (32, 5, 32, 14),
                    (32, 50, 32, 59),
                    (5, 32, 14, 32),
                    (50, 32, 59, 32),
                    (13, 13, 19, 19),
                    (45, 45, 51, 51),
                    (13, 51, 19, 45),
                    (45, 19, 51, 13),
                ):
                    painter.drawLine(x1, y1, x2, y2)
            else:
                path = QPainterPath()
                path.moveTo(32, 6)
                path.lineTo(53, 15)
                path.lineTo(50, 39)
                path.quadTo(46, 53, 32, 59)
                path.quadTo(18, 53, 14, 39)
                path.lineTo(11, 15)
                path.closeSubpath()
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#087fe5"))
                painter.drawPath(path)
                painter.setPen(
                    QPen(
                        QColor("#d7f1ff"),
                        4,
                        Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap,
                        Qt.PenJoinStyle.RoundJoin,
                    )
                )
                painter.drawLine(23, 32, 30, 39)
                painter.drawLine(30, 39, 42, 25)
        elif kind == "check-circle":
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#31ce91"))
            painter.drawEllipse(3, 3, 58, 58)
            painter.setPen(
                QPen(
                    QColor("#063d46"),
                    6,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            painter.drawLine(18, 33, 27, 42)
            painter.drawLine(27, 42, 46, 22)
        elif kind == "check":
            painter.setPen(
                QPen(
                    QColor("#35d392"),
                    6,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            painter.drawLine(13, 34, 27, 48)
            painter.drawLine(27, 48, 52, 17)
        elif kind == "refresh-blue":
            painter.setPen(
                QPen(
                    QColor("#c5e7ff"),
                    5,
                    Qt.PenStyle.SolidLine,
                    Qt.PenCapStyle.RoundCap,
                    Qt.PenJoinStyle.RoundJoin,
                )
            )
            path = QPainterPath()
            path.moveTo(50, 22)
            path.arcTo(12, 12, 40, 40, 35, 295)
            painter.drawPath(path)
            painter.drawLine(50, 12, 50, 23)
            painter.drawLine(50, 23, 39, 23)
        elif kind == "search":
            painter.setPen(
                QPen(QColor("#52b6ff"), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            )
            painter.drawEllipse(8, 8, 34, 34)
            painter.drawLine(37, 38, 56, 57)
        elif kind == "info":
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#128dff"))
            painter.drawEllipse(5, 5, 54, 54)
            painter.setPen(
                QPen(QColor("#e9f6ff"), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            )
            painter.drawPoint(32, 20)
            painter.drawLine(32, 29, 32, 46)
        elif kind == "modified":
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#ffb532"))
            painter.drawEllipse(4, 4, 56, 56)
            painter.setPen(
                QPen(QColor("#402906"), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            )
            painter.drawLine(32, 18, 32, 36)
            painter.drawPoint(32, 46)
        elif kind == "deleted":
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#ef3472"))
            painter.drawEllipse(4, 4, 56, 56)
            painter.setPen(
                QPen(QColor("#ffffff"), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            )
            painter.drawLine(20, 32, 44, 32)
        painter.end()
        return pixmap

    @classmethod
    def _icon(cls, kind: str, size: int) -> QIcon:
        return QIcon(cls._icon_pixmap(kind, size))

    def _set_folder_enabled(self, folder: str, enabled: bool) -> None:
        roots = self._roots()
        updated_roots = (
            tuple(dict.fromkeys((*roots, folder)))
            if enabled
            else tuple(root for root in roots if root != folder)
        )
        self.roots.setPlainText("\n".join(updated_roots))
        if not updated_roots:
            self.enabled.setChecked(False)
        self._save_configuration()

    def _show_actions_menu(self) -> None:
        menu = QMenu(self)
        for label, callback in (
            ("Verify now", self.verify_now),
            ("Investigate selected", self.investigate_selected),
            ("Approve selected change", self.approve_selected),
            ("View file details", self.show_selected_details),
            ("Open containing folder", self.open_selected_folder),
            ("Record evidence", self.record_selected_evidence),
        ):
            action = QAction(label, menu)
            action.triggered.connect(callback)
            menu.addAction(action)
        source = self.sender()
        anchor = source if isinstance(source, QWidget) else self
        menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))

    def _show_selected_action_menu(self, position: QPoint) -> None:
        index = self.table.table.indexAt(position)
        if index.isValid():
            self.table.table.selectRow(index.row())
        menu = QMenu(self)
        for label, callback in (
            ("Verify all protected files", self.verify_now),
            ("Investigate selected event", self.investigate_selected),
            ("Approve selected change", self.approve_selected),
            ("View file details", self.show_selected_details),
            ("Open containing folder", self.open_selected_folder),
            ("Record evidence", self.record_selected_evidence),
        ):
            action = QAction(label, menu)
            action.triggered.connect(callback)
            menu.addAction(action)
        menu.exec(self.table.table.viewport().mapToGlobal(position))

    def _on_tab_changed(self, index: int) -> None:
        self.tab_pages.setCurrentIndex(index)

    def _build_event_history(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)
        heading = QHBoxLayout()
        title = QLabel("Recent File Integrity Events")
        title.setObjectName("sectionTitle")
        heading.addWidget(title)
        heading.addStretch(1)
        actions = QPushButton("More Actions")
        actions.setObjectName("fimQuietButton")
        actions.clicked.connect(self._show_actions_menu)
        heading.addWidget(actions)
        layout.addLayout(heading)
        self.events_table = DataTable(
            ("Time", "File", "Event Type", "Status", "Details"),
            empty_message="No file-integrity events have been recorded.",
        )
        self._configure_compact_table(self.events_table)
        layout.addWidget(self.events_table, 1)
        return page

    def _build_baseline(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)
        heading = QHBoxLayout()
        title = QLabel("Trusted Baseline Files")
        title.setObjectName("sectionTitle")
        heading.addWidget(title)
        heading.addStretch(1)
        self.baseline_update_button = QPushButton("Update Baseline")
        self.baseline_update_button.clicked.connect(self._confirm_baseline_update)
        heading.addWidget(self.baseline_update_button)
        layout.addLayout(heading)
        self.baseline_table = DataTable(
            ("File", "SHA-256", "Last Approved", "Size"),
            empty_message="The initial trusted baseline will be created on first launch.",
        )
        layout.addWidget(self.baseline_table, 1)
        approvals_title = QLabel("Approval History")
        approvals_title.setObjectName("sectionTitle")
        layout.addWidget(approvals_title)
        self.approvals_table = DataTable(
            ("Approved At", "File", "Previous SHA-256", "Approved SHA-256", "Approved By"),
            empty_message="Approved baseline changes are retained here.",
        )
        self.approvals_table.setMaximumHeight(220)
        layout.addWidget(self.approvals_table)
        return page

    def _build_settings(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)
        form = QFormLayout()
        form.setSpacing(8)
        self.roots = QPlainTextEdit()
        self.roots.setPlaceholderText("Protected folders, one absolute path per line")
        self.roots.setMaximumHeight(110)
        self.roots.setPlainText("\n".join(self.services.settings.file_integrity_roots))
        roots_row = QHBoxLayout()
        roots_row.addWidget(self.roots, 1)
        self.add_folder_button = QPushButton("Add folder…")
        self.add_folder_button.clicked.connect(self._add_folder)
        roots_row.addWidget(self.add_folder_button)
        form.addRow("Protected folders", roots_row)
        self.exclusions = QPlainTextEdit()
        self.exclusions.setPlaceholderText(
            "Excluded file names or paths, one wildcard pattern per line"
        )
        self.exclusions.setMaximumHeight(70)
        self.exclusions.setPlainText("\n".join(self.services.settings.file_integrity_exclusions))
        form.addRow("Exclusions", self.exclusions)
        self.enabled = QPushButton()
        self.enabled.setCheckable(True)
        self.enabled.setChecked(self.services.settings.file_integrity_monitoring_enabled)
        self.enabled.clicked.connect(self._on_toggle_monitoring)
        controls = QHBoxLayout()
        controls.addWidget(self.enabled)
        self.save_button = QPushButton("Save Configuration")
        self.save_button.setIcon(QIcon(icon_path("shield-check.png")))
        self.save_button.clicked.connect(self._save_configuration)
        controls.addWidget(self.save_button)
        self.settings_verify_button = QPushButton("Verify Now")
        self.settings_verify_button.clicked.connect(self.verify_now)
        controls.addWidget(self.settings_verify_button)
        controls.addStretch(1)
        form.addRow("Monitoring controls", controls)
        layout.addLayout(form)
        self.settings_status = StatusIndicator("Local monitoring is ready", "info")
        layout.addWidget(self.settings_status)
        layout.addStretch(1)
        self._update_monitoring_label()
        return page

    def _metric_card(
        self, title: str, value: str, description: str, icon: str, accent: str
    ) -> QFrame:
        card = QFrame()
        card.setObjectName("fimMetricCard")
        card.setProperty("accent", accent)
        card.setMinimumHeight(82)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(7, 8, 6, 8)
        layout.setSpacing(5)
        icon_label = QLabel()
        icon_label.setPixmap(self._icon_pixmap(icon, 32))
        layout.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignVCenter)
        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(1)
        label = QLabel(title)
        label.setObjectName("caption")
        label.setStyleSheet("font-size:7pt;")
        label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        text_layout.addWidget(label)
        value_label = QLabel(value)
        value_label.setObjectName("fimMetricValue")
        value_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        description_label = QLabel(description)
        description_label.setObjectName("fimMetricDescription")
        description_label.setWordWrap(False)
        description_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        text_layout.addWidget(value_label)
        label.setMinimumWidth(0)
        value_label.setMinimumWidth(0)
        text_layout.addWidget(description_label)
        description_label.setMinimumWidth(0)
        description_label.setWordWrap(False)
        layout.addLayout(text_layout, 1)
        if title == "Protected Folders":
            arrow = QLabel("›")
            arrow.setObjectName("fimMetricArrow")
            layout.addWidget(arrow)
        card.value_label = value_label
        card.description_label = description_label
        return card

    def _roots(self) -> tuple[str, ...]:
        return tuple(line.strip() for line in self.roots.toPlainText().splitlines() if line.strip())

    def _exclusions(self) -> tuple[str, ...]:
        return tuple(
            line.strip() for line in self.exclusions.toPlainText().splitlines() if line.strip()
        )

    def _add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select file-integrity folder")
        if folder and folder not in self._roots():
            self.roots.setPlainText("\n".join((*self._roots(), folder)))

    def _save_configuration(self, _checked: bool = False) -> None:
        roots = self._roots()
        settings = self.services.settings
        enabled = self.enabled.isChecked()
        if enabled and not roots:
            self._set_status("Add a protected folder before enabling monitoring", "error")
            self.enabled.setChecked(False)
            self._update_monitoring_label()
            return
        try:
            self.services.save_settings(
                replace(
                    settings,
                    file_integrity_roots=roots,
                    file_integrity_exclusions=self._exclusions(),
                    file_integrity_monitoring_enabled=enabled,
                    file_integrity_auto_update_enabled=self.automatic_updates.isChecked(),
                )
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._set_status(f"Could not save configuration: {exc}", "error")
            return
        if roots and not self.services.endpoint_service.has_file_baseline(
            roots, self._exclusions()
        ):
            self._set_status(
                "Folder configuration changed. Update the baseline to apply it.", "warning"
            )
        else:
            self._set_status("Configuration saved", "success")
        self._update_monitoring_label()
        self._build_folder_rows()
        self.refresh_data()

    def _save_auto_update_setting(self, enabled: bool) -> None:
        try:
            self.services.save_settings(
                replace(
                    self.services.settings,
                    file_integrity_auto_update_enabled=enabled,
                )
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._set_status(f"Could not save automatic-update setting: {exc}", "error")
            self.automatic_updates.blockSignals(True)
            self.automatic_updates.setChecked(not enabled)
            self.automatic_updates.blockSignals(False)
            self.update_frequency.setEnabled(not enabled)
            return
        self.update_frequency.setEnabled(enabled)
        self._set_status(
            "Automatic updates enabled for explicitly approved changes"
            if enabled
            else "Automatic updates disabled; changes remain pending until baseline update",
            "success" if enabled else "info",
        )

    def _on_toggle_monitoring(self, _checked: bool) -> None:
        self._update_monitoring_label()
        self._save_configuration()

    def _update_monitoring_label(self) -> None:
        self.enabled.setText(
            "Monitoring enabled" if self.enabled.isChecked() else "Monitoring disabled"
        )

    def ensure_initial_baseline(self) -> None:
        if not self._roots() or self._has_any_baseline():
            return
        self.enabled.setChecked(self.services.settings.file_integrity_monitoring_enabled)
        self.start_baseline()

    def _confirm_baseline_update(self, _checked: bool = False) -> None:
        if not self._roots():
            self.tabs.setCurrentIndex(3)
            self._set_status("Add at least one protected folder first", "warning")
            return
        if not ConfirmationDialog.confirm(
            self,
            "Update trusted baseline",
            "This will approve the current state of every file in the selected folders. "
            "Unreviewed files will become trusted. Continue only after reviewing the changes.",
        ):
            return
        self.start_baseline()

    def start_baseline(self) -> None:
        if self._baseline_worker is not None and self._baseline_worker.isRunning():
            self.baselineSetupFinished.emit(False, "A baseline operation is already running.")
            return
        roots = self._roots()
        if not roots:
            message = "Add at least one protected folder before creating a baseline."
            self.enabled.setChecked(False)
            self._update_monitoring_label()
            self._set_status(message, "error")
            self.baselineSetupFinished.emit(False, message)
            return
        try:
            self._baseline_was_existing = self._has_any_baseline()
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            message = f"Could not check the saved baseline: {exc}"
            self.enabled.setChecked(False)
            self._update_monitoring_label()
            self._set_status(message, "error")
            self.baselineSetupFinished.emit(False, message)
            return
        self._resume_after_baseline = self.enabled.isChecked()
        try:
            self.services.save_settings(
                replace(
                    self.services.settings,
                    file_integrity_roots=roots,
                    file_integrity_exclusions=self._exclusions(),
                    file_integrity_monitoring_enabled=False,
                )
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            message = f"Could not save the protected folders: {exc}"
            self.enabled.setChecked(False)
            self._update_monitoring_label()
            self._set_status(message, "error")
            self.baselineSetupFinished.emit(False, message)
            return
        self._set_controls_enabled(False)
        self._baseline_started_at = time.monotonic()
        self._baseline_progress_count = 0
        self._baseline_total_count = -1
        self._set_status("Hashing files for trusted baseline…", "info")
        self.status.show()
        self.baseline_progress.show()
        worker = _BaselineWorker(self.services, roots, self._exclusions(), self)
        self._baseline_worker = worker
        worker.baselineCreated.connect(self._on_baseline_created)
        worker.baselineFailed.connect(self._on_baseline_failed)
        worker.progressChanged.connect(self._on_baseline_progress)
        worker.finished.connect(self._on_baseline_finished)
        self._refresh_baseline_progress()
        self._baseline_status_timer.start()
        worker.start()

    def _on_baseline_progress(self, count: int, total: int) -> None:
        self._baseline_progress_count = count
        self._baseline_total_count = total
        self.baselineProgressChanged.emit(count, total)
        if total < 0:
            self.baseline_progress.setRange(0, 0)
            self.baseline_progress.setFormat("Counting files to hash…")
        elif total == 0:
            self.baseline_progress.setRange(0, 1)
            self.baseline_progress.setValue(1)
            self.baseline_progress.setFormat("No files found; saving empty baseline")
        else:
            self.baseline_progress.setRange(0, total)
            self.baseline_progress.setValue(count)
            self.baseline_progress.setFormat("Hashing files: %v / %m")
        self._refresh_baseline_progress()

    def _refresh_baseline_progress(self) -> None:
        if self._baseline_started_at is None:
            return
        elapsed = int(time.monotonic() - self._baseline_started_at)
        if self._baseline_total_count < 0:
            text = f"Finding files to hash… {elapsed:,} sec"
        else:
            text = (
                f"Hashing files… {self._baseline_progress_count:,} of "
                f"{self._baseline_total_count:,} · {elapsed:,} sec"
            )
        self._set_status(text, "info")

    def _on_baseline_created(self, count: int) -> None:
        self._baseline_status_timer.stop()
        self._baseline_started_at = None
        if self._resume_after_baseline:
            self.enabled.setChecked(True)
            try:
                self.services.save_settings(
                    replace(
                        self.services.settings,
                        file_integrity_monitoring_enabled=True,
                    )
                )
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                self.enabled.setChecked(False)
                self._update_monitoring_label()
                database_path = self.services.paths.database_file
                message = (
                    "Baseline created and hashes saved to "
                    f"{database_path}, but file-integrity monitoring could not be "
                    f"enabled: {exc}"
                )
                self._set_status(message, "error")
                self.refresh_data()
                self.baselineSetupFinished.emit(False, message)
                return
            self._update_monitoring_label()
        action = "updated" if self._baseline_was_existing else "created"
        empty_note = " (no files found)" if count == 0 else ""
        message = (
            f"Trusted baseline {action}{empty_note} · {count:,} files · "
            f"hashes saved to {self.services.paths.database_file}"
        )
        if self._resume_after_baseline:
            message += " · file-integrity monitoring enabled"
        self.refresh_data()
        self._set_status(message, "success")
        self.baselineSetupFinished.emit(True, message)

    def _on_baseline_failed(self, message: str) -> None:
        self._baseline_status_timer.stop()
        self._baseline_started_at = None
        self.enabled.setChecked(False)
        self._update_monitoring_label()
        self.refresh_data()
        detail = (
            f"Baseline failed: {message} No baseline changes were saved to "
            f"{self.services.paths.database_file}. Monitoring remains off."
        )
        self._set_status(detail, "error")
        self.baselineSetupFinished.emit(False, detail)

    def _on_baseline_finished(self) -> None:
        self._baseline_status_timer.stop()
        self._baseline_started_at = None
        self.baseline_progress.hide()
        self._set_controls_enabled(True)
        self._baseline_worker = None

    def _set_controls_enabled(self, enabled: bool) -> None:
        for widget in (
            self.roots,
            self.exclusions,
            self.add_folder_button,
            self.enabled,
            self.save_button,
            self.baseline_button,
            self.baseline_update_button,
            self.verify_button,
        ):
            widget.setEnabled(enabled)

    def verify_now(self) -> None:
        if self._verify_worker is not None and self._verify_worker.isRunning():
            return
        if not self.services.endpoint_service.has_file_baseline():
            self._set_status("Create or update a trusted baseline before verifying", "warning")
            return
        self.verify_button.setEnabled(False)
        worker = _VerifyWorker(self.services, self)
        self._verify_worker = worker
        worker.completed.connect(self._on_verify_completed)
        worker.failed.connect(self._on_verify_failed)
        worker.finished.connect(self._on_verify_finished)
        worker.start()
        self._set_status("Verifying protected files with SHA-256…", "info")

    def _on_verify_completed(self, count: int) -> None:
        self._set_status(
            f"Verification complete · {count:,} new finding(s)", "warning" if count else "success"
        )
        self.refresh_data()

    def _on_verify_failed(self, message: str) -> None:
        self._set_status(f"Verification failed: {message}", "error")

    def _on_verify_finished(self) -> None:
        self.verify_button.setEnabled(True)
        self._verify_worker = None

    def _selected_file_path(self) -> str | None:
        if self.tabs.currentIndex() == 1:
            active_table = self.events_table
        elif self.tabs.currentIndex() == 2:
            active_table = self.baseline_table
        else:
            active_table = self.table
        selected_ids = active_table.selected_ids
        if not selected_ids:
            return None
        return self._row_path_by_id.get(selected_ids[0], selected_ids[0])

    def approve_selected(self) -> None:
        if not self.automatic_updates.isChecked():
            self._set_status(
                "Automatic baseline updates are disabled. Use Update Baseline Now "
                "after reviewing the pending changes.",
                "warning",
            )
            return
        path = self._selected_file_path()
        if path is None:
            self._set_status("Select a file or finding to approve", "warning")
            return
        if not ConfirmationDialog.confirm(
            self,
            "Approve file change",
            f"Trust the current state of this file?\n\n{path}",
        ):
            return
        try:
            self.services.endpoint_service.approve_file_integrity_change(path)
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._set_status(f"Could not approve file change: {exc}", "error")
            return
        self._set_status("File state approved and recorded in the audit log", "success")
        self.refresh_data()

    def investigate_selected(self) -> None:
        active_table = self.events_table if self.tabs.currentIndex() == 1 else self.table
        selected_ids = active_table.selected_ids
        if not selected_ids:
            self._set_status("Select an event to investigate", "warning")
            return
        event_id = selected_ids[0]
        try:
            event = self.services.database.fetchone(
                "SELECT id, description FROM security_events WHERE id = ?", (event_id,)
            )
            if event is None:
                self._set_status("Select a detected event to start an investigation", "warning")
                return
            repository = self.services.security_repository
            investigation_id = repository.create_investigation(
                f"File integrity: {str(event['description'])[:150]}"
            )
            repository.link_event_to_investigation(investigation_id, event_id)
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self._set_status(f"Could not start investigation: {exc}", "error")
            return
        self.pageRequested.emit("investigations")

    def show_selected_details(self) -> None:
        path = self._selected_file_path()
        if path is None:
            self._set_status("Select a file to view its details", "warning")
            return
        row = self.services.database.fetchone(
            "SELECT sha256, size, captured_at FROM file_integrity_baselines WHERE path = ?",
            (path,),
        )
        if row is None:
            QMessageBox.information(self, "File details", f"Path:\n{path}\n\nNo trusted baseline.")
            return
        QMessageBox.information(
            self,
            "Trusted file details",
            f"Path: {path}\n\nSHA-256: {row['sha256']}\n\n"
            f"Size: {int(row['size']):,} bytes\n\nLast approved: {row['captured_at']}",
        )

    def open_selected_folder(self) -> None:
        path = self._selected_file_path()
        if path is None:
            self._set_status("Select a file to open its folder", "warning")
            return
        folder = Path(path).parent
        if not folder.is_dir():
            self._set_status("The file's folder is no longer available", "warning")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder))):
            self._set_status(f"Could not open folder: {folder}", "error")

    def record_selected_evidence(self) -> None:
        path = self._selected_file_path()
        if path is None:
            self._set_status("Select a file to record as evidence", "warning")
            return
        if self._evidence_worker is not None and self._evidence_worker.isRunning():
            return
        worker = _EvidenceWorker(self.services, path, self)
        self._evidence_worker = worker
        worker.completed.connect(self._on_evidence_recorded)
        worker.failed.connect(self._on_evidence_failed)
        worker.finished.connect(self._on_evidence_finished)
        self.evidence_button.setEnabled(False)
        self._set_status("Hashing selected file and recording evidence…", "info")
        worker.start()

    def _on_evidence_recorded(self, _evidence_id: str) -> None:
        self._set_status("File hash recorded in Evidence", "success")
        self.pageRequested.emit("evidence")

    def _on_evidence_failed(self, message: str) -> None:
        self._set_status(f"Could not record evidence: {message}", "error")

    def _on_evidence_finished(self) -> None:
        self.evidence_button.setEnabled(True)
        self._evidence_worker = None

    def _has_any_baseline(self) -> bool:
        return (
            self.services.database.fetchone(
                "SELECT 1 FROM file_integrity_baseline_config WHERE id = 1"
            )
            is not None
        )

    def _has_current_baseline(
        self,
        roots: tuple[str, ...],
        exclusions: tuple[str, ...],
    ) -> bool:
        return self.services.endpoint_service.has_file_baseline(roots, exclusions)

    def refresh_data(self) -> None:
        try:
            baseline_rows = self.services.database.fetchall(
                "SELECT path, sha256, size, captured_at FROM file_integrity_baselines ORDER BY path"
            )
            has_current_baseline = self._has_current_baseline(
                self.services.settings.file_integrity_roots,
                self.services.settings.file_integrity_exclusions,
            )
            event_rows = self.services.database.fetchall(
                "SELECT id, occurred_at, event_type, severity, description, attributes_json "
                "FROM security_events WHERE source = 'file-integrity' "
                "ORDER BY occurred_at DESC LIMIT 500"
            )
            approval_rows = self.services.database.fetchall(
                "SELECT path, previous_sha256, approved_sha256, actor, approved_at "
                "FROM file_integrity_approvals ORDER BY approved_at DESC LIMIT 500"
            )
            findings = self.services.database.fetchone(
                "SELECT COUNT(*) AS count FROM file_integrity_findings"
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error, json.JSONDecodeError) as exc:
            self.table.show_error(f"Could not load file-integrity data: {exc}")
            self._set_status(f"Local data unavailable: {exc}", "error")
            return

        rows: list[tuple[object, ...]] = []
        row_ids: list[str] = []
        self._row_path_by_id.clear()
        for event in event_rows[:5]:
            attributes = json.loads(event["attributes_json"])
            path = str(attributes.get("path", "Unknown file"))
            file_name = Path(path).name or path
            folder = str(Path(path).parent)
            event_type = str(event["event_type"]).casefold()
            if "delet" in event_type:
                display_type = "Deleted"
                status_text = "Investigate"
                details = "File no longer exists"
            elif "modif" in event_type or "chang" in event_type:
                display_type = "Modified"
                status_text = "Review Required"
                details = "Hash changed"
            elif "new" in event_type or "creat" in event_type:
                display_type = "New File"
                status_text = "Review Required"
                details = "New file detected"
            elif "renam" in event_type:
                display_type = "Renamed"
                status_text = "Review Required"
                details = "File path changed"
            else:
                display_type = str(event["event_type"]).replace("_", " ").title()
                status_text = "Normal" if str(event["severity"]).casefold() == "low" else "Review"
                details = str(event["description"])
            row_id = str(event["id"])
            rows.append(
                (
                    self._format_event_time(str(event["occurred_at"])),
                    f"{file_name}\n{folder}",
                    display_type,
                    status_text,
                    details,
                )
            )
            row_ids.append(row_id)
            self._row_path_by_id[row_id] = path
        self.table.set_rows(rows, row_ids)
        self._style_recent_events(rows, event_rows[:5])
        self.baseline_table.set_rows(
            [
                (
                    row["path"],
                    row["sha256"],
                    row["captured_at"],
                    f"{int(row['size']):,} bytes",
                )
                for row in baseline_rows
            ],
            [str(row["path"]) for row in baseline_rows],
        )
        self.approvals_table.set_rows(
            [
                (
                    row["approved_at"],
                    row["path"],
                    row["previous_sha256"] or "—",
                    row["approved_sha256"] or "Deleted",
                    row["actor"],
                )
                for row in approval_rows
            ]
        )
        history: list[tuple[object, ...]] = []
        history_ids: list[str] = []
        for row in event_rows:
            attributes = json.loads(row["attributes_json"])
            path = str(attributes.get("path", "Unknown file"))
            self._row_path_by_id[str(row["id"])] = path
            history.append(
                (
                    self._format_event_time(str(row["occurred_at"])),
                    Path(path).name,
                    str(row["event_type"]).replace("_", " ").title(),
                    str(row["severity"]).title(),
                    str(row["description"]),
                )
            )
            history_ids.append(str(row["id"]))
        self.events_table.set_rows(history, history_ids)

        settings = self.services.settings
        roots = settings.file_integrity_roots
        self.automatic_updates.blockSignals(True)
        self.automatic_updates.setChecked(settings.file_integrity_auto_update_enabled)
        self.automatic_updates.blockSignals(False)
        self.update_frequency.setEnabled(settings.file_integrity_auto_update_enabled)
        self.protected_count.value_label.setText(str(len(roots)))
        self.protected_count.description_label.setText("Folders monitored")
        finding_count = int(findings["count"]) if findings else 0
        self.tracked_count.value_label.setText(f"{len(baseline_rows) + finding_count:,}")
        self.tracked_count.description_label.setText(
            f"{len(baseline_rows):,} trusted · {finding_count:,} new"
        )
        self.violation_count.value_label.setText(str(finding_count))
        self.violation_count.description_label.setText(
            "No recent violations" if not finding_count else "Review required"
        )
        running = self._is_running()
        self.monitoring_count.value_label.setText(
            '<span style="color:#28ce91">●</span> Active' if running else "Inactive"
        )
        self.monitoring_count.description_label.setText(
            "Watching for changes" if running else "Monitoring paused"
        )
        self.folder_summary.setText(
            "These folders are monitored for file integrity changes."
            if roots
            else "No protected folders configured. Add folders in Settings."
        )
        self._build_folder_rows()
        latest_baseline = max((str(row["captured_at"]) for row in baseline_rows), default=None)
        last_updated = (
            self._format_event_time(latest_baseline) if latest_baseline else "Not yet created"
        )
        self.baseline_summary.setText(f"Last updated automatically:\n{last_updated}")
        self.baseline_state_title.setText(
            "Baseline is up to date" if has_current_baseline else "Baseline setup required"
        )
        self.baseline_status_icon.setPixmap(
            self._icon_pixmap("check-circle" if has_current_baseline else "modified", 32)
        )
        self.baseline_summary.setProperty(
            "baselineState", "ready" if has_current_baseline else "missing"
        )
        self.baseline_summary.style().unpolish(self.baseline_summary)
        self.baseline_summary.style().polish(self.baseline_summary)
        worker = self._baseline_worker
        if worker is None or not worker.isRunning():
            if has_current_baseline:
                self._set_status(
                    f"{len(baseline_rows):,} baseline files · "
                    f"{finding_count:,} unresolved change(s)",
                    "success" if finding_count == 0 else "warning",
                )
            else:
                self._set_status("Baseline requires setup or an explicit update", "warning")

    @staticmethod
    def _format_event_time(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return value
        return parsed.strftime("%b %d, %Y %I:%M %p").replace(" 0", " ")

    def _style_recent_events(
        self,
        rows: list[tuple[object, ...]],
        events: list[sqlite3.Row],
    ) -> None:
        table = self.table.table
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            event = events[row_index]
            path = self._row_path_by_id.get(str(event["id"]), "")
            suffix = Path(path).suffix.casefold()
            file_icon = (
                "file-pdf"
                if suffix == ".pdf"
                else "file-code"
                if suffix in {".exe", ".dll", ".ps1", ".py"}
                else "file-text"
            )
            file_item = table.item(row_index, 1)
            if file_item is not None:
                file_item.setIcon(self._icon(file_icon, 20))
                file_item.setTextAlignment(
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                )
            event_type = str(row[2])
            type_item = table.item(row_index, 2)
            status_item = table.item(row_index, 3)
            if type_item is not None:
                if event_type == "Deleted":
                    type_item.setIcon(self._icon("deleted", 17))
                    type_item.setForeground(QColor("#f43c78"))
                elif event_type in {"Modified", "New File", "Renamed"}:
                    type_item.setIcon(self._icon("modified", 17))
                    type_item.setForeground(QColor("#ffb532"))
                else:
                    type_item.setIcon(self._icon("check-circle", 17))
                    type_item.setForeground(QColor("#4bd6a0"))
            if status_item is not None:
                status = str(row[3])
                badge = QLabel(status)
                badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
                badge.setObjectName(
                    "fimEventPillNormal"
                    if status == "Normal"
                    else "fimEventPillInvestigate"
                    if status == "Investigate"
                    else "fimEventPillReview"
                )
                table.setCellWidget(row_index, 3, badge)
            table.setRowHeight(row_index, 44)

    def _set_status(self, message: str, state: str) -> None:
        self.status.set_text(message)
        self.status.set_state(state)
        self.settings_status.set_text(message)
        self.settings_status.set_state(state)

    def showEvent(self, event: QEvent) -> None:
        super().showEvent(event)
        settings = self.services.settings
        self.roots.setPlainText("\n".join(settings.file_integrity_roots))
        self.exclusions.setPlainText("\n".join(settings.file_integrity_exclusions))
        self.enabled.setChecked(settings.file_integrity_monitoring_enabled)
        self._update_monitoring_label()
        self._build_folder_rows()
        self.refresh_data()
        self._refresh_timer.start()

    def hideEvent(self, event: QEvent) -> None:
        self._refresh_timer.stop()
        super().hideEvent(event)

    def closeEvent(self, event: QEvent) -> None:
        self.stop_workers()
        super().closeEvent(event)

    def stop_workers(self) -> None:
        worker = self._baseline_worker
        if worker is not None and worker.isRunning():
            worker.wait()
        verify_worker = self._verify_worker
        if verify_worker is not None and verify_worker.isRunning():
            verify_worker.wait()
        evidence_worker = self._evidence_worker
        if evidence_worker is not None and evidence_worker.isRunning():
            evidence_worker.wait()

    def _is_running(self) -> bool:
        worker = self.services.endpoint_service.workers.get("file-integrity")
        return worker is not None and worker.isRunning()
