"""File-integrity configuration, baseline creation, and change history."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

from PySide6.QtCore import QEvent, QThread, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.ui.components.data_table import DataTable
from src.ui.components.status_indicator import StatusIndicator
from src.ui.icon_assets import icon_path


class _BaselineWorker(QThread):
    baselineCreated = Signal(int)
    baselineFailed = Signal(str)
    progressChanged = Signal(int)

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
                self.progressChanged.emit,
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.baselineFailed.emit(str(exc))
            return
        self.baselineCreated.emit(count)


class FileIntegrityPage(QWidget):
    actionRequested = Signal(str)

    def __init__(
        self,
        services: ApplicationServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self._baseline_worker: _BaselineWorker | None = None
        self._resume_after_baseline = False
        self.setObjectName("page-file-integrity")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(12)
        title = QLabel("File Integrity")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Select local folders, establish a hash baseline, and review detected changes."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        configuration = QWidget()
        form = QFormLayout(configuration)
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(8)
        self.roots = QPlainTextEdit()
        self.roots.setPlaceholderText("Monitored directories, one absolute path per line")
        self.roots.setMaximumHeight(90)
        self.roots.setPlainText("\n".join(services.settings.file_integrity_roots))
        roots_row = QHBoxLayout()
        roots_row.addWidget(self.roots, 1)
        self.add_folder_button = QPushButton("Add folder…")
        self.add_folder_button.setIcon(QIcon(icon_path("folder-search.png")))
        self.add_folder_button.clicked.connect(self._add_folder)
        roots_row.addWidget(self.add_folder_button)
        form.addRow("Folders to monitor", roots_row)
        self.exclusions = QPlainTextEdit()
        self.exclusions.setPlaceholderText(
            "Excluded file names or paths, one wildcard pattern per line"
        )
        self.exclusions.setMaximumHeight(65)
        self.exclusions.setPlainText(
            "\n".join(services.settings.file_integrity_exclusions)
        )
        form.addRow("Exclusions", self.exclusions)
        self.enabled = QPushButton(
            "Disable monitoring"
            if services.settings.file_integrity_monitoring_enabled
            else "Enable monitoring"
        )
        self.enabled.setCheckable(True)
        self.enabled.setChecked(services.settings.file_integrity_monitoring_enabled)
        self.enabled.clicked.connect(self._on_toggle_monitoring)
        self.save_button = QPushButton("Save configuration")
        self.save_button.setIcon(QIcon(icon_path("shield-check.png")))
        self.save_button.clicked.connect(self._save_configuration)
        self.baseline_button = QPushButton("Create / refresh baseline")
        self.baseline_button.setIcon(QIcon(icon_path("radar-scan.png")))
        self.baseline_button.setObjectName("primaryButton")
        self.baseline_button.clicked.connect(self.start_baseline)
        self.status = StatusIndicator("No file baseline established", "warning")
        actions = QHBoxLayout()
        actions.addWidget(self.enabled)
        actions.addWidget(self.save_button)
        actions.addWidget(self.baseline_button)
        actions.addStretch(1)
        form.addRow("Monitoring controls", actions)
        form.addRow("", self.status)
        layout.addWidget(configuration)

        self.table = DataTable(
            ("File", "Change", "Detected", "Integrity status"),
            empty_message="No baseline or file-integrity events are recorded yet.",
        )
        layout.addWidget(self.table, 1)
        self.refresh_button = QPushButton("Refresh records")
        self.refresh_button.setIcon(QIcon(icon_path("refresh.png")))
        self.refresh_button.clicked.connect(self.refresh_data)
        layout.addWidget(self.refresh_button, 0)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(
            max(1000, services.settings.endpoint_poll_interval_seconds * 1000)
        )
        self._refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_data()

    def _roots(self) -> tuple[str, ...]:
        return tuple(
            line.strip()
            for line in self.roots.toPlainText().splitlines()
            if line.strip()
        )

    def _exclusions(self) -> tuple[str, ...]:
        return tuple(
            line.strip()
            for line in self.exclusions.toPlainText().splitlines()
            if line.strip()
        )

    def _add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select file-integrity folder")
        if not folder:
            return
        roots = list(self._roots())
        if folder not in roots:
            roots.append(folder)
        self.roots.setPlainText("\n".join(roots))

    def _save_configuration(self, _checked: bool = False) -> None:
        roots = self._roots()
        settings = self.services.settings
        roots_changed = roots != settings.file_integrity_roots
        has_baseline = self._has_current_baseline(roots, self._exclusions())
        enabled = self.enabled.isChecked()
        if enabled and not roots:
            self.status.set_text("Add a folder before enabling file monitoring")
            self.status.set_state("error")
            self.enabled.setChecked(False)
            self.enabled.setText("Enable monitoring")
            return
        if enabled and (not has_baseline or roots_changed):
            self.status.set_text("Create a baseline for the selected folders first")
            self.status.set_state("warning")
            self.enabled.setChecked(False)
            self.enabled.setText("Enable monitoring")
            return
        try:
            self.services.save_settings(
                replace(
                    settings,
                    file_integrity_roots=roots,
                    file_integrity_exclusions=self._exclusions(),
                    file_integrity_monitoring_enabled=enabled,
                )
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.status.set_text(f"Could not save configuration: {exc}")
            self.status.set_state("error")
            return
        self.status.set_text(
            "Monitoring enabled" if enabled else "Configuration saved; monitoring disabled"
        )
        self.enabled.setText(
            "Disable monitoring" if enabled else "Enable monitoring"
        )
        self.status.set_state("success" if enabled else "info")
        self.refresh_data()

    def _on_toggle_monitoring(self, _checked: bool) -> None:
        self.enabled.setText(
            "Disable monitoring"
            if self.enabled.isChecked()
            else "Enable monitoring"
        )
        self._save_configuration()

    def start_baseline(self) -> None:
        if self._baseline_worker is not None and self._baseline_worker.isRunning():
            return
        roots = self._roots()
        if not roots:
            self.status.set_text("Add at least one folder before creating a baseline")
            self.status.set_state("error")
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
            self.status.set_text(f"Could not save folders: {exc}")
            self.status.set_state("error")
            return
        self._set_controls_enabled(False)
        self.status.set_text("Creating file baseline…")
        self.status.set_state("info")
        worker = _BaselineWorker(
            self.services,
            roots,
            self._exclusions(),
            self,
        )
        self._baseline_worker = worker
        worker.baselineCreated.connect(self._on_baseline_created)
        worker.baselineFailed.connect(self._on_baseline_failed)
        worker.progressChanged.connect(self._on_baseline_progress)
        worker.finished.connect(self._on_baseline_finished)
        worker.start()

    def _on_baseline_progress(self, count: int) -> None:
        self.status.set_text(f"Creating file baseline… hashed {count:,} files")
        self.status.set_state("info")

    def _on_baseline_created(self, count: int) -> None:
        self.status.set_text(f"Baseline established for {count:,} files")
        self.status.set_state("success")
        if self._resume_after_baseline:
            self.enabled.setChecked(True)
            self._save_configuration()
        self.refresh_data()

    def _on_baseline_failed(self, message: str) -> None:
        self.enabled.setChecked(False)
        self.enabled.setText("Enable monitoring")
        self.status.set_text(f"Baseline failed: {message}")
        self.status.set_state("error")
        self.refresh_data()

    def _on_baseline_finished(self) -> None:
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
        ):
            widget.setEnabled(enabled)

    def _has_current_baseline(
        self,
        roots: tuple[str, ...],
        exclusions: tuple[str, ...],
    ) -> bool:
        return self.services.endpoint_service.has_file_baseline(roots, exclusions)

    def refresh_data(self) -> None:
        try:
            baseline_rows = self.services.database.fetchall(
                "SELECT path, captured_at FROM file_integrity_baselines ORDER BY path"
            )
            has_current_baseline = self._has_current_baseline(
                self.services.settings.file_integrity_roots,
                self.services.settings.file_integrity_exclusions,
            )
            events = [
                event
                for event in self.services.security_repository.list_events(limit=10000)
                if "integrity" in str(event["source"]).casefold()
            ]
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.table.show_error(f"Could not load file-integrity data: {exc}")
            self.status.set_text(f"Local data unavailable: {exc}")
            self.status.set_state("error")
            return

        latest_by_path: dict[str, dict[str, object]] = {}
        for event in events:
            attributes = event.get("attributes")
            if isinstance(attributes, dict) and attributes.get("path"):
                latest_by_path.setdefault(str(attributes["path"]), event)

        rows: list[tuple[object, ...]] = []
        row_ids: list[str] = []
        for path, captured_at in (
            (str(row["path"]), row["captured_at"]) for row in baseline_rows
        ):
            event = latest_by_path.pop(path, None)
            if event is None:
                rows.append((path, "Baseline", captured_at, "Unchanged"))
            else:
                rows.append(
                    (
                        path,
                        str(event["event_type"]).replace("_", " ").title(),
                        event["occurred_at"],
                        str(event["severity"]).title(),
                    )
                )
            row_ids.append(str(event["id"]) if event else path)
        for path, event in latest_by_path.items():
            rows.append(
                (
                    path,
                    str(event["event_type"]).replace("_", " ").title(),
                    event["occurred_at"],
                    str(event["severity"]).title(),
                )
            )
            row_ids.append(str(event["id"]))
        self.table.set_rows(rows, row_ids)
        self.status.set_text(
            f"{len(baseline_rows):,} baseline files"
            f"{'' if has_current_baseline else ' · baseline needs refresh for current configuration'} · "
            f"{len(events):,} recorded changes · "
            f"{'monitoring active' if self._is_running() else 'monitoring inactive'}"
        )
        self.status.set_state(
            "success" if has_current_baseline else "warning"
        )

    def showEvent(self, event: QEvent) -> None:
        super().showEvent(event)
        settings = self.services.settings
        self.roots.setPlainText("\n".join(settings.file_integrity_roots))
        self.exclusions.setPlainText("\n".join(settings.file_integrity_exclusions))
        self.enabled.setChecked(settings.file_integrity_monitoring_enabled)
        self.enabled.setText(
            "Disable monitoring"
            if settings.file_integrity_monitoring_enabled
            else "Enable monitoring"
        )
        self.refresh_data()
        self._refresh_timer.start()

    def hideEvent(self, event: QEvent) -> None:
        self._refresh_timer.stop()
        super().hideEvent(event)

    def closeEvent(self, event: QEvent) -> None:
        worker = self._baseline_worker
        if worker is not None and worker.isRunning():
            worker.wait()
        super().closeEvent(event)

    def _is_running(self) -> bool:
        worker = self.services.endpoint_service.workers.get("file-integrity")
        return worker is not None and worker.isRunning()
