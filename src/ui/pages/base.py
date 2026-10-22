"""Shared, service-backed views for local security records."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.reporting.report_service import export_daily_report, generate_daily_reports
from src.security.reputation import ReputationResult
from src.ui.components.data_table import DataTable
from src.ui.components.status_indicator import StatusIndicator
from src.ui.icon_assets import icon_path
from src.ui.navigation import PAGES_BY_KEY


class _ReputationWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, operation, parent: QWidget) -> None:
        super().__init__(parent)
        self.operation = operation

    def run(self) -> None:
        try:
            self.completed.emit(self.operation())
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.failed.emit(str(exc))


class DataPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)
    alertCountChanged = Signal()

    page_key = ""

    def __init__(
        self,
        services: ApplicationServices | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        definition = PAGES_BY_KEY[self.page_key]
        self.setObjectName(f"page-{definition.key}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(14)

        heading = QHBoxLayout()
        title_stack = QVBoxLayout()
        self.title_label = QLabel(definition.title)
        self.title_label.setObjectName("pageTitle")
        self.subtitle_label = QLabel(definition.description)
        self.subtitle_label.setObjectName("subtitle")
        self.subtitle_label.setWordWrap(True)
        title_stack.addWidget(self.title_label)
        title_stack.addWidget(self.subtitle_label)
        heading.addLayout(title_stack, 1)
        self.source_status = StatusIndicator("Waiting for a local data source")
        heading.addWidget(self.source_status)
        layout.addLayout(heading)

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setIcon(QIcon(icon_path("refresh.png")))
        self.refresh_button.clicked.connect(self._refresh)
        toolbar.addWidget(self.refresh_button)
        self.primary_button: QPushButton | None = None
        self.alert_action: QComboBox | None = None
        self.investigation_status: QComboBox | None = None
        self.windows_level: QComboBox | None = None
        self.windows_period: QComboBox | None = None
        self.download_pdf_button: QPushButton | None = None
        self.download_excel_button: QPushButton | None = None
        self.open_html_button: QPushButton | None = None
        self._reputation_worker: _ReputationWorker | None = None
        if definition.key == "investigations":
            self.primary_button = QPushButton("New investigation")
            self.primary_button.setIcon(QIcon(icon_path("add.png")))
            self.primary_button.clicked.connect(self._create_investigation)
            self.primary_button.setObjectName("primaryButton")
            toolbar.addWidget(self.primary_button)
            self.note_button = QPushButton("Add note")
            self.note_button.setIcon(QIcon(icon_path("edit.png")))
            self.note_button.clicked.connect(self._add_investigation_note)
            toolbar.addWidget(self.note_button)
            self.view_notes_button = QPushButton("View notes")
            self.view_notes_button.setIcon(QIcon(icon_path("file-search.png")))
            self.view_notes_button.clicked.connect(self._view_investigation_notes)
            toolbar.addWidget(self.view_notes_button)
            self.link_event_button = QPushButton("Link event…")
            self.link_event_button.setIcon(QIcon(icon_path("add.png")))
            self.link_event_button.clicked.connect(self._link_event)
            toolbar.addWidget(self.link_event_button)
            self.investigation_status = QComboBox()
            self.investigation_status.addItem("Open", "open")
            self.investigation_status.addItem("In progress", "in_progress")
            self.investigation_status.addItem("Closed", "closed")
            toolbar.addWidget(self.investigation_status)
            self.set_investigation_status_button = QPushButton("Update status")
            self.set_investigation_status_button.setIcon(QIcon(icon_path("edit.png")))
            self.set_investigation_status_button.clicked.connect(
                self._update_investigation_status
            )
            toolbar.addWidget(self.set_investigation_status_button)
        elif definition.key in {"alerts", "threat-detection"}:
            if definition.key == "alerts":
                self.alert_action = QComboBox()
                self.alert_action.addItem("Acknowledge", "acknowledged")
                self.alert_action.addItem("Investigating", "investigating")
                self.alert_action.addItem("Resolve as confirmed", "resolved")
                self.alert_action.addItem("Dismiss as false positive", "dismissed")
                toolbar.addWidget(self.alert_action)
                self.apply_alert_action_button = QPushButton("Apply to selected")
                self.apply_alert_action_button.setIcon(
                    QIcon(icon_path("shield-check.png"))
                )
                self.apply_alert_action_button.clicked.connect(
                    self._transition_selected_alert
                )
                toolbar.addWidget(self.apply_alert_action_button)
            self.alert_details_button = QPushButton("Review details")
            self.alert_details_button.setIcon(QIcon(icon_path("info-alert.png")))
            self.alert_details_button.clicked.connect(self._show_alert_details)
            toolbar.addWidget(self.alert_details_button)
            self.create_investigation_button = QPushButton("Investigate selected")
            self.create_investigation_button.setIcon(
                QIcon(icon_path("radar-scan.png"))
            )
            self.create_investigation_button.clicked.connect(
                self._create_investigation_for_selected_alert
            )
            toolbar.addWidget(self.create_investigation_button)
        elif definition.key == "windows-logs":
            self.windows_level = QComboBox()
            self.windows_level.addItem("All levels", "all")
            self.windows_level.addItem("Errors", "error")
            self.windows_level.addItem("Warnings", "warning")
            self.windows_level.addItem("Information", "info")
            self.windows_level.addItem("Other", "other")
            self.windows_level.currentIndexChanged.connect(self._refresh)
            self.windows_level.setToolTip("Filter locally collected event levels")
            self.windows_period = QComboBox()
            self.windows_period.addItem("Last 24 hours", 24)
            self.windows_period.addItem("Last 7 days", 24 * 7)
            self.windows_period.addItem("All collected", 0)
            self.windows_period.currentIndexChanged.connect(self._refresh)
            toolbar.addWidget(self.windows_level)
            toolbar.addWidget(self.windows_period)
        elif definition.key == "threat-intelligence":
            self.add_indicator_button = QPushButton("Add local indicator…")
            self.add_indicator_button.setIcon(QIcon(icon_path("add.png")))
            self.add_indicator_button.clicked.connect(self._add_threat_indicator)
            toolbar.addWidget(self.add_indicator_button)
            self.check_indicator_button = QPushButton("Review local matches")
            self.check_indicator_button.setIcon(
                QIcon(icon_path("folder-search.png"))
            )
            self.check_indicator_button.clicked.connect(
                self._review_indicator_matches
            )
            toolbar.addWidget(self.check_indicator_button)
            self.delete_indicator_button = QPushButton("Delete selected")
            self.delete_indicator_button.setIcon(QIcon(icon_path("delete.png")))
            self.delete_indicator_button.clicked.connect(
                self._delete_threat_indicator
            )
            toolbar.addWidget(self.delete_indicator_button)
            self.sync_urlhaus_button = QPushButton("Sync URLhaus feed")
            self.sync_urlhaus_button.setIcon(QIcon(icon_path("refresh.png")))
            self.sync_urlhaus_button.clicked.connect(self._sync_urlhaus_feed)
            toolbar.addWidget(self.sync_urlhaus_button)
            self.configure_reputation_button = QPushButton("Configure API keys…")
            self.configure_reputation_button.setIcon(
                QIcon(icon_path("shield-check.png"))
            )
            self.configure_reputation_button.clicked.connect(
                self._configure_reputation_keys
            )
            toolbar.addWidget(self.configure_reputation_button)
            self.check_virustotal_button = QPushButton("Check VirusTotal")
            self.check_virustotal_button.setIcon(
                QIcon(icon_path("folder-search.png"))
            )
            self.check_virustotal_button.clicked.connect(
                self._check_selected_virustotal
            )
            toolbar.addWidget(self.check_virustotal_button)
        elif definition.key == "reports":
            self.primary_button = QPushButton("Generate daily summary")
            self.primary_button.setIcon(QIcon(icon_path("analytics-report.png")))
            self.primary_button.setObjectName("primaryButton")
            self.primary_button.clicked.connect(
                lambda: self._ensure_daily_report(force=True)
            )
            toolbar.addWidget(self.primary_button)
            self.download_pdf_button = QPushButton("Download PDF")
            self.download_pdf_button.setIcon(QIcon(icon_path("download.png")))
            self.download_pdf_button.clicked.connect(
                lambda: self._download_report("pdf", "PDF files (*.pdf)")
            )
            toolbar.addWidget(self.download_pdf_button)
            self.download_excel_button = QPushButton("Download Excel")
            self.download_excel_button.setIcon(QIcon(icon_path("download.png")))
            self.download_excel_button.clicked.connect(
                lambda: self._download_report(
                    "xlsx", "Excel workbooks (*.xlsx)"
                )
            )
            toolbar.addWidget(self.download_excel_button)
            self.open_html_button = QPushButton("Open HTML")
            self.open_html_button.setIcon(QIcon(icon_path("export-document.png")))
            self.open_html_button.clicked.connect(self._open_html_report)
            toolbar.addWidget(self.open_html_button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        if definition.columns:
            table_title = QLabel("Local records")
            table_title.setObjectName("sectionTitle")
            layout.addWidget(table_title)
            self.table = DataTable(definition.columns)
            self.table.state_view.retryRequested.connect(self._refresh)
            layout.addWidget(self.table, 1)
        else:
            self.table = None
        footer = QLabel(self._footer_text())
        footer.setObjectName("muted")
        footer.setWordWrap(True)
        layout.addWidget(footer)

        if definition.key == "reports" and services is not None:
            self._daily_report_timer = QTimer(self)
            self._daily_report_timer.setInterval(60 * 60 * 1000)
            self._daily_report_timer.timeout.connect(self._ensure_daily_report)
            self._daily_report_timer.start()
            QTimer.singleShot(0, self._ensure_daily_report)

    def _footer_text(self) -> str:
        if self.page_key == "alerts":
            return (
                "Rule matches need analyst validation; a rule-generated alert is not "
                "automatically a confirmed true positive."
            )
        if self.page_key == "reports":
            return (
                "Daily summaries include local events, active rule alerts, and file "
                "integrity baseline counts. Baseline counts are not malware scan results."
            )
        if self.page_key == "windows-logs":
            return (
                "Only Windows System and Application events collected while the "
                "collector is enabled are shown."
            )
        if self.page_key == "threat-intelligence":
            return (
                "Indicators are manually maintained and matched against the latest "
                "10,000 locally stored security events. No external feed or reputation "
                "service is configured."
            )
        return (
            "Records are read from local application storage. No background monitoring "
            "is started by this screen."
        )

    def _refresh(self) -> None:
        if self.table is None:
            return
        if self.services is None:
            self.table.show_error("Application services are unavailable.")
            self.source_status.set_text("Local data unavailable")
            self.source_status.set_state("error")
            return
        try:
            if self.page_key in {"alerts", "threat-detection"}:
                self._refresh_alerts()
            elif self.page_key == "investigations":
                self._refresh_investigations()
            elif self.page_key == "windows-logs":
                self._refresh_windows_logs()
            elif self.page_key == "threat-intelligence":
                self._refresh_threat_intelligence()
            elif self.page_key == "reports":
                self._refresh_reports()
            elif self.page_key == "audit-log":
                self._refresh_audit_log()
            else:
                raise ValueError(f"No local data provider exists for {self.page_key}.")
        except (OSError, ValueError, RuntimeError, sqlite3.Error, KeyError) as exc:
            self.table.show_error(f"Could not load local records: {exc}")
            self.source_status.set_text("Local data unavailable")
            self.source_status.set_state("error")

    def _refresh_alerts(self) -> None:
        assert self.services is not None and self.table is not None
        active = [
            alert
            for alert in self.services.security_repository.list_alerts(limit=10000)
            if alert["status"] in {"open", "acknowledged", "investigating"}
        ]
        if self.page_key == "threat-detection":
            active = [
                alert
                for alert in active
                if str(alert["severity"]).casefold() in {"high", "critical"}
            ]
        self.table.set_rows(
            (
                (
                    alert["title"],
                    alert["severity"],
                    alert["source"],
                    alert["created_at"],
                    alert["status"],
                )
                for alert in active
            ),
            [str(alert["id"]) for alert in active],
        )
        self.source_status.set_text(
            f"{len(active):,} rule matches need review"
            if active
            else "No active rule matches need review"
        )
        self.source_status.set_state("warning" if active else "success")
        self.alertCountChanged.emit()

    def _selected_id(self) -> str | None:
        if self.table is None:
            return None
        selected = self.table.selected_ids
        return selected[0] if len(selected) == 1 else None

    def _transition_selected_alert(self) -> None:
        if self.services is None or self.alert_action is None:
            return
        alert_id = self._selected_id()
        if alert_id is None:
            self.source_status.set_text("Select one alert to update")
            self.source_status.set_state("warning")
            return
        try:
            self.services.security_repository.transition_alert(
                alert_id, str(self.alert_action.currentData())
            )
        except (KeyError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not update alert: {exc}")
            self.source_status.set_state("error")
            return
        self._refresh()

    def _show_alert_details(self) -> None:
        if self.services is None:
            return
        alert_id = self._selected_id()
        alert = next(
            (
                item
                for item in self.services.security_repository.list_alerts(limit=10000)
                if str(item["id"]) == alert_id
            ),
            None,
        )
        if alert is None:
            self.source_status.set_text("Select an alert to review")
            self.source_status.set_state("warning")
            return
        QMessageBox.information(
            self,
            "Alert details",
            f"{alert['title']}\n\nSeverity: {alert['severity']}\n"
            f"Source: {alert['source']}\nStatus: {alert['status']}\n\n"
            f"Rule rationale: {alert['rationale']}\n\n"
            f"Event: {alert['description']}",
        )
        if alert["status"] == "open":
            try:
                self.services.security_repository.transition_alert(
                    alert_id,
                    "acknowledged",
                )
            except (KeyError, ValueError, RuntimeError, sqlite3.Error) as exc:
                self.source_status.set_text(
                    f"Alert reviewed but could not be acknowledged: {exc}"
                )
                self.source_status.set_state("error")
                return
            self._refresh()

    def _create_investigation_for_selected_alert(self) -> None:
        if self.services is None:
            return
        alert_id = self._selected_id()
        if alert_id is None:
            self.source_status.set_text("Select one finding to investigate")
            self.source_status.set_state("warning")
            return
        try:
            self.services.security_repository.create_investigation_for_alert(
                alert_id
            )
        except (KeyError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not start investigation: {exc}")
            self.source_status.set_state("error")
            return
        self.source_status.set_text(
            "Investigation created, source event linked, and alert moved to investigating"
        )
        self.source_status.set_state("success")
        self._refresh()

    def _create_investigation(self) -> None:
        if self.services is None:
            return
        title, accepted = QInputDialog.getText(
            self, "New investigation", "Investigation title:"
        )
        if not accepted:
            return
        try:
            self.services.security_repository.create_investigation(title)
        except (ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not create investigation: {exc}")
            self.source_status.set_state("error")
            return
        self._refresh()

    def _add_investigation_note(self) -> None:
        if self.services is None:
            return
        investigation_id = self._selected_id()
        if investigation_id is None:
            self.source_status.set_text("Select one investigation first")
            self.source_status.set_state("warning")
            return
        note, accepted = QInputDialog.getMultiLineText(
            self, "Add investigation note", "Analyst note:"
        )
        if not accepted:
            return
        try:
            self.services.security_repository.add_investigation_note(
                investigation_id, note
            )
        except (KeyError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not add note: {exc}")
            self.source_status.set_state("error")
            return
        self._refresh()

    def _view_investigation_notes(self) -> None:
        if self.services is None:
            return
        investigation_id = self._selected_id()
        if investigation_id is None:
            self.source_status.set_text("Select one investigation first")
            self.source_status.set_state("warning")
            return
        try:
            notes = self.services.security_repository.list_investigation_notes(
                investigation_id
            )
        except (KeyError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not load investigation notes: {exc}")
            self.source_status.set_state("error")
            return
        content = "\n\n".join(
            f"{note['created_at']}\n{note['body']}" for note in notes
        ) or "No notes have been added."
        QMessageBox.information(self, "Investigation notes", content)

    def _link_event(self) -> None:
        if self.services is None:
            return
        investigation_id = self._selected_id()
        if investigation_id is None:
            self.source_status.set_text("Select one investigation first")
            self.source_status.set_state("warning")
            return
        event_id, accepted = QInputDialog.getText(
            self, "Link security event", "Event ID:"
        )
        if not accepted:
            return
        try:
            self.services.security_repository.link_event_to_investigation(
                investigation_id, event_id.strip()
            )
        except (KeyError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not link event: {exc}")
            self.source_status.set_state("error")
            return
        self._refresh()

    def _update_investigation_status(self) -> None:
        if self.services is None or self.investigation_status is None:
            return
        investigation_id = self._selected_id()
        if investigation_id is None:
            self.source_status.set_text("Select one investigation first")
            self.source_status.set_state("warning")
            return
        try:
            self.services.security_repository.set_investigation_status(
                investigation_id, str(self.investigation_status.currentData())
            )
        except (KeyError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not update investigation: {exc}")
            self.source_status.set_state("error")
            return
        self._refresh()

    def _refresh_investigations(self) -> None:
        assert self.services is not None and self.table is not None
        investigations = self.services.security_repository.list_investigations()
        self.table.set_rows(
            (
                (
                    item["title"],
                    item["created_at"],
                    item["updated_at"],
                    item["status"],
                    f"{item['note_count']} notes / {item['event_count']} events",
                )
                for item in investigations
            ),
            [str(item["id"]) for item in investigations],
        )
        self.source_status.set_text(f"{len(investigations):,} local investigations")
        self.source_status.set_state("success" if investigations else "info")

    def _refresh_windows_logs(self) -> None:
        assert self.services is not None and self.table is not None
        all_events = [
            event
            for event in self.services.security_repository.list_events(limit=10000)
            if str(event["source"]).casefold().startswith("windows-event-log:")
        ]
        level = (
            str(self.windows_level.currentData())
            if self.windows_level is not None
            else "all"
        )
        hours = (
            int(self.windows_period.currentData())
            if self.windows_period is not None
            else 0
        )
        cutoff = datetime.now().astimezone().timestamp() - hours * 3600 if hours else 0
        events = []
        for event in all_events:
            attributes = _event_attributes(event)
            event_level = str(
                attributes.get("event_type", event["severity"])
            ).casefold()
            if level != "all" and event_level != level:
                continue
            if cutoff:
                try:
                    occurred_at = datetime.fromisoformat(
                        str(event["occurred_at"])
                    ).astimezone()
                except ValueError:
                    continue
                if occurred_at.timestamp() < cutoff:
                    continue
            events.append(event)
        self.table.set_rows(
            (
                (
                    event["occurred_at"],
                    _event_attributes(event).get("source_name", "—"),
                    _event_attributes(event).get("event_id", "—"),
                    _event_attributes(event).get("event_type", event["severity"]),
                    event["description"],
                )
                for event in events
            ),
            [str(event["id"]) for event in events],
        )
        self.source_status.set_text(
            f"{len(events):,} of {len(all_events):,} locally collected Windows "
            "records shown"
        )
        self.source_status.set_state("success" if events else "info")

    def _refresh_threat_intelligence(self) -> None:
        assert self.services is not None and self.table is not None
        indicators = self.services.security_repository.list_threat_indicators()
        match_counts = (
            self.services.security_repository.threat_indicator_match_counts()
        )
        checked_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        self.table.set_rows(
            (
                (
                    indicator["value"],
                    indicator["indicator_type"],
                    indicator["source"],
                    checked_at,
                    (
                        f"{match_counts.get(str(indicator['id']), 0):,} local "
                        "event match(es)"
                    ),
                )
                for indicator in indicators
            ),
            [str(indicator["id"]) for indicator in indicators],
        )
        total_matches = sum(match_counts.values())
        feed = self.services.database.fetchone(
            "SELECT updated_at, entry_count FROM reputation_feed_status "
            "WHERE provider = 'urlhaus'"
        )
        feed_status = (
            f"URLhaus local feed: {int(feed['entry_count']):,} indicators, "
            f"updated {feed['updated_at']}"
            if feed is not None
            else "URLhaus feed not synchronized"
        )
        self.source_status.set_text(
            f"{len(indicators):,} analyst indicators · {total_matches:,} event matches "
            f"in recent local events · {feed_status} · selected VirusTotal queries "
            "send only the chosen IP/domain/SHA-256 indicator"
        )
        self.source_status.set_state("success" if indicators else "info")

    def _configure_reputation_keys(self) -> None:
        if self.services is None:
            return
        provider, accepted = QInputDialog.getItem(
            self,
            "Configure reputation provider",
            "Choose a provider credential to save encrypted for this Windows user:",
            ("URLhaus Auth-Key", "VirusTotal API key"),
            0,
            False,
        )
        if not accepted:
            return
        key, accepted = QInputDialog.getText(
            self,
            f"Configure {provider}",
            "Credential (stored using Windows DPAPI):",
            QLineEdit.EchoMode.Password,
        )
        if not accepted:
            return
        try:
            if provider == "URLhaus Auth-Key":
                self.services.reputation_service.save_urlhaus_key(key)
            else:
                self.services.reputation_service.save_virustotal_key(key)
        except (OSError, ValueError, RuntimeError) as exc:
            self.source_status.set_text(f"Could not save provider credential: {exc}")
            self.source_status.set_state("error")
            return
        self.source_status.set_text(f"{provider} stored securely for this user")
        self.source_status.set_state("success")

    def _sync_urlhaus_feed(self) -> None:
        if self.services is None:
            return
        self._start_reputation_operation(
            self.services.reputation_service.sync_urlhaus,
            "Synchronizing the URLhaus feed…",
        )

    def _check_selected_virustotal(self) -> None:
        if self.services is None:
            return
        indicator_id = self._selected_id()
        if indicator_id is None:
            self.source_status.set_text("Select one IP, domain, or SHA-256 indicator")
            self.source_status.set_state("warning")
            return
        try:
            row = self.services.database.fetchone(
                "SELECT indicator_type, value FROM threat_indicators WHERE id = ?",
                (indicator_id,),
            )
        except sqlite3.Error as exc:
            self.source_status.set_text(f"Could not load the selected indicator: {exc}")
            self.source_status.set_state("error")
            return
        if row is None:
            self.source_status.set_text("The selected indicator no longer exists")
            self.source_status.set_state("warning")
            return
        operation = lambda: self.services.reputation_service.lookup_virustotal(
            str(row["indicator_type"]),
            str(row["value"]),
        )
        self._start_reputation_operation(
            operation,
            "Requesting selected indicator reputation from VirusTotal…",
        )

    def _start_reputation_operation(self, operation, message: str) -> None:
        if self._reputation_worker is not None and self._reputation_worker.isRunning():
            self.source_status.set_text("A reputation operation is already running")
            self.source_status.set_state("warning")
            return
        self.source_status.set_text(message)
        self.source_status.set_state("info")
        worker = _ReputationWorker(operation, self)
        self._reputation_worker = worker
        worker.completed.connect(self._reputation_operation_completed)
        worker.failed.connect(self._reputation_operation_failed)
        worker.finished.connect(lambda: self._clear_reputation_worker(worker))
        worker.start()

    def _reputation_operation_completed(self, result: object) -> None:
        if isinstance(result, ReputationResult):
            QMessageBox.information(
                self,
                "VirusTotal result",
                f"{result.value}\n\nVerdict: {result.verdict.replace('_', ' ')}\n"
                f"Malicious: {result.malicious if result.malicious is not None else '—'}\n"
                f"Suspicious: {result.suspicious if result.suspicious is not None else '—'}\n\n"
                f"{result.detail}\n\nChecked: {result.checked_at}",
            )
        elif isinstance(result, int):
            self.source_status.set_text(
                f"URLhaus feed synchronized: {result:,} active URL/domain indicators"
            )
            self.source_status.set_state("success")
        self._refresh()

    def _reputation_operation_failed(self, message: str) -> None:
        self.source_status.set_text(f"Reputation operation failed: {message}")
        self.source_status.set_state("error")

    def _clear_reputation_worker(self, worker: _ReputationWorker) -> None:
        if self._reputation_worker is worker:
            self._reputation_worker = None

    def stop_workers(self) -> None:
        worker = self._reputation_worker
        if worker is not None and worker.isRunning():
            worker.wait()

    def _add_threat_indicator(self) -> None:
        if self.services is None:
            return
        value, accepted = QInputDialog.getText(
            self,
            "Add local threat indicator",
            "IP address, domain, or SHA-256 digest:",
        )
        if not accepted:
            return
        indicator_type, accepted = QInputDialog.getItem(
            self,
            "Indicator type",
            "Choose the exact-match indicator type:",
            ("IP address", "Domain", "SHA-256"),
            0,
            False,
        )
        if not accepted:
            return
        type_value = {
            "IP address": "ip",
            "Domain": "domain",
            "SHA-256": "sha256",
        }[indicator_type]
        source, accepted = QInputDialog.getText(
            self, "Indicator source", "Source / analyst note:", text="Local analyst"
        )
        if not accepted:
            return
        try:
            self.services.security_repository.add_threat_indicator(
                value, type_value, source
            )
        except (ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not add indicator: {exc}")
            self.source_status.set_state("error")
            return
        self._refresh()

    def _review_indicator_matches(self) -> None:
        if self.services is None:
            return
        indicator_id = self._selected_id()
        if indicator_id is None:
            self.source_status.set_text("Select one local indicator")
            self.source_status.set_state("warning")
            return
        try:
            matches = self.services.security_repository.list_threat_indicator_matches(
                indicator_id
            )
        except (KeyError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not check local events: {exc}")
            self.source_status.set_state("error")
            return
        content = "\n\n".join(
            f"{event['occurred_at']} · {event['source']}\n{event['description']}"
            for event in matches[:10]
        )
        QMessageBox.information(
            self,
            "Local indicator matches",
            (
                f"{len(matches):,} exact local event match(es) found in the latest "
                f"10,000 stored events.\n\n{content}"
                if matches
                else "No exact matches were found in the latest 10,000 locally stored "
                "security events. This is not an external reputation check."
            ),
        )

    def _delete_threat_indicator(self) -> None:
        if self.services is None:
            return
        indicator_id = self._selected_id()
        if indicator_id is None:
            self.source_status.set_text("Select one local indicator to delete")
            self.source_status.set_state("warning")
            return
        if QMessageBox.question(
            self,
            "Delete local indicator?",
            "Remove this analyst-maintained indicator from the local list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.services.security_repository.delete_threat_indicator(indicator_id)
        except (KeyError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not delete indicator: {exc}")
            self.source_status.set_state("error")
            return
        self._refresh()

    def _refresh_audit_log(self) -> None:
        assert self.services is not None and self.table is not None
        records = self.services.security_repository.list_audit(limit=10000)
        self.table.set_rows(
            (
                (
                    record["occurred_at"],
                    record["actor"],
                    record["action"],
                    record["outcome"],
                    record["details"],
                )
                for record in records
            ),
            [str(record["id"]) for record in records],
        )
        self.source_status.set_text(f"{len(records):,} local audit records")
        self.source_status.set_state("success" if records else "info")

    def _reports_directory(self) -> Path:
        if self.services is None:
            raise RuntimeError("Application services are unavailable.")
        return self.services.paths.exports_directory / "daily"

    def _ensure_daily_report(self, force: bool = False) -> None:
        if self.services is None:
            return
        today = datetime.now().astimezone().date().isoformat()
        directory = self._reports_directory()
        expected = [
            directory / f"daily-executive-{today}.{format_name}"
            for format_name in ("pdf", "xlsx", "html")
        ]
        if force or not all(path.is_file() for path in expected):
            try:
                generate_daily_reports(
                    directory,
                    self.services.database,
                    self.services.security_repository,
                )
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                self.source_status.set_text(f"Daily report generation failed: {exc}")
                self.source_status.set_state("error")
                return
        self._refresh_reports()

    def _refresh_reports(self) -> None:
        assert self.table is not None
        files = sorted(
            (
                path
                for path in self._reports_directory().glob("daily-executive-*")
                if path.suffix.casefold() in {".pdf", ".xlsx", ".html"}
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        self.table.set_rows(
            (
                (
                    path.stem,
                    datetime.fromtimestamp(path.stat().st_mtime)
                    .astimezone()
                    .date()
                    .isoformat(),
                    path.suffix.lstrip(".").upper(),
                    "Ready",
                )
                for path in files
            ),
            [str(path) for path in files],
        )
        self.source_status.set_text(
            f"{len(files):,} PDF, Excel, or HTML report files in local storage"
        )
        self.source_status.set_state("success" if files else "info")

    def _download_report(self, format_name: str, file_filter: str) -> None:
        if self.services is None:
            return
        today = datetime.now().astimezone().date().isoformat()
        suffix = "xlsx" if format_name == "xlsx" else format_name
        destination, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save daily executive summary",
            str(self._reports_directory() / f"daily-executive-{today}.{suffix}"),
            file_filter,
        )
        if not destination:
            return
        try:
            export_daily_report(
                format_name,
                destination,
                self.services.database,
                self.services.security_repository,
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.source_status.set_text(f"Could not export report: {exc}")
            self.source_status.set_state("error")
            return
        self.source_status.set_text(f"Saved report to {destination}")
        self.source_status.set_state("success")
        self._refresh_reports()

    def _open_html_report(self) -> None:
        if self.services is None:
            return
        path = (
            self._reports_directory()
            / f"daily-executive-{datetime.now().astimezone().date().isoformat()}.html"
        )
        if not path.is_file():
            self._ensure_daily_report(force=True)
        if not path.is_file():
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            self.source_status.set_text(f"Could not open HTML report: {path}")
            self.source_status.set_state("error")


def _event_attributes(event: dict[str, object]) -> dict[str, object]:
    attributes = event.get("attributes")
    return attributes if isinstance(attributes, dict) else {}
