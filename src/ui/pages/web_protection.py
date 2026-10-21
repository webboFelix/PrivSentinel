"""Browser URL reputation history and domain override controls."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.security.reputation import ReputationResult
from src.ui.components.data_table import DataTable
from src.ui.components.status_indicator import StatusIndicator
from src.ui.icon_assets import icon_path


class _WebLookupWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, operation: Callable[[], ReputationResult], parent: QWidget):
        super().__init__(parent)
        self.operation = operation

    def run(self) -> None:
        try:
            self.completed.emit(self.operation())
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.failed.emit(str(exc))


class WebProtectionPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)

    def __init__(
        self,
        services: ApplicationServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self._lookup_worker: _WebLookupWorker | None = None
        self.setObjectName("page-web-protection")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(12)

        heading = QLabel("Browser Web Protection")
        heading.setObjectName("pageTitle")
        description = QLabel(
            "The browser extension blocks domains from the synchronized local "
            "URLhaus feed and analyst decisions before navigation. Unknown sites "
            "default to allow but are never labeled safe. VirusTotal queries are "
            "manual, cached, and limited to selected indicators."
        )
        description.setObjectName("subtitle")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        toolbar = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setIcon(QIcon(icon_path("refresh.png")))
        self.refresh_button.clicked.connect(self.refresh_data)
        self.allow_button = QPushButton("Allow selected domain")
        self.allow_button.setIcon(QIcon(icon_path("shield-check.png")))
        self.allow_button.clicked.connect(lambda: self._set_selected_decision("allow"))
        self.block_button = QPushButton("Block selected domain")
        self.block_button.setIcon(QIcon(icon_path("firewall.png")))
        self.block_button.clicked.connect(lambda: self._set_selected_decision("block"))
        self.check_reputation_button = QPushButton("Check selected domain")
        self.check_reputation_button.setIcon(QIcon(icon_path("internet-search.png")))
        self.check_reputation_button.clicked.connect(self._check_selected_domain)
        self.remove_decision_button = QPushButton("Remove selected override")
        self.remove_decision_button.setIcon(QIcon(icon_path("delete.png")))
        self.remove_decision_button.clicked.connect(self._remove_selected_decision)
        self.configure_button = QPushButton("Configure reputation feeds…")
        self.configure_button.setIcon(QIcon(icon_path("cloud-sync.png")))
        self.configure_button.clicked.connect(
            lambda: self.pageRequested.emit("threat-intelligence")
        )
        self.install_button = QPushButton("Browser setup…")
        self.install_button.setIcon(QIcon(icon_path("internet-search.png")))
        self.install_button.clicked.connect(self._show_install_instructions)
        for button in (
            self.refresh_button,
            self.allow_button,
            self.block_button,
            self.check_reputation_button,
            self.remove_decision_button,
            self.configure_button,
            self.install_button,
        ):
            toolbar.addWidget(button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        self.status = StatusIndicator("Waiting for browser activity", "info")
        layout.addWidget(self.status)
        self.table = DataTable(
            ("Time", "Browser", "Website", "Domain", "Decision", "Source / reason"),
            empty_message="No browser activity has been received from the extension yet.",
        )
        layout.addWidget(self.table, 1)
        self.override_table = DataTable(
            ("Domain", "Decision", "Reason", "Updated"),
            empty_message="No user allow/block overrides are configured.",
        )
        layout.addWidget(self.override_table, 1)
        footer = QLabel(
            "Visited URLs are recorded locally with query strings and fragments removed. "
            "The URLhaus feed is downloaded to the device using your stored Auth-Key; "
            "the browser does not submit each visited URL to URLhaus or VirusTotal. "
            "Use the extension setup action to load the browser package and register "
            "its local native connector."
        )
        footer.setObjectName("muted")
        footer.setWordWrap(True)
        layout.addWidget(footer)
        self.refresh_data()

    def refresh_data(self) -> None:
        try:
            events = self.services.browser_protection.list_site_events()
            decisions = self.services.browser_protection.list_domain_decisions()
            status = self.services.database.fetchone(
                "SELECT updated_at, entry_count FROM reputation_feed_status "
                "WHERE provider = 'urlhaus'"
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.status.set_text(f"Could not load web protection history: {exc}")
            self.status.set_state("error")
            return
        self.table.set_rows(
            (
                (
                    event["occurred_at"],
                    event["browser"],
                    event["url"],
                    event["domain"],
                    str(event["decision"]).upper(),
                    f"{event['provider']}: {event['detail']}",
                )
                for event in events
            ),
            [str(event["id"]) for event in events],
        )
        self.override_table.set_rows(
            (
                (
                    item["domain"],
                    str(item["decision"]).upper(),
                    item["reason"],
                    item["updated_at"],
                )
                for item in decisions
            ),
            [str(item["domain"]) for item in decisions],
        )
        if status is None:
            self.status.set_text(
                f"{len(events):,} local browser event(s) · URLhaus feed not synchronized"
            )
            self.status.set_state("warning")
        else:
            self.status.set_text(
                f"{len(events):,} local browser event(s) · "
                f"{int(status['entry_count']):,} URLhaus indicators · "
                f"feed updated {status['updated_at']}"
            )
            self.status.set_state("success")

    def _selected_event_domain(self) -> str | None:
        selected = self.table.selected_ids
        if len(selected) != 1:
            self.status.set_text("Select exactly one browser event")
            self.status.set_state("warning")
            return None
        row = self.services.database.fetchone(
            "SELECT domain FROM browser_site_events WHERE id = ?",
            (selected[0],),
        )
        if row is None:
            self.status.set_text("The selected browser event is no longer available")
            self.status.set_state("warning")
            return None
        return str(row["domain"])

    def _set_selected_decision(self, decision: str) -> None:
        domain = self._selected_event_domain()
        if domain is None:
            return
        if decision == "allow" and QMessageBox.question(
            self,
            "Allow this domain?",
            f"Allow {domain} even when local threat indicators match? The exception "
            "will be synchronized to the installed browser extension.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.services.browser_protection.set_domain_decision(
                domain,
                decision,
                "User decision from browser protection history",
            )
        except (ValueError, RuntimeError, sqlite3.Error) as exc:
            self.status.set_text(f"Could not update the domain decision: {exc}")
            self.status.set_state("error")
            return
        self.status.set_text(f"{domain} set to {decision}; browser rules refresh periodically")
        self.status.set_state("success")
        self.refresh_data()

    def _remove_selected_decision(self) -> None:
        selected = self.override_table.selected_ids
        if len(selected) != 1:
            self.status.set_text("Select exactly one domain override")
            self.status.set_state("warning")
            return
        domain = selected[0]
        try:
            with self.services.database.transaction() as connection:
                cursor = connection.execute(
                    "DELETE FROM browser_domain_decisions WHERE domain = ?",
                    (domain,),
                )
                if cursor.rowcount != 1:
                    raise ValueError("The selected domain override no longer exists.")
            self.services.security_repository.record_audit(
                "user",
                "browser.domain_override_removed",
                "success",
                domain,
            )
        except (ValueError, RuntimeError, sqlite3.Error) as exc:
            self.status.set_text(f"Could not remove the override: {exc}")
            self.status.set_state("error")
            return
        self.refresh_data()

    def _check_selected_domain(self) -> None:
        if self._lookup_worker is not None and self._lookup_worker.isRunning():
            self.status.set_text("A VirusTotal request is already running")
            self.status.set_state("warning")
            return
        domain = self._selected_event_domain()
        if domain is None:
            return
        self.status.set_text(
            "Checking the domain with VirusTotal; the domain is sent to that provider…"
        )
        self.status.set_state("info")
        worker = _WebLookupWorker(
            lambda: self.services.reputation_service.lookup_virustotal("domain", domain),
            self,
        )
        self._lookup_worker = worker
        worker.completed.connect(self._lookup_completed)
        worker.failed.connect(self._lookup_failed)
        worker.finished.connect(lambda: self._clear_lookup_worker(worker))
        worker.start()

    def _lookup_completed(self, result: object) -> None:
        if not isinstance(result, ReputationResult):
            return
        self.status.set_text(
            f"VirusTotal: {result.verdict.replace('_', ' ')} · "
            f"{result.malicious or 0} malicious / {result.suspicious or 0} suspicious"
        )
        self.status.set_state(
            "error" if result.verdict == "malicious" else
            "warning" if result.verdict == "suspicious" else "info"
        )
        self.refresh_data()

    def _lookup_failed(self, message: str) -> None:
        self.status.set_text(f"VirusTotal lookup failed: {message}")
        self.status.set_state("error")

    def _clear_lookup_worker(self, worker: _WebLookupWorker) -> None:
        if self._lookup_worker is worker:
            self._lookup_worker = None

    def _show_install_instructions(self) -> None:
        extension = Path(__file__).resolve().parents[2] / "browser" / "extension"
        script = Path(__file__).resolve().parents[2] / "scripts" / "install_browser_native_host.ps1"
        QMessageBox.information(
            self,
            "Install browser protection",
            "1. Load this extension folder in each browser's extension developer mode:\n"
            f"   {extension}\n"
            "2. Copy each browser's 32-character extension ID.\n"
            "3. Run this PowerShell script from the repository:\n"
            f"   {script}\n"
            "4. Enter the Chrome, Edge, and Brave IDs when prompted, then restart "
            "the browsers.\n\n"
            "Supported: Chrome, Edge, Brave, Firefox. Firefox temporary add-ons are "
            "removed when Firefox closes; a signed Firefox package or enterprise "
            "deployment is needed for a persistent installation. Browser restrictions "
            "and local URLhaus/analyst rules determine blocking. Unknown sites are "
            "not scanned for page contents.",
        )

    def stop_workers(self) -> None:
        worker = self._lookup_worker
        if worker is not None and worker.isRunning():
            worker.wait()
