"""Service-backed, privacy-first security dashboard."""

import sqlite3
from datetime import UTC, datetime, timedelta

from PySide6.QtCore import QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.ui.components.chart_widget import ChartWidget
from src.ui.components.metric_card import MetricCard
from src.ui.components.notification_panel import NotificationPanel
from src.ui.components.status_indicator import StatusIndicator
from src.ui.icon_assets import icon_path


class DashboardPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)

    def __init__(
        self,
        services: ApplicationServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("page-dashboard")
        self.services = services
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 12, 16, 16)
        outer.setSpacing(10)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        title = QLabel("Security Overview")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Local identity verification and privacy-first endpoint security monitoring"
        )
        subtitle.setObjectName("subtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        header.addLayout(titles, 1)
        self.protection_status = StatusIndicator("Protection inactive", "warning")
        header.addWidget(self.protection_status)
        self.monitor_button = QPushButton("Start Scan")
        self.monitor_button.setIcon(QIcon(icon_path("target-scan.png")))
        self.monitor_button.setObjectName("primaryButton")
        self.monitor_button.clicked.connect(lambda: self.actionRequested.emit("scan"))
        header.addWidget(self.monitor_button)
        self.monitoring_button = QPushButton("Start Monitoring")
        self.monitoring_button.setIcon(QIcon(icon_path("camera.png")))
        self.monitoring_button.clicked.connect(
            lambda: self.actionRequested.emit("toggle-monitoring")
        )
        header.addWidget(self.monitoring_button)
        self.report_button = QPushButton("Export Report")
        self.report_button.setIcon(QIcon(icon_path("export-document.png")))
        self.report_button.clicked.connect(lambda: self.actionRequested.emit("export"))
        header.addWidget(self.report_button)
        outer.addLayout(header)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        metrics = (
            ("Identity Protection", "—", "Enrollment not configured", "#20d49a", "face-scan.png"),
            (
                "Endpoint Security Score",
                "—",
                "No risk assessment available",
                "#f5ad32",
                "security-score-gauge.png",
            ),
            ("Active Threats", "0", "No open local alerts", "#f04b67", "critical-alert.png"),
            (
                "Protected Files",
                "0",
                "No integrity baseline configured",
                "#00b9e8",
                "locked-file.png",
            ),
        )
        self.metric_cards: list[MetricCard] = []
        for column, (label, value, detail, accent, icon) in enumerate(metrics):
            card = MetricCard(label, value, detail, accent, icon=icon)
            self.metric_cards.append(card)
            grid.addWidget(card, 0, column)
            grid.setColumnStretch(column, 1)

        self.alert_chart = ChartWidget(
            "Security Events — Last 24 Hours",
            "No locally recorded security events in the last 24 hours.",
            icon="critical-alert.png",
            color="#00c7f2",
            mode="line",
            period="Last 24 Hours",
        )
        self.threat_chart = ChartWidget(
            "3D Threat Landscape",
            "Threat topology appears when local security events are recorded.",
            icon="network-nodes.png",
            mode="network",
        )
        grid.addWidget(self.alert_chart, 1, 0, 1, 2)
        grid.addWidget(self.threat_chart, 1, 2, 1, 2)

        self.identity_chart = ChartWidget(
            "Identity Verification",
            "No identity verification events recorded.",
            icon="identity-verified.png",
            color="#18d89b",
            mode="pie",
        )
        self.integrity_chart = ChartWidget(
            "File Integrity Activity",
            "No file-integrity events recorded.",
            icon="verified-document.png",
            color="#08b9f3",
            mode="bar",
            period="Local history",
        )
        self.feed = NotificationPanel("Live Security Feed")
        self.feed.set_message(
            "No local security events have been recorded. Monitoring is disabled "
            "until you enable a data source."
        )
        grid.addWidget(self.identity_chart, 2, 0)
        grid.addWidget(self.integrity_chart, 2, 1)
        grid.addWidget(self.feed, 2, 2, 1, 2)

        self.network_card = self._status_card(
            "Network Activity",
            "Connection metadata collection is disabled.",
            "Open Network Monitor",
            "network-monitor",
            "network-nodes.png",
        )
        self.process_card = self._status_card(
            "Process Monitor",
            "Process collection is disabled.",
            "Open Process Monitor",
            "process-monitor",
            "processor.png",
        )
        self.windows_card = self._status_card(
            "Windows Logs",
            "Windows event log collection is disabled.",
            "Open Windows Logs",
            "windows-logs",
            "windows-system-file.png",
        )
        self.camera_card = self._status_card(
            "Camera",
            "Camera access is disabled.",
            "Open Identity Protection",
            "identity-protection",
            "camera.png",
        )
        self.identity_card = self.camera_card
        grid.addWidget(self.network_card, 3, 0)
        grid.addWidget(self.process_card, 3, 1)
        grid.addWidget(self.windows_card, 3, 2)
        grid.addWidget(self.camera_card, 3, 3)
        outer.addLayout(grid)
        outer.addStretch(1)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(15_000)
        self._refresh_timer.timeout.connect(self.refresh_security_data)
        self._refresh_timer.start()
        self.refresh_security_data()

    def refresh_security_data(self) -> None:
        now_utc = datetime.now(UTC)
        start_utc = now_utc - timedelta(hours=24)
        try:
            events = self.services.security_repository.list_events(limit=8)
            hourly_event_rows = self.services.database.fetchall(
                "SELECT occurred_at FROM security_events WHERE occurred_at >= ?",
                (start_utc.isoformat(),),
            )
            alert_counts = self.services.database.fetchall(
                "SELECT severity, COUNT(*) AS count FROM alerts "
                "WHERE status = 'open' GROUP BY severity"
            )
            integrity_counts = self.services.database.fetchall(
                "SELECT event_type, COUNT(*) AS count FROM security_events "
                "WHERE source LIKE '%integrity%' GROUP BY event_type "
                "ORDER BY count DESC LIMIT 8"
            )
            file_count = self.services.database.fetchone(
                "SELECT COUNT(*) AS count FROM file_integrity_baselines"
            )
            identity_counts = self.services.database.fetchall(
                "SELECT state, COUNT(*) AS count FROM identity_events GROUP BY state"
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            for card in self.metric_cards:
                card.set_value("—")
                card.set_description(f"Local data unavailable: {exc}")
            self.alert_chart.set_message(f"Local security data unavailable: {exc}")
            self.feed.set_message(f"Could not load local security events: {exc}")
            return

        open_alert_count = sum(int(row["count"]) for row in alert_counts)
        self.metric_cards[2].set_value(str(open_alert_count))
        self.metric_cards[2].set_description(
            "Open local alerts" if open_alert_count else "No open local alerts"
        )
        self.metric_cards[3].set_value(str(file_count["count"] if file_count else 0))
        if file_count and file_count["count"]:
            self.metric_cards[3].set_description("Files in configured baselines")

        now_local = datetime.now().astimezone()
        hourly = [
            (
                (now_local - timedelta(hours=23 - index)).strftime("%I %p").lstrip("0"),
                0.0,
            )
            for index in range(24)
        ]
        for event in hourly_event_rows:
            try:
                occurred = datetime.fromisoformat(str(event["occurred_at"]))
                occurred = occurred.replace(tzinfo=UTC) if occurred.tzinfo is None else occurred
            except ValueError:
                continue
            bucket = min(
                23,
                max(0, int((occurred - start_utc).total_seconds() // 3600)),
            )
            label, count = hourly[bucket]
            hourly[bucket] = (label, count + 1)
        self.alert_chart.set_data(hourly)

        self.threat_chart.set_data(
            tuple((str(row["severity"]), float(row["count"])) for row in alert_counts)
        )
        self.identity_chart.set_data(
            tuple(
                (str(row["state"]).replace("_", " ").title(), float(row["count"]))
                for row in identity_counts
            )
        )

        self.integrity_chart.set_data(
            tuple(
                (
                    str(row["event_type"]).replace("_", " ").title(),
                    float(row["count"]),
                )
                for row in integrity_counts
            )
        )
        self.feed.set_events(events[:8])
        self._set_collector_summary(
            "Network Activity", self.services.settings.network_monitoring_enabled
        )
        self._set_collector_summary(
            "Process Monitor", self.services.settings.process_monitoring_enabled
        )
        self._set_collector_summary(
            "Windows Logs", self.services.settings.windows_log_collection_enabled
        )
        self.set_camera_state(
            self.services.identity_service.camera_state,
            self.services.identity_service.camera_detail,
        )

    def set_identity_state(
        self,
        enrolled_name: str | None,
        monitoring: bool,
        state: str,
        detail: str,
        unknown_faces: int,
        last_event=None,
    ) -> None:
        endpoint_running = any(
            worker.isRunning() for worker in self.services.endpoint_service.workers.values()
        )
        self.protection_status.set_text(
            "PROTECTION ACTIVE" if monitoring or endpoint_running else "PROTECTION INACTIVE"
        )
        self.protection_status.set_state(        "success" if monitoring or endpoint_running else "warning"
        )
        self.monitoring_button.setText(
        "Pause Monitoring" if monitoring else "Start Monitoring"
        )
        self.monitoring_button.setIcon(
        QIcon(
            icon_path(
                "pause-monitoring.png" if monitoring else "camera.png"
            )
        ))
        self.metric_cards[0].set_value("ENROLLED" if enrolled_name else "—")
        self.metric_cards[0].set_description(enrolled_name or "Consent-based enrollment required")
        self.metric_cards[1].set_value("—")
        self.metric_cards[1].set_description(
            "Risk scoring will appear when endpoint data is available"
        )
        if last_event is not None:
            self.identity_chart.setToolTip(
                f"Last result: {last_event.state.replace('_', ' ').title()} — {detail}"
            )
        self.set_camera_state(
            self.services.identity_service.camera_state,
            self.services.identity_service.camera_detail,
        )
        self.metric_cards[0].setToolTip(
            f"{enrolled_name or 'No enrolled identity'}; "
            f"{unknown_faces} unknown-face events; {detail}"
        )

    def set_identity_error(self, message: str) -> None:
        self.metric_cards[0].set_value("—")
        self.metric_cards[0].set_description(f"Identity history unavailable: {message}")
        self.identity_chart.set_message(f"Identity history unavailable: {message}")

    def set_camera_state(self, state: str, detail: str) -> None:
        descriptions = {
            "disabled": "Camera access is disabled in Settings.",
            "idle": "Camera access enabled · no active camera session.",
            "connecting": "Opening camera…",
            "connected": "Camera connected and ready.",
            "unavailable": "Camera unavailable; no attack is inferred.",
        }
        body = self.camera_card.findChild(QLabel, "cardBody")
        body.setText(descriptions.get(state, "Camera status unknown."))
        body.setToolTip(detail)

    def _set_collector_summary(self, title: str, enabled: bool) -> None:
        sources = {
            "Network Activity": "network",
            "Process Monitor": "process",
            "Windows Logs": "windows-event-log",
            "Camera": "camera",
        }
        card = next(
            card
            for card in (
                self.network_card,
                self.process_card,
                self.windows_card,
                self.camera_card,
            )
            if card.property("cardTitle") == title
        )
        body = card.findChild(QLabel, "cardBody")
        if title == "Camera":
            self.set_camera_state(
                self.services.identity_service.camera_state,
                self.services.identity_service.camera_detail,
            )
            return
        worker = self.services.endpoint_service.workers.get(sources[title])
        running = worker is not None and worker.isRunning()
        body.setText(
            "Collection is active"
            if running
            else "Enabled in settings · not running"
            if enabled
            else "Collection is disabled."
        )

    def _status_card(
        self,
        title: str,
        message: str,
        action: str,
        page_key: str,
        icon: str,
    ) -> QFrame:
        card = QFrame()
        card.setObjectName("panel")
        card.setProperty("cardTitle", title)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(10, 9, 10, 9)
        icon_label = QLabel()
        icon_label.setPixmap(QIcon(icon_path(icon)).pixmap(19, 19))
        layout.addWidget(icon_label, 0)
        text_layout = QVBoxLayout()
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        body = QLabel(message)
        body.setObjectName("cardBody")
        body.setProperty("class", "muted")
        body.setWordWrap(True)
        text_layout.addWidget(heading)
        text_layout.addWidget(body)
        layout.addLayout(text_layout, 1)
        button = QPushButton("›")
        button.setFixedWidth(28)
        button.setToolTip(action)
        button.clicked.connect(lambda: self.pageRequested.emit(page_key))
        layout.addWidget(button)
        return card
