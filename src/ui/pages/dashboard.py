"""Service-backed, privacy-first security dashboard."""

import json
import sqlite3
import time
from datetime import UTC, datetime, timedelta

import psutil
from PySide6.QtCore import QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.endpoint.host_topology import HostTopologyCollector
from src.endpoint.process_monitor import ProcessMonitor
from src.network.connection_monitor import ConnectionMonitor
from src.ui.components.chart_widget import ChartWidget
from src.ui.components.dashboard_activity import (
    DashboardLiveFeed,
    DashboardNetworkPanel,
    DashboardProcessPanel,
)
from src.ui.components.dashboard_summary import (
    DashboardFilesCard,
    DashboardIdentityCard,
    DashboardScoreCard,
    DashboardThreatCard,
)
from src.ui.components.integrity_activity_chart import FileIntegrityActivityChart
from src.ui.components.security_alert_chart import SecurityAlertChart
from src.ui.components.status_indicator import StatusIndicator
from src.ui.components.threat_landscape import ThreatLandscapeWidget
from src.ui.icon_assets import icon_path


def _ratio_percent(numerator: int, denominator: int) -> int | None:
    if denominator <= 0:
        return None
    return min(100, max(0, round(numerator * 100 / denominator)))


class DashboardPage(QWidget):
    actionRequested = Signal(str)
    pageRequested = Signal(str)
    blockIpRequested = Signal(str)
    quarantineRequested = Signal(int)

    def __init__(
        self,
        services: ApplicationServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("page-dashboard")
        self.setMinimumWidth(0)
        self.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred,
        )
        self.services = services
        self._process_snapshot = ProcessMonitor(services.settings.process_exclusions)
        self._topology_collector = HostTopologyCollector()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 8, 10, 10)
        outer.setSpacing(8)

        header = QHBoxLayout()
        header.setSpacing(6)
        titles = QVBoxLayout()
        title = QLabel("Security Overview")
        title.setObjectName("pageTitle")
        title.setStyleSheet("font-size: 16pt; font-weight: 650;")
        subtitle = QLabel(
            "Real-time protection, local identity verification and intelligent threat monitoring"
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        subtitle.setMinimumWidth(0)
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
        self.update_button = QPushButton("Check Updates")
        self.update_button.setIcon(QIcon(icon_path("system-activity.png")))
        self.update_button.clicked.connect(lambda: self.actionRequested.emit("check-updates"))
        header.addWidget(self.update_button)
        for button in (
            self.monitor_button,
            self.monitoring_button,
            self.report_button,
            self.update_button,
        ):
            button.setStyleSheet("font-size: 8pt; padding: 4px 6px;")
        outer.addLayout(header)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        for column in range(16):
            grid.setColumnStretch(column, 1)
        self.identity_summary = DashboardIdentityCard()
        self.score_summary = DashboardScoreCard()
        self.threat_summary = DashboardThreatCard()
        self.threat_summary.viewAllRequested.connect(
            lambda: self.pageRequested.emit("alerts")
        )
        self.files_summary = DashboardFilesCard()
        self.metric_cards: list[
            DashboardIdentityCard
            | DashboardScoreCard
            | DashboardThreatCard
            | DashboardFilesCard
        ] = [
            self.identity_summary,
            self.score_summary,
            self.threat_summary,
            self.files_summary,
        ]
        for index, card in enumerate(self.metric_cards):
            grid.addWidget(card, 0, index * 4, 1, 4)

        self.alert_chart = SecurityAlertChart()
        self.alert_chart.viewAllRequested.connect(
            lambda: self.pageRequested.emit("alerts")
        )
        self.threat_chart = ThreatLandscapeWidget()
        self.threat_chart.refreshRequested.connect(self.refresh_host_topology)
        self.threat_chart.blockIpRequested.connect(self.blockIpRequested)
        self.threat_chart.quarantineRequested.connect(self.quarantineRequested)
        self.threat_chart.pageRequested.connect(self.pageRequested)
        self.identity_chart = ChartWidget(
            "Identity Verification",
            "No identity verification events recorded.",
            icon="identity-verified.png",
            color="#18d89b",
            mode="pie",
        )
        self.integrity_chart = FileIntegrityActivityChart()
        self.integrity_chart.periodChanged.connect(
            self._on_integrity_period_changed
        )
        self.feed = DashboardLiveFeed()
        self.feed.viewAllRequested.connect(lambda: self.pageRequested.emit("alerts"))
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
        self.network_activity = DashboardNetworkPanel()
        self.process_activity = DashboardProcessPanel()
        self.network_activity.viewAllRequested.connect(
            lambda: self.pageRequested.emit("network-monitor")
        )
        self.process_activity.viewAllRequested.connect(
            lambda: self.pageRequested.emit("process-monitor")
        )
        self.network_activity.setMinimumHeight(100)
        self.process_activity.setMinimumHeight(100)
        self.collector_status = QFrame()
        self.collector_status.setObjectName("panel")
        self.collector_status.setMinimumHeight(90)
        collector_layout = QGridLayout(self.collector_status)
        collector_layout.setContentsMargins(5, 5, 5, 5)
        collector_layout.setSpacing(4)
        for index, card in enumerate(
            (self.network_card, self.process_card, self.windows_card, self.camera_card)
        ):
            collector_layout.addWidget(card, index, 0)

        grid.addWidget(self.alert_chart, 1, 0, 1, 8)
        grid.addWidget(self.threat_chart, 1, 8, 1, 8)
        grid.addWidget(self.identity_chart, 2, 0, 1, 4)
        grid.addWidget(self.integrity_chart, 2, 4, 1, 4)
        grid.addWidget(self.feed, 2, 8, 1, 8)
        grid.addWidget(self.network_activity, 3, 0, 1, 8)
        grid.addWidget(self.process_activity, 3, 8, 1, 5)
        grid.addWidget(self.collector_status, 3, 13, 1, 3)
        grid.setRowStretch(1, 3)
        grid.setRowStretch(2, 3)
        grid.setRowStretch(3, 1)
        self._dashboard_grid = grid
        self._desktop_placements = tuple(
            (grid.itemAt(index).widget(), *grid.getItemPosition(index))
            for index in range(grid.count())
            if grid.itemAt(index).widget() is not None
        )
        self._desktop_size_policies = {
            placement[0]: placement[0].sizePolicy()
            for placement in self._desktop_placements
        }
        self._compact_layout = False
        self._responsive_layout_active = False
        outer.addLayout(grid, 1)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(15_000)
        self._refresh_timer.timeout.connect(self.refresh_security_data)
        self._refresh_timer.start()
        self.refresh_security_data()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._responsive_layout_active = True
        self._update_responsive_layout()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self._responsive_layout_active:
            self._update_responsive_layout()

    def _update_responsive_layout(self) -> None:
        parent = self.parentWidget()
        available_width = parent.width() if parent is not None else self.width()
        compact = available_width < 760
        if compact == self._compact_layout:
            return
        # Stack panels instead of letting IP and table labels widen the viewport.
        grid = self._dashboard_grid
        for placement in self._desktop_placements:
            widget = placement[0]
            grid.removeWidget(widget)
            if compact:
                widget.setMinimumWidth(0)
                widget.setSizePolicy(
                    QSizePolicy.Policy.Ignored,
                    QSizePolicy.Policy.Preferred,
                )
            else:
                widget.setSizePolicy(self._desktop_size_policies[widget])
        if compact:
            for row in range(4):
                grid.setRowStretch(row, 0)
            for row, placement in enumerate(self._desktop_placements):
                widget = placement[0]
                grid.addWidget(widget, row, 0, 1, 16)
        else:
            for widget, row, column, row_span, column_span in self._desktop_placements:
                grid.addWidget(widget, row, column, row_span, column_span)
            grid.setRowStretch(1, 3)
            grid.setRowStretch(2, 3)
            grid.setRowStretch(3, 1)
        self._compact_layout = compact

    def refresh_security_data(self) -> None:
        now_utc = datetime.now(UTC)
        start_utc = now_utc - timedelta(hours=24)
        try:
            events = self.services.security_repository.list_events(limit=100)
            hourly_event_rows = self.services.database.fetchall(
                "SELECT occurred_at, severity FROM security_events WHERE occurred_at >= ?",
                (start_utc.isoformat(),),
            )
            alert_counts = self.services.database.fetchall(
                "SELECT severity, COUNT(*) AS count FROM alerts "
                "WHERE status = 'open' GROUP BY severity"
            )
            file_count = self.services.database.fetchone(
                "SELECT COUNT(*) AS count FROM file_integrity_baselines"
            )
            file_baseline_ready = self.services.endpoint_service.has_file_baseline()
            identity_counts = self.services.database.fetchall(
                "SELECT state, COUNT(*) AS count FROM identity_events "
                "WHERE occurred_at >= ? GROUP BY state",
                (start_utc.isoformat(),),
            )
            collector_counts = self.services.database.fetchall(
                "SELECT source, COUNT(*) AS count FROM security_events "
                "WHERE occurred_at >= ? GROUP BY source",
                (start_utc.isoformat(),),
            )
            hourly_alert_rows = self.services.database.fetchall(
                "SELECT created_at FROM alerts "
                "WHERE status = 'open' "
                "AND created_at >= ?",
                (start_utc.isoformat(),),
            )
            file_change_count = self.services.database.fetchone(
                "SELECT COUNT(*) AS count FROM security_events "
                "WHERE source LIKE '%integrity%' "
                "AND event_type IN "
                "('file_added', 'file_changed', 'file_modified', 'file_missing', "
                "'file_renamed') "
                "AND occurred_at >= ?",
                (start_utc.isoformat(),),
            )
            active_file_alerts = self.services.database.fetchall(
                "SELECT e.attributes_json FROM alerts a "
                "JOIN security_events e ON e.id = a.event_id "
                "WHERE a.status IN ('open', 'acknowledged', 'investigating') "
                "AND e.source LIKE 'file-integrity%'"
            )
            process_count = len(psutil.pids())
            self._process_snapshot.exclusions = tuple(
                item.casefold()
                for item in self.services.settings.process_exclusions
            )
            process_snapshot = (
                self._process_snapshot.snapshot(limit=None)
                if self.services.settings.process_monitoring_enabled
                else None
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            for card in self.metric_cards:
                card.set_error(f"Local data unavailable: {exc}")
            self.alert_chart.set_message(f"Local security data unavailable: {exc}")
            self.feed.set_message(f"Could not load local security events: {exc}")
            self.network_activity.set_message(f"Could not load local network activity: {exc}")
            self.process_activity.set_message(f"Could not load local process activity: {exc}")
            return

        alert_severities = {
            str(row["severity"]).casefold(): int(row["count"])
            for row in alert_counts
        }
        hourly_alert_counts = [0] * 24
        for alert in hourly_alert_rows:
            try:
                occurred = datetime.fromisoformat(str(alert["created_at"]))
                occurred = occurred.replace(tzinfo=UTC) if occurred.tzinfo is None else occurred
            except ValueError:
                continue
            bucket = min(
                23,
                max(0, int((occurred - start_utc).total_seconds() // 3600)),
            )
            hourly_alert_counts[bucket] += 1
        self.threat_summary.set_alert_data(alert_severities, hourly_alert_counts)
        self.files_summary.set_file_data(
            int(file_count["count"] if file_count else 0),
            int(file_change_count["count"] if file_change_count else 0),
            len(active_file_alerts),
        )
        counts_by_source = {
            str(row["source"]).casefold(): int(row["count"])
            for row in collector_counts
        }
        def count_for(prefix: str) -> int:
            return sum(
                count
                for source, count in counts_by_source.items()
                if source.startswith(prefix)
            )
        identity_states = {
            str(row["state"]).casefold(): int(row["count"])
            for row in identity_counts
        }
        freshness_limit = (
            self.services.settings.endpoint_poll_interval_seconds * 3
        )

        def collector_is_fresh(source: str) -> bool:
            worker = self.services.endpoint_service.workers.get(source)
            last_success = (
                worker.last_successful_collection_at if worker is not None else None
            )
            return (
                worker is not None
                and worker.isRunning()
                and last_success is not None
                and time.monotonic() - last_success <= freshness_limit
            )
        identity_attempts = sum(identity_states.values())
        identity_passes = identity_states.get("recognized", 0)
        baseline_files = int(file_count["count"] if file_count else 0)
        alerted_file_paths: set[str] = set()
        file_alerts_without_path = 0
        for row in active_file_alerts:
            try:
                attributes = json.loads(str(row["attributes_json"]))
            except json.JSONDecodeError:
                file_alerts_without_path += 1
                continue
            path = attributes.get("path") if isinstance(attributes, dict) else None
            if isinstance(path, str) and path:
                alerted_file_paths.add(path.casefold())
            else:
                file_alerts_without_path += 1
        file_alerted_count = min(
            baseline_files, len(alerted_file_paths) + file_alerts_without_path
        )
        clean_baseline_files = max(0, baseline_files - file_alerted_count)
        process_details_count = sum(
            process.executable is not None for process in process_snapshot or ()
        )

        network_counts: tuple[int, int] | None = None
        network_detail = "Network collection is disabled"
        if self.services.settings.network_monitoring_enabled:
            try:
                network_counts = ConnectionMonitor.inventory_counts()
                network_detail = (
                    f"{network_counts[1]:,} attributed / {network_counts[0]:,} "
                    "remote connections"
                )
            except PermissionError as exc:
                network_detail = str(exc)

        windows_worker = self.services.endpoint_service.workers.get(
            "windows-event-log"
        )
        windows_channels: tuple[str, ...] = ()
        windows_read_channels: tuple[str, ...] = ()
        if windows_worker is not None and windows_worker.isRunning():
            collector = windows_worker.collector
            windows_channels = tuple(getattr(collector, "channels", ()))
            windows_read_channels = tuple(
                getattr(collector, "last_read_channels", ())
            )

        process_worker_running = collector_is_fresh("process")
        network_worker_running = collector_is_fresh("network")
        file_worker_running = collector_is_fresh("file-integrity")
        windows_worker_running = collector_is_fresh("windows-event-log")
        process_statistic = (
            f"{len(process_snapshot):,}/{process_count:,} processes"
            if process_snapshot is not None
            else f"{process_count:,} processes · monitor off"
        )
        if process_snapshot is not None and not process_worker_running:
            process_statistic += " · stopped"
        windows_statistic = (
            f"{len(windows_read_channels)}/{len(windows_channels)} channels read"
            if windows_channels and windows_read_channels
            else f"{count_for('windows-event-log'):,} collected records · "
            "waiting for a successful channel read"
        )
        files_score = (
            _ratio_percent(clean_baseline_files, baseline_files)
            if file_baseline_ready and file_worker_running and baseline_files > 0
            else None
        )
        identity_score = _ratio_percent(identity_passes, identity_attempts)
        process_score = (
            _ratio_percent(process_details_count, process_count)
            if process_worker_running and process_count > 0
            else None
        )
        network_score = (
            _ratio_percent(network_counts[1], network_counts[0])
            if network_worker_running and network_counts is not None
            else None
        )
        windows_score = (
            _ratio_percent(len(windows_read_channels), len(windows_channels))
            if windows_worker_running
            and windows_channels
            and windows_read_channels
            else None
        )
        self.score_summary.set_factors(
            {
                "Identity": (
                    identity_score,
                    f"{identity_passes:,}/{identity_attempts:,} samples",
                ),
                "Files": (
                    files_score,
                    (
                        f"{clean_baseline_files:,}/{baseline_files:,} clean files"
                        if file_worker_running
                        else f"{baseline_files:,} baseline · monitor off"
                    )
                    if file_baseline_ready
                    else "No matching baseline",
                ),
                "Processes": (
                    process_score,
                    process_statistic,
                ),
                "Network": (
                    network_score,
                    (
                        f"{network_counts[1]:,}/{network_counts[0]:,} remote"
                        if network_counts is not None
                        else "not measured"
                    ),
                ),
                "Windows": (
                    windows_score,
                    windows_statistic,
                ),
            }
        )
        for name, tooltip in {
            "Identity": (
                "Recognized verification samples divided by all recorded identity "
                "samples in the last 24 hours. No samples means no percentage."
            ),
            "Files": (
                "Baseline paths without an active file-integrity alert divided by "
                "the current configured baseline size. This is not a malware scan."
            ),
            "Processes": (
                "Visible processes with an executable path divided by all OS process "
                "IDs. Configured exclusions and inaccessible processes lower coverage."
            ),
            "Network": (
                "Live remote connections attributed to a process divided by all live "
                "remote connections. No remote connections means no percentage."
            ),
            "Windows": (
                "Windows event-log channels successfully read in the last collection "
                "cycle divided by the configured local channels."
            ),
        }.items():
            details = {
                "Identity": (
                    f"{identity_passes:,} recognized of {identity_attempts:,} samples"
                ),
                "Files": (
                    f"{clean_baseline_files:,} without active file alerts of "
                    f"{baseline_files:,} baseline paths"
                ),
                "Processes": process_statistic,
                "Network": network_detail,
                "Windows": windows_statistic,
            }[name]
            detail_tooltip = f"{tooltip}\nCurrent sample: {details}"
            self.score_summary.factor_values[name].setToolTip(detail_tooltip)
            self.score_summary.factor_progress[name].setToolTip(detail_tooltip)

        now_local = datetime.now().astimezone()
        hourly = [
            (
                (now_local - timedelta(hours=23 - index)).strftime("%I %p").lstrip("0"),
                0.0,
            )
            for index in range(24)
        ]
        hourly_severities = [
            {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for _ in range(24)
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
            severity = str(event["severity"]).casefold()
            if severity in hourly_severities[bucket]:
                hourly_severities[bucket][severity] += 1
        self.alert_chart.set_data(hourly, hourly_severities)

        self.identity_chart.set_data(
            tuple(
                (str(row["state"]).replace("_", " ").title(), float(row["count"]))
                for row in identity_counts
            )
        )

        self.refresh_host_topology()
        self.refresh_integrity_activity()
        self.feed.set_events(events[:8])
        self.network_activity.set_events(
            [event for event in events if "network" in str(event["source"]).casefold()]
        )
        if process_snapshot is None:
            self.process_activity.set_message(
                "Enable process monitoring in Settings to view live process usage."
            )
        else:
            self.process_activity.set_processes(process_snapshot[:4])
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

    def refresh_host_topology(self) -> None:
        try:
            topology = self._topology_collector.collect()
            alerts = self.services.security_repository.list_alerts(
                limit=1, status="open"
            )
            finding_row = self.services.database.fetchone(
                "SELECT id, provider, path, rule, sha256, status, detected_at "
                "FROM malware_findings WHERE status = 'detected' "
                "ORDER BY detected_at DESC LIMIT 1"
            )
            finding = dict(finding_row) if finding_row is not None else None
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.threat_chart.set_status(
                f"Could not refresh local host or alert context: {exc}",
                error=True,
            )
            return
        self.threat_chart.set_snapshot(
            topology,
            alerts[0] if alerts else None,
            finding,
        )

    def refresh_integrity_activity(self) -> None:
        try:
            now = datetime.now(UTC)
            start = self.integrity_chart.range_start_utc(now)
            rows = self.services.database.fetchall(
                "SELECT occurred_at, event_type FROM security_events "
                "WHERE source LIKE '%integrity%' AND occurred_at >= ? "
                "AND occurred_at <= ? "
                "AND event_type IN "
                "('file_added', 'file_changed', 'file_modified', 'file_missing', "
                "'file_renamed') "
                "ORDER BY occurred_at",
                (start.isoformat(), now.isoformat()),
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.integrity_chart.set_message(
                f"Could not load file-integrity activity: {exc}"
            )
            return
        self.integrity_chart.set_events(
            tuple(dict(row) for row in rows),
            now,
        )

    def _on_integrity_period_changed(self, period: str) -> None:
        if period == self.integrity_chart.period:
            self.refresh_integrity_activity()

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
        self.identity_summary.set_identity(
            enrolled_name,
            state,
            last_event,
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
        self.identity_summary.set_error(f"Identity history unavailable: {message}")
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
        icon_label.setPixmap(QIcon(icon_path(icon)).pixmap(16, 16))
        layout.addWidget(icon_label, 0)
        text_layout = QVBoxLayout()
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        heading.setStyleSheet("font-size: 8pt;")
        body = QLabel(message)
        body.setObjectName("cardBody")
        body.setProperty("class", "muted")
        body.setWordWrap(True)
        text_layout.addWidget(heading)
        text_layout.addWidget(body)
        layout.addLayout(text_layout, 1)
        button = QPushButton("›")
        button.setFixedWidth(20)
        button.setFixedHeight(24)
        button.setToolTip(action)
        button.clicked.connect(lambda: self.pageRequested.emit(page_key))
        layout.addWidget(button)
        return card
