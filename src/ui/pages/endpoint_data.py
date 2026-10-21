"""Service-backed views for local endpoint monitoring data."""

from __future__ import annotations

import ipaddress
import socket
import sqlite3

import psutil
from PySide6.QtCore import QEvent, QObject, QRunnable, QThreadPool, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.app.dependencies import ApplicationServices
from src.endpoint.process_monitor import ProcessMonitor, ProcessSnapshot
from src.response.network_actions import allow_ip, block_ip
from src.response.process_actions import terminate_process
from src.ui.components.data_table import DataTable
from src.ui.components.status_indicator import StatusIndicator
from src.ui.icon_assets import icon_path
from src.ui.navigation import PAGES_BY_KEY


class _ReverseDnsSignals(QObject):
    resolved = Signal(str, str)


class _ReverseDnsLookup(QRunnable):
    def __init__(self, address: str) -> None:
        super().__init__()
        self.address = address
        self.signals = _ReverseDnsSignals()

    def run(self) -> None:
        try:
            hostname = socket.gethostbyaddr(self.address)[0].rstrip(".")
        except socket.herror:
            hostname = "No reverse-DNS name available"
        except OSError as exc:
            hostname = f"Reverse-DNS lookup failed: {exc}"
        else:
            try:
                forward_addresses = {
                    str(ipaddress.ip_address(result[4][0]))
                    for result in socket.getaddrinfo(
                        hostname, None, type=socket.SOCK_STREAM
                    )
                }
            except OSError as exc:
                hostname = (
                    f"{hostname} (PTR only; forward lookup failed: {exc})"
                )
            else:
                hostname = (
                    f"{hostname} (forward-confirmed)"
                    if self.address in forward_addresses
                    else f"{hostname} (PTR only; forward address differs)"
                )
        self.signals.resolved.emit(self.address, hostname)


class _ForwardDnsLookup(QRunnable):
    def __init__(self, domain: str) -> None:
        super().__init__()
        self.domain = domain
        self.signals = _ReverseDnsSignals()

    def run(self) -> None:
        try:
            results = socket.getaddrinfo(
                self.domain, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            result = f"DNS lookup failed: {exc}"
        else:
            addresses = sorted(
                {
                    str(ipaddress.ip_address(address[4][0]))
                    for address in results
                }
            )
            result = ", ".join(addresses) or "No A/AAAA addresses returned"
        self.signals.resolved.emit(self.domain, result)


class EndpointDataPage(QWidget):
    """Refresh a local event-backed table only while its page is visible."""

    actionRequested = Signal(str)

    def __init__(
        self,
        page_key: str,
        services: ApplicationServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.services = services
        self.page_key = page_key
        definition = PAGES_BY_KEY[page_key]
        self.setObjectName(f"page-{page_key}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 22)
        layout.setSpacing(14)
        title = QLabel(definition.title)
        title.setObjectName("pageTitle")
        subtitle = QLabel(definition.description)
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        toolbar = QHBoxLayout()
        self.source_status = StatusIndicator("Waiting for a local data source")
        toolbar.addWidget(self.source_status)
        toolbar.addStretch(1)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setIcon(QIcon(icon_path("refresh.png")))
        self.refresh_button.clicked.connect(self.refresh_data)
        toolbar.addWidget(self.refresh_button)
        self.terminate_button: QPushButton | None = None
        self.host_details_button: QPushButton | None = None
        self.domain_lookup_button: QPushButton | None = None
        self.block_ip_button: QPushButton | None = None
        self.allow_ip_button: QPushButton | None = None
        self._processes_by_row_id: dict[str, ProcessSnapshot] = {}
        self._network_events_by_row_id: dict[str, dict[str, object]] = {}
        self._network_rows_by_address: dict[str, list[str]] = {}
        self._reverse_dns_cache: dict[str, str] = {}
        self._reverse_dns_pending: set[str] = set()
        self._reverse_dns_jobs: dict[str, _ReverseDnsLookup] = {}
        self._forward_dns_jobs: set[_ForwardDnsLookup] = set()
        self._pending_host_details: tuple[str, dict[str, object]] | None = None
        self._dns_pool = QThreadPool(self)
        self._dns_pool.setMaxThreadCount(8)
        if page_key == "process-monitor":
            self.terminate_button = QPushButton("End selected task")
            self.terminate_button.setIcon(QIcon(icon_path("delete.png")))
            self.terminate_button.setEnabled(False)
            self.terminate_button.clicked.connect(self._terminate_selected_process)
            toolbar.addWidget(self.terminate_button)
        elif page_key == "network-monitor":
            self.host_details_button = QPushButton("Host discovery")
            self.host_details_button.setIcon(QIcon(icon_path("internet-search.png")))
            self.host_details_button.clicked.connect(self._show_host_details)
            self.domain_lookup_button = QPushButton("Lookup domain…")
            self.domain_lookup_button.setIcon(
                QIcon(icon_path("internet-search.png"))
            )
            self.domain_lookup_button.clicked.connect(self._lookup_domain)
            self.block_ip_button = QPushButton("Block IP")
            self.block_ip_button.setIcon(QIcon(icon_path("firewall.png")))
            self.block_ip_button.setEnabled(False)
            self.block_ip_button.clicked.connect(self._block_selected_ip)
            self.allow_ip_button = QPushButton("Allow IP…")
            self.allow_ip_button.setIcon(QIcon(icon_path("shield-check.png")))
            self.allow_ip_button.clicked.connect(self._allow_ip)
            toolbar.addWidget(self.host_details_button)
            toolbar.addWidget(self.domain_lookup_button)
            toolbar.addWidget(self.block_ip_button)
            toolbar.addWidget(self.allow_ip_button)
        layout.addLayout(toolbar)

        self.table = DataTable(
            definition.columns,
            empty_message="No matching local endpoint records have been collected.",
        )
        self.table.table.itemSelectionChanged.connect(self._update_action_buttons)
        layout.addWidget(self.table, 1)
        self._process_snapshot = (
            ProcessMonitor(services.settings.process_exclusions)
            if page_key == "process-monitor"
            else None
        )
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(
            max(1000, services.settings.endpoint_poll_interval_seconds * 1000)
        )
        self._refresh_timer.timeout.connect(self.refresh_data)

    def showEvent(self, event: QEvent) -> None:
        super().showEvent(event)
        self.refresh_data()
        self._refresh_timer.start()

    def hideEvent(self, event: QEvent) -> None:
        self._refresh_timer.stop()
        super().hideEvent(event)

    def refresh_data(self) -> None:
        try:
            if self.page_key == "network-monitor":
                self._refresh_network()
            elif self.page_key == "process-monitor":
                self._refresh_processes()
            else:
                raise ValueError(f"Unsupported endpoint data page: {self.page_key}")
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            self.table.show_error(f"Could not load local endpoint data: {exc}")
            self.source_status.set_text("Local data unavailable")
            self.source_status.set_state("error")

    def _refresh_network(self) -> None:
        if not self.services.settings.network_monitoring_enabled:
            self._network_events_by_row_id.clear()
            self.table.set_rows(())
            self.source_status.set_text("Network collection is disabled in Settings")
            self.source_status.set_state("warning")
            return
        events = self._events_for("network")
        rows = []
        row_ids = []
        self._network_events_by_row_id = {}
        self._network_rows_by_address = {}
        for event in events:
            attributes = _event_attributes(event)
            pid = attributes.get("pid")
            process_name = "—"
            if isinstance(pid, int):
                try:
                    process_name = psutil.Process(pid).name()
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    process_name = "Process ended"
            rows.append(
                (
                    (
                        f"{attributes.get('local_address') or '—'}:"
                        f"{attributes.get('local_port') or '—'}"
                    ),
                    attributes.get("remote_address") or "—",
                    "Lookup pending…",
                    attributes.get("remote_port") or "—",
                    attributes.get("protocol") or "—",
                    process_name,
                    attributes.get("state") or "—",
                )
            )
            row_id = str(event["id"])
            row_ids.append(row_id)
            self._network_events_by_row_id[row_id] = event
            address = attributes.get("remote_address")
            if isinstance(address, str):
                try:
                    normalized_address = str(ipaddress.ip_address(address))
                except ValueError:
                    continue
                self._network_rows_by_address.setdefault(
                    normalized_address, []
                ).append(row_id)
        self.table.set_rows(rows, row_ids)
        self._set_collector_status("network", len(rows))
        for address in self._network_rows_by_address:
            self._queue_reverse_dns(address)

    def _refresh_processes(self) -> None:
        if not self.services.settings.process_monitoring_enabled:
            self._processes_by_row_id.clear()
            self.table.set_rows(())
            self.source_status.set_text("Process collection is disabled in Settings")
            self.source_status.set_state("warning")
            return
        if self._process_snapshot is None:
            raise RuntimeError("Process snapshot collector was not initialized.")
        self._process_snapshot.exclusions = tuple(
            item.casefold() for item in self.services.settings.process_exclusions
        )
        processes = self._process_snapshot.snapshot(limit=None)
        os_process_count = len(psutil.pids())
        self._processes_by_row_id = {}
        rows = [
            (
                process.name,
                process.pid,
                process.user or "—",
                f"{process.cpu_percent:.1f}%"
                if process.cpu_percent is not None
                else "—",
                f"{process.memory_bytes / (1024 * 1024):.1f} MB"
                if process.memory_bytes is not None
                else "—",
                process.executable or "—",
            )
            for process in processes
        ]
        row_ids = []
        for process in processes:
            row_id = (
                f"{process.pid}:{process.create_time}"
                if process.create_time is not None
                else str(process.pid)
            )
            row_ids.append(row_id)
            self._processes_by_row_id[row_id] = process
        self.table.set_rows(rows, row_ids)
        self.source_status.set_text(
            f"Live process snapshot · {len(rows):,} visible / "
            f"{os_process_count:,} OS process IDs · risk not assessed"
        )
        self.source_status.set_state("success" if rows else "info")

    def _update_action_buttons(self) -> None:
        selected = len(self.table.selected_ids) == 1
        if self.terminate_button is not None:
            self.terminate_button.setEnabled(selected)
        if self.block_ip_button is not None:
            self.block_ip_button.setEnabled(selected)

    def _terminate_selected_process(self) -> None:
        row_ids = self.table.selected_ids
        if len(row_ids) != 1:
            self.source_status.set_text("Select one process to end")
            self.source_status.set_state("warning")
            return
        process = self._processes_by_row_id.get(row_ids[0])
        if process is None:
            self.source_status.set_text(
                "Process details are stale; refresh and select it again"
            )
            self.source_status.set_state("warning")
            return
        confirmed = QMessageBox.question(
            self,
            "End process?",
            f"End {process.name} (PID {process.pid})? Unsaved work in this process "
            "may be lost.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmed != QMessageBox.StandardButton.Yes:
            return
        try:
            terminate_process(process.pid, process.create_time)
        except (OSError, ValueError, RuntimeError) as exc:
            self.source_status.set_text(f"Could not end process: {exc}")
            self.source_status.set_state("error")
            return
        self.source_status.set_text(f"Ended {process.name} (PID {process.pid})")
        self.source_status.set_state("success")
        self.refresh_data()

    def _selected_network_event(self) -> dict[str, object] | None:
        row_ids = self.table.selected_ids
        return (
            self._network_events_by_row_id.get(row_ids[0])
            if len(row_ids) == 1
            else None
        )

    def _network_ip(self, title: str) -> str | None:
        event = self._selected_network_event()
        address = _event_attributes(event).get("remote_address") if event else None
        if isinstance(address, str) and address:
            try:
                return str(ipaddress.ip_address(address))
            except ValueError:
                return None
        value, accepted = QInputDialog.getText(
            self, title, "IPv4 or IPv6 address:"
        )
        if not accepted:
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            QMessageBox.warning(
                self, "Invalid IP address", "Enter a valid IPv4 or IPv6 address."
            )
            return None

    def _show_host_details(self) -> None:
        address = self._network_ip("Host discovery")
        if address is None:
            return
        event = self._selected_network_event()
        attributes = _event_attributes(event) if event else {}
        parsed = ipaddress.ip_address(address)
        hostname = self._reverse_dns_cache.get(address)
        if hostname is None:
            self._pending_host_details = (address, attributes)
            self.source_status.set_text(
                f"Looking up reverse and forward DNS for {address}…"
            )
            self.source_status.set_state("info")
            self._queue_reverse_dns(address)
            return
        self._present_host_details(address, attributes, parsed, hostname)

    def _present_host_details(
        self,
        address: str,
        attributes: dict[str, object],
        parsed: ipaddress.IPv4Address | ipaddress.IPv6Address,
        hostname: str,
    ) -> None:
        port = attributes.get("remote_port")
        protocol = str(attributes.get("protocol", "")).casefold()
        service = "Unknown service"
        if isinstance(port, int) and protocol in {"tcp", "udp"}:
            try:
                service = socket.getservbyport(port, protocol)
            except OSError:
                pass
        process_details = "Not available"
        pid = attributes.get("pid")
        if isinstance(pid, int):
            try:
                process = psutil.Process(pid)
                process_details = (
                    f"{process.name()} (PID {pid}, user {process.username()})"
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_details = f"Process {pid} ended or is inaccessible"
        detail_lines = (
            f"IP address: {address}",
            f"Address type: {'Private' if parsed.is_private else 'Public'} IPv{parsed.version}",
            f"Reverse DNS: {hostname}",
            f"Port / service: {port or '—'} / {service}",
            f"Protocol / state: {attributes.get('protocol', '—')} / {attributes.get('state', '—')}",
            f"Process: {process_details}",
            "Inspection uses local socket metadata only; packet contents are not captured.",
        )
        QMessageBox.information(self, "Host discovery", "\n".join(detail_lines))

    def _lookup_domain(self) -> None:
        domain, accepted = QInputDialog.getText(
            self, "Domain lookup", "Domain name (forward DNS lookup):"
        )
        if not accepted:
            return
        try:
            normalized_domain = domain.strip().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            normalized_domain = ""
        if (
            not normalized_domain
            or len(normalized_domain) > 253
            or any(character.isspace() for character in normalized_domain)
        ):
            QMessageBox.warning(
                self, "Invalid domain", "Enter a valid domain name."
            )
            return
        lookup = _ForwardDnsLookup(normalized_domain)
        lookup.signals.resolved.connect(self._on_forward_dns_resolved)
        self._forward_dns_jobs.add(lookup)
        self.source_status.set_text(
            f"Looking up {normalized_domain} with the system DNS resolver…"
        )
        self.source_status.set_state("info")
        self._dns_pool.start(lookup)

    def _on_forward_dns_resolved(self, domain: str, result: str) -> None:
        self._forward_dns_jobs = {
            job for job in self._forward_dns_jobs if job.domain != domain
        }
        self.source_status.set_text(f"Domain lookup complete: {domain}")
        self.source_status.set_state(
            "success" if "failed" not in result.casefold() else "warning"
        )
        QMessageBox.information(
            self, "Domain lookup", f"{domain}\n\nResolved addresses:\n{result}"
        )

    def _queue_reverse_dns(self, address: str) -> None:
        if address in self._reverse_dns_cache or address in self._reverse_dns_pending:
            return
        lookup = _ReverseDnsLookup(address)
        lookup.signals.resolved.connect(self._on_reverse_dns_resolved)
        self._reverse_dns_pending.add(address)
        self._reverse_dns_jobs[address] = lookup
        self._dns_pool.start(lookup)

    def _on_reverse_dns_resolved(self, address: str, hostname: str) -> None:
        self._reverse_dns_cache[address] = hostname
        self._reverse_dns_pending.discard(address)
        self._reverse_dns_jobs.pop(address, None)
        for row_id in self._network_rows_by_address.get(address, ()):
            self.table.update_cell(row_id, 2, hostname)
        pending_details = self._pending_host_details
        if pending_details is not None and pending_details[0] == address:
            self._pending_host_details = None
            self._present_host_details(
                address,
                pending_details[1],
                ipaddress.ip_address(address),
                hostname,
            )
        self._set_collector_status(
            "network", len(self._network_events_by_row_id)
        )

    def _block_selected_ip(self) -> None:
        address = self._network_ip("Block IP")
        if address is None:
            return
        confirmed = QMessageBox.warning(
            self,
            "Block network address?",
            f"Add Windows Firewall rules to block {address} for inbound and outbound "
            "traffic? This may disrupt active connections and may require "
            "administrator access.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmed != QMessageBox.StandardButton.Yes:
            return
        try:
            block_ip(address)
        except (OSError, ValueError, RuntimeError) as exc:
            self.source_status.set_text(f"Could not block {address}: {exc}")
            self.source_status.set_state("error")
            return
        self.source_status.set_text(f"Windows Firewall is blocking {address}")
        self.source_status.set_state("success")

    def _allow_ip(self) -> None:
        address = self._network_ip("Allow IP")
        if address is None:
            return
        confirmed = QMessageBox.question(
            self,
            "Remove PrivSentinel block?",
            f"Remove PrivSentinel's Windows Firewall rules for {address}? Other "
            "firewall rules may still block this address.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmed != QMessageBox.StandardButton.Yes:
            return
        try:
            allow_ip(address)
        except (OSError, ValueError, RuntimeError) as exc:
            self.source_status.set_text(f"Could not allow {address}: {exc}")
            self.source_status.set_state("error")
            return
        self.source_status.set_text(
            f"Removed PrivSentinel firewall rules for {address}"
        )
        self.source_status.set_state("success")

    def _events_for(self, source: str) -> list[dict[str, object]]:
        return [
            event
            for event in self.services.security_repository.list_events(limit=10000)
            if str(event["source"]).casefold() == source
        ]

    def _set_collector_status(self, source: str, count: int) -> None:
        worker = self.services.endpoint_service.workers.get(source)
        running = worker is not None and worker.isRunning()
        if source == "network":
            address_count = len(self._network_rows_by_address)
            completed_count = sum(
                address in self._reverse_dns_cache
                for address in self._network_rows_by_address
            )
            dns_status = (
                f" · reverse DNS {completed_count:,}/{address_count:,} "
                f"({len(self._reverse_dns_pending):,} pending)"
                if address_count
                else " · no IP addresses to resolve"
            )
        else:
            dns_status = ""
        self.source_status.set_text(
            f"{'Collecting' if running else 'Monitoring enabled; collector not running'}"
            f" · {count:,} local records{dns_status}"
        )
        self.source_status.set_state("success" if running else "warning")


def _event_attributes(event: dict[str, object]) -> dict[str, object]:
    attributes = event.get("attributes")
    if isinstance(attributes, dict):
        return attributes
    return {}
