"""Interactive local topology and current threat context for the dashboard."""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping
from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from src.endpoint.host_topology import ActiveEndpoint, HostTopology
from src.ui.icon_assets import icon_path


@dataclass(frozen=True, slots=True)
class _TopologyNode:
    key: str
    label: str
    kind: str
    address: str = ""
    detail: str = ""
    connection: ActiveEndpoint | None = None


class _TopologyCanvas(QWidget):
    nodeSelected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.nodes: tuple[_TopologyNode, ...] = ()
        self.selected_key = "computer"
        self.interactive = True
        self.zoom = 1.0
        self._node_positions: dict[str, QPointF] = {}
        self._node_pixmaps = {
            "computer": QIcon(icon_path("security_appliance.png")).pixmap(32, 32),
            "internet": QIcon(icon_path("network_globe.png")).pixmap(32, 32),
            "firewall": QIcon(icon_path("laptop_security.png")).pixmap(26, 26),
            "router": QIcon(icon_path("router.png")).pixmap(32, 32),
            "endpoint": QIcon(icon_path("security_appliance.png")).pixmap(26, 26),
            "usb": QIcon(icon_path("usb_drive.png")).pixmap(26, 26),
        }
        self._phase = 0.0
        self._animation = QTimer(self)
        self._animation.setInterval(45)
        self._animation.timeout.connect(self._advance_animation)
        self.setMinimumHeight(260)
        self.setMouseTracking(True)

    def set_topology(
        self,
        nodes: tuple[_TopologyNode, ...],
        selected_key: str,
    ) -> None:
        self.nodes = nodes
        self.selected_key = selected_key
        self.update()

    def paintEvent(self, event) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#071a31"))
        center = QPointF(self.width() * 0.5, self.height() * 0.28)
        self._node_positions = self._positions(center)
        edges = self._edges()
        for edge_index, (source, target) in enumerate(edges):
            start = self._node_positions[source]
            end = self._node_positions[target]
            painter.setPen(QPen(QColor("#15537b"), 2))
            painter.drawLine(start, end)
            for packet_index in range(2):
                progress = (self._phase + packet_index * 0.5 + edge_index * 0.17) % 1.0
                packet = QPointF(
                    start.x() + (end.x() - start.x()) * progress,
                    start.y() + (end.y() - start.y()) * progress,
                )
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor("#00c7f2") if packet_index == 0 else QColor("#18d89b"))
                painter.drawEllipse(packet, 3.2, 3.2)
        for node in self.nodes:
            position = self._node_positions.get(node.key)
            if position is not None:
                self._draw_node(painter, node, position)

    def _positions(self, center: QPointF) -> dict[str, QPointF]:
        slots = {
            "computer": center,
            "internet": QPointF(self.width() * 0.84, center.y()),
            "firewall": QPointF(self.width() * 0.39, self.height() * 0.55),
            "usb": QPointF(self.width() * 0.61, self.height() * 0.55),
        }
        for node in self.nodes:
            if node.kind == "router":
                slots[node.key] = QPointF(self.width() * 0.16, center.y())
        peers = [node for node in self.nodes if node.kind == "endpoint"]
        for index, node in enumerate(peers):
            fraction = (index + 1) / (len(peers) + 1)
            base = QPointF(
                self.width() * (0.12 + fraction * 0.76),
                self.height() * 0.76,
            )
            base += QPointF(
                math.sin(self._phase * math.tau + index) * 4.0,
                math.cos(self._phase * math.tau + index) * 4.0,
            )
            slots[node.key] = base
        for node in self.nodes:
            if node.key not in slots:
                continue
            position = slots[node.key]
            if node.kind == "router":
                position += QPointF(0, math.sin(self._phase * math.tau) * 1.2)
            if node.kind == "internet":
                position += QPointF(0, math.cos(self._phase * math.tau) * 1.2)
            slots[node.key] = center + (position - center) * self.zoom
        return slots

    def _edges(self) -> tuple[tuple[str, str], ...]:
        available = set(self._node_positions)
        edges: list[tuple[str, str]] = []
        router = next(
            (node.key for node in self.nodes if node.kind == "router"),
            None,
        )
        if router and "computer" in available:
            edges.append((router, "computer"))
        if "computer" in available and "internet" in available:
            edges.append(("computer", "internet"))
        for node in self.nodes:
            if node.kind in {"firewall", "usb"} and node.key in available:
                edges.append(("computer", node.key))
            elif node.kind == "endpoint" and node.key in available:
                edges.append((router or "computer", node.key))
        return tuple(edges)

    def _advance_animation(self) -> None:
        self._phase = (self._phase + 0.012) % 1.0
        self.update()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._animation.start()

    def hideEvent(self, event) -> None:
        self._animation.stop()
        super().hideEvent(event)

    def _draw_node(
        self,
        painter: QPainter,
        node: _TopologyNode,
        position: QPointF,
    ) -> None:

        size = 32 if node.kind in {"computer", "router", "internet"} else 26
        painter.setPen(QPen(QColor("#77d9ff"), 2 if node.key == self.selected_key else 1))
        painter.setBrush(QColor("#0a2c4c"))
        painter.drawEllipse(position, size / 2 + 5, size / 2 + 5)
        painter.drawPixmap(
            QPointF(position.x() - size / 2, position.y() - size / 2),
            self._node_pixmaps[node.kind],
        )
        label = node.label if not node.address else f"{node.label}\n{node.address}"
        painter.setPen(QColor("#d8ebff"))
        painter.setFont(self.font())
        label_rect = QRectF(position.x() - 66, position.y() + size / 2 + 5, 132, 36)
        painter.drawText(
            label_rect,
            Qt.AlignmentFlag.AlignHCenter
            | Qt.AlignmentFlag.AlignTop
            | Qt.TextFlag.TextWordWrap,
            label,
        )

    def mousePressEvent(self, event) -> None:
        if not self.interactive or event.button() != Qt.MouseButton.LeftButton:
            super().mousePressEvent(event)
            return
        nearest = min(
            self._node_positions.items(),
            key=lambda item: math.hypot(
                item[1].x() - event.position().x(),
                item[1].y() - event.position().y(),
            ),
            default=None,
        )
        if nearest is not None and math.hypot(
            nearest[1].x() - event.position().x(),
            nearest[1].y() - event.position().y(),
        ) <= 24:
            self.nodeSelected.emit(nearest[0])

    def zoom_by(self, factor: float) -> None:
        self.zoom = min(1.4, max(0.75, self.zoom * factor))
        self.update()


class ThreatLandscapeWidget(QFrame):
    refreshRequested = Signal()
    blockIpRequested = Signal(str)
    quarantineRequested = Signal(int)
    pageRequested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self._nodes: tuple[_TopologyNode, ...] = ()
        self._node_by_key: dict[str, _TopologyNode] = {}
        self._active_alert: Mapping[str, object] | None = None
        self._potential_finding: Mapping[str, object] | None = None
        self._selected_key = "computer"
        self._block_address = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 10, 13, 8)
        layout.setSpacing(6)
        header = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QIcon(icon_path("network_topology.png")).pixmap(18, 18))
        header.addWidget(icon)
        title = QLabel("3D Threat Landscape")
        title.setObjectName("sectionTitle")
        header.addWidget(title, 1)
        self.interactive_button = QPushButton("Interactive View")
        self.interactive_button.setCheckable(True)
        self.interactive_button.setChecked(True)
        self.interactive_button.toggled.connect(self._set_interactive)
        header.addWidget(self.interactive_button)
        self.refresh_button = QToolButton()
        self.refresh_button.setIcon(QIcon(icon_path("refresh.png")))
        self.refresh_button.setToolTip("Refresh connected host devices")
        self.refresh_button.clicked.connect(self.refreshRequested)
        header.addWidget(self.refresh_button)
        layout.addLayout(header)

        content = QHBoxLayout()
        content.setSpacing(8)
        topology_column = QVBoxLayout()
        zoom_controls = QHBoxLayout()
        zoom_controls.addStretch(1)
        zoom_in = QToolButton()
        zoom_in.setText("+")
        zoom_in.setToolTip("Zoom in")
        zoom_in.clicked.connect(lambda: self.canvas.zoom_by(1.12))
        zoom_out = QToolButton()
        zoom_out.setText("-")
        zoom_out.setToolTip("Zoom out")
        zoom_out.clicked.connect(lambda: self.canvas.zoom_by(0.89))
        zoom_controls.addWidget(zoom_in)
        zoom_controls.addWidget(zoom_out)
        topology_column.addLayout(zoom_controls)
        self.canvas = _TopologyCanvas()
        self.canvas.nodeSelected.connect(self._select_node)
        topology_column.addWidget(self.canvas, 1)
        self.topology_status = QLabel("Collecting local host topology…")
        self.topology_status.setObjectName("muted")
        self.topology_status.setWordWrap(True)
        self.topology_status.setSizePolicy(
            QSizePolicy.Policy.Ignored,
            QSizePolicy.Policy.Preferred,
        )
        topology_column.addWidget(self.topology_status)
        content.addLayout(topology_column, 7)

        self.details = QFrame()
        self.details.setObjectName("threatDetails")
        self.details.setMinimumWidth(190)
        self.details.setMaximumWidth(270)
        detail_layout = QVBoxLayout(self.details)
        detail_layout.setContentsMargins(10, 8, 10, 8)
        detail_layout.setSpacing(5)
        detail_header = QHBoxLayout()
        detail_title = QLabel("Details")
        detail_title.setObjectName("sectionTitle")
        detail_header.addWidget(detail_title, 1)
        self.severity_badge = QLabel("NO ACTIVE ALERT")
        self.severity_badge.setObjectName("threatSeverity")
        detail_header.addWidget(self.severity_badge)
        detail_layout.addLayout(detail_header)
        self.threat_title = QLabel("No active threat details")
        self.threat_title.setObjectName("threatTitle")
        self.threat_title.setWordWrap(True)
        detail_layout.addWidget(self.threat_title)
        self.node_selector = QComboBox()
        self.node_selector.setToolTip("Select a connected host, endpoint, or device")
        # Prevent long IPv6 endpoints from forcing a wider dashboard.
        self.node_selector.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.node_selector.setMinimumContentsLength(18)
        self.node_selector.currentIndexChanged.connect(self._selection_changed)
        detail_layout.addWidget(self.node_selector)
        fields = QGridLayout()
        fields.setHorizontalSpacing(7)
        fields.setVerticalSpacing(4)
        self.values: dict[str, QLabel] = {}
        for row, name in enumerate(
            ("Process", "PID", "User", "Source", "Remote IP", "Risk Score", "Details")
        ):
            label = QLabel(name)
            label.setObjectName("muted")
            value = QLabel("—")
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            fields.addWidget(label, row, 0)
            fields.addWidget(value, row, 1)
            self.values[name] = value
        detail_layout.addLayout(fields)
        self.quarantine_button = QPushButton("Quarantine")
        self.quarantine_button.setIcon(QIcon(icon_path("quarantine-box.png")))
        self.quarantine_button.setEnabled(False)
        self.quarantine_button.clicked.connect(self._request_quarantine)
        self.block_button = QPushButton("Block IP")
        self.block_button.setIcon(QIcon(icon_path("laptop_security.png")))
        self.block_button.setEnabled(False)
        self.block_button.clicked.connect(self._request_block)
        self.view_details_button = QPushButton("View Details")
        self.view_details_button.setIcon(QIcon(icon_path("file-search.png")))
        self.view_details_button.clicked.connect(self._view_details)
        detail_layout.addWidget(self.quarantine_button)
        detail_layout.addWidget(self.block_button)
        detail_layout.addWidget(self.view_details_button)
        content.addWidget(self.details, 3)
        layout.addLayout(content, 1)
        self.setMinimumHeight(290)

    def set_snapshot(
        self,
        topology: HostTopology,
        active_alert: Mapping[str, object] | None,
        potential_finding: Mapping[str, object] | None,
    ) -> None:
        self._active_alert = active_alert
        self._potential_finding = potential_finding
        self.topology_status.setStyleSheet("")
        self._nodes = _topology_nodes(topology)
        self._node_by_key = {node.key: node for node in self._nodes}
        if self._selected_key not in self._node_by_key:
            self._selected_key = "computer"
        self.canvas.set_topology(
            self._nodes,
            self._selected_key,
        )
        self.node_selector.blockSignals(True)
        self.node_selector.clear()
        for node in self._nodes:
            label = node.label
            if node.address:
                label = f"{label} · {node.address}"
            self.node_selector.addItem(label, node.key)
        selected_index = self.node_selector.findData(self._selected_key)
        self.node_selector.setCurrentIndex(max(0, selected_index))
        self.node_selector.blockSignals(False)
        local_peer_count = len(
            {
                endpoint.remote_address
                for endpoint in topology.endpoints
                if _is_lan_ipv4(endpoint.remote_address)
            }
        )
        gateway_text = (
            f"{len(topology.gateways)} gateway(s)"
            if topology.gateways
            else "gateway unavailable"
        )
        usb_count = len(topology.removable_storage)
        suffix = "; ".join(topology.warnings)
        summary = (
            f"This device · {gateway_text} · "
            f"{local_peer_count:,} observed local peer(s) · "
            f"{usb_count:,} removable device(s)"
        )
        if suffix:
            summary += f" · Partial inventory: {suffix}"
        self.topology_status.setText(summary)
        self._render_details()

    def set_status(self, message: str, error: bool = False) -> None:
        self.topology_status.setText(message)
        self.topology_status.setStyleSheet(
            "color: #f04b67;" if error else "color: #8ea9c8;"
        )

    def _set_interactive(self, enabled: bool) -> None:
        self.canvas.interactive = enabled
        self.node_selector.setEnabled(enabled)

    def _select_node(self, key: str) -> None:
        index = self.node_selector.findData(key)
        if index >= 0:
            self.node_selector.setCurrentIndex(index)

    def _selection_changed(self, index: int) -> None:
        key = self.node_selector.itemData(index)
        if not isinstance(key, str):
            return
        self._selected_key = key
        self.canvas.selected_key = key
        self.canvas.update()
        self._render_details()

    def _render_details(self) -> None:
        node = self._node_by_key.get(self._selected_key)
        if node is None:
            return
        alert = self._active_alert
        attributes = alert.get("attributes", {}) if alert else {}
        attributes = attributes if isinstance(attributes, Mapping) else {}
        finding = self._potential_finding
        if alert is not None:
            title = str(alert.get("title") or "Active alert")
            severity = str(alert.get("severity") or "unknown").upper()
            process = str(
                attributes.get("process_name")
                or attributes.get("process")
                or (node.connection.process_name if node.connection else "—")
            )
            pid = str(attributes.get("pid") or (node.connection.pid if node.connection else "—"))
            user = str(attributes.get("user") or attributes.get("username") or (
                node.connection.username if node.connection else "—"
            ))
            source = str(alert.get("source") or "Alert")
            risk = alert.get("risk_score")
            risk_text = f"{float(risk):.0f}/100" if risk is not None else "Not measured"
            remote_ip = str(
                attributes.get("remote_address")
                or attributes.get("remote_ip")
                or attributes.get("destination_ip")
                or (node.address if node.kind == "endpoint" else "—")
            )
            if remote_ip != "—" and not _is_ipv4(remote_ip):
                remote_ip = "—"
            details = str(alert.get("rationale") or node.detail or "—")
            self.severity_badge.setText(severity)
        elif finding is not None:
            title = f"Potential {finding.get('provider', 'malware')} match"
            severity = "REVIEW"
            process = node.connection.process_name if node.connection else "—"
            pid = user = "—"
            source = f"{finding.get('provider', 'Scanner')}: {finding.get('rule', 'match')}"
            risk_text = "Not scored"
            remote_ip = (
                node.address
                if node.kind == "endpoint" and _is_ipv4(node.address)
                else "—"
            )
            details = (
                f"{finding.get('path', 'Unknown file')} · SHA-256 "
                f"{finding.get('sha256', 'unavailable')} · review required; "
                "a rule match is not a confirmed malware verdict"
            )
            self.severity_badge.setText(severity)
        else:
            title = node.label
            severity = "NO VERDICT"
            process = node.connection.process_name if node.connection else "—"
            pid = str(node.connection.pid) if node.connection and node.connection.pid else "—"
            user = node.connection.username if node.connection else "—"
            source = node.kind.replace("-", " ").title()
            risk_text = "Not evaluated"
            remote_ip = (
                node.address
                if node.kind in {"endpoint", "router", "internet"}
                else "—"
            )
            if remote_ip != "—" and not _is_ipv4(remote_ip):
                remote_ip = "—"
            details = node.detail or "—"
            self.severity_badge.setText("NO ALERT")
        self.threat_title.setText(title)
        self.details.setToolTip(title)
        self.values["Process"].setText(process)
        self.values["PID"].setText(pid)
        self.values["User"].setText(user)
        self.values["Source"].setText(source)
        self.values["Remote IP"].setText(remote_ip)
        self.values["Risk Score"].setText(risk_text)
        self.values["Details"].setText(details)
        self.quarantine_button.setEnabled(
            finding is not None and str(finding.get("id", "")).isdigit()
        )
        selected_ip = (
            remote_ip
            if remote_ip != "—"
            else node.address
            if node.kind == "endpoint"
            else ""
        )
        self._block_address = selected_ip if _is_blockable_address(selected_ip) else ""
        self.block_button.setEnabled(bool(self._block_address))
        self.view_details_button.setToolTip(title)

    def _request_quarantine(self) -> None:
        if self._potential_finding is None:
            return
        try:
            finding_id = int(self._potential_finding["id"])
        except (KeyError, TypeError, ValueError):
            return
        self.quarantineRequested.emit(finding_id)

    def _request_block(self) -> None:
        if self._block_address:
            self.blockIpRequested.emit(self._block_address)

    def _view_details(self) -> None:
        if self._active_alert is not None:
            self.pageRequested.emit("alerts")
        elif (
            self._potential_finding is not None
            or self._selected_key == "usb"
        ):
            self.pageRequested.emit("malware-protection")
        else:
            self.pageRequested.emit("network-monitor")


def _topology_nodes(topology: HostTopology) -> tuple[_TopologyNode, ...]:
    local_address = _primary_ipv4(topology.local_addresses)
    nodes = [
        _TopologyNode(
            "computer",
            "This device",
            "computer",
            address=local_address or "IP unavailable",
            detail="This device",
        ),
        _TopologyNode(
            "firewall",
            "Firewall",
            "firewall",
            detail="Windows Firewall configuration is not queried by this inventory.",
        ),
    ]
    nodes.append(
        _TopologyNode(
            f"router:{topology.gateways[0] if topology.gateways else 'unknown'}",
            "Router / gateway",
            "router",
            address=next(
                (address for address in topology.gateways if _is_ipv4(address)),
                "IPv4 unavailable",
            ),
            detail=(
                "Default gateway reported by Windows"
                if topology.gateways
                else "Default gateway was not available from the local system"
            ),
        )
    )
    unique_endpoints: dict[str, ActiveEndpoint] = {}
    for endpoint in topology.endpoints:
        if not _is_ipv4(endpoint.remote_address):
            continue
        unique_endpoints.setdefault(endpoint.remote_address, endpoint)
    public_addresses = sorted(
        address
        for address in unique_endpoints
        if ipaddress.ip_address(address).is_global
    )
    local_peers = sorted(
        address
        for address in unique_endpoints
        if _is_lan_ipv4(address)
    )
    nodes.append(
        _TopologyNode(
            "internet",
            "Internet",
            "internet",
            detail=(
                f"{len(public_addresses):,} active public peer IP(s) observed"
                if public_addresses
                else "No active public peer connections observed"
            ),
        )
    )
    nodes.extend(
        _TopologyNode(
            f"endpoint:{address}",
            "Connected device",
            "endpoint",
            address=address,
            detail="Private IP observed in a current local connection",
            connection=unique_endpoints[address],
        )
        for address in local_peers[:3]
    )
    if len(local_peers) > 3:
        nodes.append(
            _TopologyNode(
                "endpoint-overflow",
                "More devices",
                "endpoint",
                detail=f"{len(local_peers) - 3:,} additional local peer(s)",
            )
        )
    if topology.removable_storage:
        volume = topology.removable_storage[0]
        nodes.append(
            _TopologyNode(
                "usb",
                "USB storage",
                "usb",
                detail=(
                    f"{len(topology.removable_storage):,} mounted removable volume(s); "
                    f"example mount: {volume.mount_point} · no network IP"
                ),
            )
        )
    return tuple(nodes)


def _is_blockable_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not address.is_loopback and not address.is_unspecified


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def _is_lan_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    return address.version == 4 and any(address in network for network in networks)


def _primary_ipv4(addresses: tuple[str, ...]) -> str:
    networks = (
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
    )
    for network in networks:
        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version == 4 and address in network:
                return str(address)
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4 and not address.is_loopback and not address.is_unspecified:
            return str(address)
    return "IPv4 unavailable"
