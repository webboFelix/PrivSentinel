"""Interactive local topology and current threat context for the dashboard."""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping
from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFontMetrics, QIcon, QPainter, QPen
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

from src.endpoint.host_topology import HostTopology, PhysicalPort
from src.ui.icon_assets import icon_path


@dataclass(frozen=True, slots=True)
class _TopologyNode:
    key: str
    label: str
    kind: str
    address: str = ""
    detail: str = ""
    other_addresses: tuple[str, ...] = ()
    port_name: str = ""


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
            "gateway": QIcon(icon_path("router.png")).pixmap(30, 30),
            "usb": QIcon(icon_path("usb_drive.png")).pixmap(26, 26),
            "serial": QIcon(icon_path("network-nodes.png")).pixmap(26, 26),
            "display": QIcon(icon_path("security_appliance.png")).pixmap(26, 26),
            "bluetooth": QIcon(icon_path("network-nodes.png")).pixmap(26, 26),
        }
        self._phase = 0.0
        self._animation = QTimer(self)
        self._animation.setInterval(45)
        self._animation.timeout.connect(self._advance_animation)
        self.setMinimumHeight(180)
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
        center = QPointF(self.width() * 0.5, self.height() * 0.5)
        self._node_positions = self._positions(center)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for index, color in enumerate(("#164a70", "#123c60", "#0d3152")):
            inset = index * 13
            painter.setPen(QPen(QColor(color), 1, Qt.PenStyle.DashLine))
            painter.drawEllipse(
                QRectF(
                    self.width() * 0.5 - self.width() * 0.41 + inset,
                    self.height() * 0.52 - self.height() * 0.31 + inset * 0.45,
                    self.width() * 0.82 - inset * 2,
                    self.height() * 0.62 - inset * 0.9,
                )
            )
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
        slots = {"computer": center}
        orbit_nodes = [node for node in self.nodes if node.kind != "computer"]
        for index, node in enumerate(orbit_nodes):
            angle = -math.pi / 2 + math.tau * index / max(1, len(orbit_nodes))
            slots[node.key] = QPointF(
                self.width() * 0.5 + math.cos(angle) * self.width() * 0.35,
                self.height() * 0.5
                + math.sin(angle) * self.height() * 0.31,
            )
        for key, position in slots.items():
            slots[key] = center + (position - center) * self.zoom
        return slots

    def _edges(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            ("computer", node.key)
            for node in self.nodes
            if node.key != "computer"
        )

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

        size = 32 if node.kind == "computer" else 30 if node.kind == "gateway" else 26
        painter.setPen(QPen(QColor("#77d9ff"), 2 if node.key == self.selected_key else 1))
        painter.setBrush(QColor("#0a2c4c"))
        painter.drawEllipse(position, size / 2 + 5, size / 2 + 5)
        painter.drawPixmap(
            QPointF(position.x() - size / 2, position.y() - size / 2),
            self._node_pixmaps[node.kind],
        )
        label = node.label
        painter.setPen(QColor("#d8ebff"))
        painter.setFont(self.font())
        label_width = min(76, max(52, self.width() // max(5, len(self.nodes))))
        label = QFontMetrics(self.font()).elidedText(
            label,
            Qt.TextElideMode.ElideMiddle,
            label_width,
        )
        label_x = min(
            max(2, position.x() - label_width / 2),
            self.width() - label_width - 2,
        )
        label_y = (
            position.y() + size / 2 + 3
            if position.y() < self.height() * 0.5
            else position.y() - size / 2 - 19
        )
        label_rect = QRectF(label_x, label_y, label_width, 16)
        painter.drawText(
            label_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
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
        self._physical_ports: tuple[PhysicalPort, ...] = ()
        self._topology = HostTopology(
            hostname="",
            local_addresses=(),
            gateways=(),
            endpoints=(),
            removable_storage=(),
            warnings=(),
        )
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
        self.details.setMaximumWidth(230)
        detail_layout = QVBoxLayout(self.details)
        detail_layout.setContentsMargins(10, 8, 10, 8)
        detail_layout.setSpacing(5)
        detail_header = QHBoxLayout()
        detail_title = QLabel("Details")
        detail_title.setObjectName("sectionTitle")
        detail_header.addWidget(detail_title, 1)
        self.severity_badge = QLabel("CONNECTED")
        self.severity_badge.setObjectName("threatSeverity")
        detail_header.addWidget(self.severity_badge)
        detail_layout.addLayout(detail_header)
        self.threat_title = QLabel("No active threat details")
        self.threat_title.setObjectName("threatTitle")
        self.threat_title.setWordWrap(True)
        detail_layout.addWidget(self.threat_title)
        self.node_selector = QComboBox()
        self.node_selector.setToolTip(
            "Select this device or one of its connected physical devices"
        )
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
        self._field_rows: dict[str, tuple[QLabel, QLabel]] = {}
        for row, name in enumerate(
            (
                "Process",
                "Source",
                "IP address",
                "Connection",
                "Other local IPs",
                "Ports",
                "Details",
            )
        ):
            label = QLabel(name)
            label.setObjectName("muted")
            value = QLabel("—")
            value.setWordWrap(True)
            value.setMaximumHeight(38)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            fields.addWidget(label, row, 0)
            fields.addWidget(value, row, 1)
            self.values[name] = value
            self._field_rows[name] = (label, value)
        detail_layout.addLayout(fields)
        self.quarantine_button = QPushButton("Quarantine")
        self.quarantine_button.setIcon(QIcon(icon_path("quarantine-box.png")))
        self.quarantine_button.clicked.connect(self._request_quarantine)
        self.block_button = QPushButton("Block IP")
        self.block_button.setIcon(QIcon(icon_path("laptop_security.png")))
        self.block_button.clicked.connect(self._request_block)
        self.view_details_button = QPushButton("View Details")
        self.view_details_button.setIcon(QIcon(icon_path("file-search.png")))
        self.view_details_button.clicked.connect(self._view_details)
        actions = QHBoxLayout()
        actions.setSpacing(4)
        for button in (
            self.quarantine_button,
            self.block_button,
            self.view_details_button,
        ):
            button.setMinimumWidth(0)
            actions.addWidget(button)
            button.hide()
        detail_layout.addLayout(actions)
        content.addWidget(self.details, 3)
        layout.addLayout(content, 1)
        self.setMinimumHeight(245)

    def set_snapshot(
        self,
        topology: HostTopology,
        active_alert: Mapping[str, object] | None,
        potential_finding: Mapping[str, object] | None,
    ) -> None:
        self._topology = topology
        self._active_alert = active_alert
        self._potential_finding = potential_finding
        self.topology_status.setStyleSheet("")
        self._nodes = _topology_nodes(topology)
        self._node_by_key = {node.key: node for node in self._nodes}
        self._physical_ports = topology.physical_ports or tuple(
            PhysicalPort(device.port_name, device.label, device.detail)
            for device in topology.attached_devices
            if device.port_name
        )
        if self._selected_key not in self._node_by_key:
            self._selected_key = "computer"
        self.canvas.set_topology(
            self._nodes,
            self._selected_key,
        )
        self.node_selector.blockSignals(True)
        self.node_selector.clear()
        for node in self._nodes:
            self.node_selector.addItem(node.label, node.key)
        selected_index = self.node_selector.findData(self._selected_key)
        self.node_selector.setCurrentIndex(max(0, selected_index))
        self.node_selector.blockSignals(False)
        device_count = sum(
            node.kind in {"usb", "serial", "display", "bluetooth"}
            for node in self._nodes
        )
        port_count = len(self._physical_ports)
        primary_address = topology.primary_address or self._node_by_key[
            "computer"
        ].address
        gateway_node = next(
            (node for node in self._nodes if node.kind == "gateway"),
            None,
        )
        gateway = gateway_node.address if gateway_node else "unavailable"
        suffix = "; ".join(topology.warnings)
        summary = (
            f"Host {primary_address or 'IP unavailable'} · Gateway {gateway} · "
            f"{device_count} device(s) / {port_count} port(s)"
        )
        if suffix:
            summary += " · Inventory partial"
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
        alert = (
            self._active_alert
            if node.kind == "computer"
            else None
        )
        attributes = alert.get("attributes", {}) if alert else {}
        attributes = attributes if isinstance(attributes, Mapping) else {}
        finding = self._potential_finding if node.kind == "computer" else None
        if alert is not None:
            title = str(alert.get("title") or "Active alert")
            severity = str(alert.get("severity") or "unknown").upper()
            process = str(
                attributes.get("process_name")
                or attributes.get("process")
                or "—"
            )
            source = str(alert.get("source") or "Alert")
            connection_text = str(
                alert.get("risk_score") and f"Risk {float(alert['risk_score']):.0f}/100"
                or "—"
            )
            ip_address = str(
                attributes.get("remote_address")
                or attributes.get("remote_ip")
                or attributes.get("destination_ip")
                or node.address
                or "—"
            )
            details = str(alert.get("rationale") or node.detail or "—")
            other_local_ips = ""
            ports = node.port_name
            self.severity_badge.setText(severity)
        elif finding is not None:
            title = f"Potential {finding.get('provider', 'malware')} match"
            severity = "REVIEW"
            process = "—"
            source = f"{finding.get('provider', 'Scanner')}: {finding.get('rule', 'match')}"
            connection_text = node.detail or "Not scored"
            ip_address = node.address or "—"
            details = (
                f"{finding.get('path', 'Unknown file')} · SHA-256 "
                f"{finding.get('sha256', 'unavailable')} · review required; "
                "a rule match is not a confirmed malware verdict"
            )
            other_local_ips = ""
            ports = node.port_name
            self.severity_badge.setText(severity)
        else:
            title = node.label
            severity = "NO VERDICT"
            process = "—"
            source = node.kind.replace("-", " ").title()
            connection_text = (
                node.detail
                if node.detail and (node.kind != "computer" or node.address)
                else "—"
            )
            if node.address:
                ip_address = node.address
            elif node.kind == "usb":
                ip_address = "No IP assigned over USB"
            elif node.kind in {"serial", "display"}:
                ip_address = "No network IP assigned"
            elif node.kind == "bluetooth":
                ip_address = "No IP address assigned over Bluetooth"
            else:
                ip_address = "—"
            details = node.detail if node.kind != "computer" else "—"
            other_local_ips = "; ".join(node.other_addresses) or "—"
            ports = (
                "; ".join(
                    f"{port.name}: {port.device} ({port.status})"
                    for port in self._physical_ports
                )
                if node.kind == "computer" and self._physical_ports
                else node.port_name
            )
            self.severity_badge.setText("NO ALERT")
        self.threat_title.setText(title)
        self.details.setToolTip(title)
        self.values["Process"].setText(process)
        self.values["Source"].setText(source)
        self.values["IP address"].setText(ip_address)
        self.values["Connection"].setText(connection_text)
        self.values["Other local IPs"].setText(other_local_ips or "—")
        self.values["Ports"].setText(ports or "—")
        self.values["Details"].setText(details[:180])
        visible_values = {
            "Process": process,
            "Source": source,
            "IP address": ip_address,
            "Connection": connection_text,
            "Other local IPs": other_local_ips,
            "Ports": ports,
            "Details": details if details != connection_text else "",
        }
        for name, (label_widget, value_widget) in self._field_rows.items():
            visible = visible_values[name] not in {
                "",
                "—",
                "Not measured",
                "Not evaluated",
            }
            label_widget.setVisible(visible)
            value_widget.setVisible(visible)
        can_quarantine = finding is not None and str(finding.get("id", "")).isdigit()
        self.quarantine_button.setVisible(can_quarantine)
        self.quarantine_button.setEnabled(can_quarantine)
        is_remote_endpoint = node.kind == "endpoint" or (
            alert is not None
            and any(
                attributes.get(key)
                for key in ("remote_address", "remote_ip", "destination_ip")
            )
        )
        selected_ip = (
            ip_address
            if is_remote_endpoint and ip_address != "—" and _is_ip_address(ip_address)
            else ""
        )
        self._block_address = selected_ip if _is_blockable_address(selected_ip) else ""
        self.block_button.setVisible(bool(self._block_address))
        self.block_button.setEnabled(bool(self._block_address))
        can_view_details = (
            alert is not None
            or finding is not None
            or node.kind in {"endpoint", "usb", "serial", "display"}
        )
        self.view_details_button.setVisible(can_view_details)
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
        elif self._potential_finding is not None or (
            self._selected_key in self._node_by_key
            and self._node_by_key[self._selected_key].kind == "usb"
        ):
            self.pageRequested.emit("malware-protection")
        else:
            self.pageRequested.emit("network-monitor")


def _topology_nodes(topology: HostTopology) -> tuple[_TopologyNode, ...]:
    usable_addresses = tuple(
        address
        for address in topology.local_addresses
        if not ipaddress.ip_address(address).is_link_local
    )
    primary_address = topology.primary_address or (
        usable_addresses[0]
        if usable_addresses
        else topology.local_addresses[0]
        if topology.local_addresses
        else ""
    )
    other_addresses = tuple(
        f"{interface.name}: {address}"
        for interface in topology.network_interfaces
        for address in interface.addresses
        if address != primary_address
        and not ipaddress.ip_address(address).is_link_local
    )
    if not topology.network_interfaces:
        other_addresses = tuple(
            address
            for address in topology.local_addresses
            if address != primary_address
            and not ipaddress.ip_address(address).is_link_local
        )
    usable_gateways = []
    for address in topology.gateways:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_link_local and not parsed.is_unspecified:
            usable_gateways.append(address)
    gateway = next(
        (address for address in usable_gateways if ipaddress.ip_address(address).version == 4),
        usable_gateways[0] if usable_gateways else "",
    )
    host_detail = (
        f"{topology.primary_interface} · default route via {gateway}"
        if topology.primary_interface and gateway
        else f"Default gateway {gateway}"
        if gateway
        else topology.primary_interface or "Local interface"
    )
    nodes = [
        _TopologyNode(
            "computer",
            "This device",
            "computer",
            address=primary_address,
            detail=host_detail,
            other_addresses=other_addresses,
        ),
    ]
    if gateway:
        nodes.append(
            _TopologyNode(
                f"gateway:{gateway}",
                "Gateway",
                "gateway",
                address=gateway,
                detail="Active default gateway",
            )
        )
    nodes.extend(
        _TopologyNode(
            f"device:{device.instance_id}",
            _device_display_label(device.label, device.kind),
            device.kind,
            detail=device.detail,
            port_name=device.port_name,
        )
        for device in topology.attached_devices
    )
    if topology.removable_storage and not any(
        device.kind == "usb" for device in topology.attached_devices
    ):
        volume = topology.removable_storage[0]
        nodes.append(
            _TopologyNode(
                "device:removable-storage",
                "USB storage",
                "usb",
                detail=f"Connected at {volume.mount_point}",
            )
        )
    return tuple(nodes)


def _device_display_label(label: str, kind: str) -> str:
    normalized = label.casefold()
    if kind == "display":
        if "displayport" in normalized:
            return "DisplayPort"
        if "vga" in normalized:
            return "VGA"
        if "hdmi" in normalized:
            return "HDMI"
        return "Display"
    if kind == "serial":
        return label
    if kind == "bluetooth":
        return label
    if "mouse" in normalized or "pointing" in normalized:
        return label
    if any(phone in normalized for phone in ("android", "nokia", "phone", "mtp")):
        return label
    if "storage" in normalized or "drive" in normalized:
        return "USB storage"
    return "USB device"


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_blockable_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not address.is_loopback and not address.is_unspecified
