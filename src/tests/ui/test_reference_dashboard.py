from datetime import UTC, datetime, timedelta

from src.endpoint.host_topology import ActiveEndpoint, AttachedDevice, HostTopology
from src.ui.components.dashboard_summary import DashboardScoreCard
from src.ui.components.integrity_activity_chart import FileIntegrityActivityChart
from src.ui.components.threat_landscape import ThreatLandscapeWidget
from src.ui.pages.verification_history import (
    _liveness_result_label,
    _verification_result_label,
)


def test_integrity_chart_aggregates_all_reference_categories(qtbot):
    chart = FileIntegrityActivityChart()
    qtbot.addWidget(chart)
    now = datetime.now(UTC)
    assert chart.range_start_utc(now) == now - timedelta(hours=24)
    rows = tuple(
        {
            "occurred_at": now.isoformat(),
            "event_type": event_type,
        }
        for event_type in (
            "file_added",
            "file_changed",
            "file_missing",
            "file_renamed",
        )
    )

    chart.set_events(rows, now)

    assert chart._has_data
    assert tuple(
        sum(chart.series[name])
        for name in ("Created", "Modified", "Deleted", "Renamed")
    ) == (1, 1, 1, 1)
    assert len(chart.series["Renamed"]) == 24

    chart.period_selector.setCurrentIndex(1)
    chart.set_events(rows, now)
    assert len(chart.series["Created"]) == 7

    chart.set_events((), now)
    assert not chart._has_data


def test_threat_landscape_displays_real_alert_and_emits_guarded_actions(qtbot):
    widget = ThreatLandscapeWidget()
    qtbot.addWidget(widget)
    endpoint = ActiveEndpoint(
        local_address="192.168.1.20",
        local_port=51514,
        remote_address="198.51.100.17",
        remote_port=443,
        protocol="TCP",
        state="ESTABLISHED",
        pid=321,
        process_name="browser.exe",
        username="local-user",
    )
    topology = HostTopology(
        hostname="workstation",
        local_addresses=("192.168.1.20",),
        gateways=("192.168.1.1",),
        endpoints=(endpoint,),
        removable_storage=(),
        warnings=(),
    )
    alert = {
        "title": "Observed suspicious connection",
        "severity": "high",
        "risk_score": 76,
        "source": "network",
        "rationale": "Connection matched a local detection rule.",
        "attributes": {
            "remote_address": endpoint.remote_address,
            "process_name": endpoint.process_name,
            "pid": endpoint.pid,
            "user": endpoint.username,
        },
    }

    widget.set_snapshot(topology, alert, None)

    assert widget.threat_title.text() == "Observed suspicious connection"
    assert "workstation" not in widget.topology_status.text()
    assert "198.51.100.17" not in widget.node_selector.currentText()
    assert widget._node_by_key["computer"].label == "This device"
    assert widget._node_by_key["computer"].address == "192.168.1.20"
    assert set(widget._node_by_key) == {"computer"}
    assert widget.values["Process"].text() == "browser.exe"
    assert widget.values["IP address"].text() == endpoint.remote_address
    assert widget.values["Connection"].text() == "Risk 76/100"
    assert widget.block_button.isEnabled()
    with qtbot.waitSignal(widget.blockIpRequested) as signal:
        widget.block_button.click()
    assert signal.args == [endpoint.remote_address]

    finding = {
        "id": 42,
        "provider": "yara",
        "rule": "TestRule",
        "path": r"C:\Users\local-user\Downloads\sample.bin",
        "sha256": "a" * 64,
    }
    widget.set_snapshot(topology, None, finding)
    assert widget.quarantine_button.isEnabled()
    with qtbot.waitSignal(widget.quarantineRequested) as signal:
        widget.quarantine_button.click()
    assert signal.args == [42]


def test_topology_exposes_host_and_peer_addresses_only_in_selected_details(qtbot):
    widget = ThreatLandscapeWidget()
    qtbot.addWidget(widget)
    local_endpoint = ActiveEndpoint(
        local_address="192.168.1.20",
        local_port=50000,
        remote_address="192.168.1.41",
        remote_port=445,
        protocol="TCP",
        state="ESTABLISHED",
        pid=None,
        process_name="Unavailable",
        username="Unavailable",
    )
    ipv6_endpoint = ActiveEndpoint(
        local_address="fe80::1",
        local_port=50001,
        remote_address="2001:4860:4860::8888",
        remote_port=443,
        protocol="TCP",
        state="ESTABLISHED",
        pid=None,
        process_name="Unavailable",
        username="Unavailable",
    )
    public_endpoint = ActiveEndpoint(
        local_address="192.168.1.20",
        local_port=50002,
        remote_address="8.8.8.8",
        remote_port=443,
        protocol="TCP",
        state="ESTABLISHED",
        pid=None,
        process_name="Unavailable",
        username="Unavailable",
    )
    topology = HostTopology(
        hostname="OffSecShujaa",
        local_addresses=("169.254.10.20", "192.168.1.20", "fe80::abcd"),
        gateways=("fe80::1", "192.168.1.1"),
        endpoints=(local_endpoint, ipv6_endpoint, public_endpoint),
        removable_storage=(),
        warnings=(),
    )

    widget.set_snapshot(topology, None, None)
    widget.show()
    initial_phase = widget.canvas._phase
    qtbot.wait(70)

    assert widget._node_by_key["computer"].address == (
        "169.254.10.20, 192.168.1.20, fe80::abcd"
    )
    assert "fe80::abcd" in widget._node_by_key["computer"].address
    assert widget.topology_status.text() == "This device · 0 connected device(s)"
    assert "fe80" not in widget.topology_status.text()
    assert all(
        widget.node_selector.itemText(index) == "This device"
        for index in range(widget.node_selector.count())
    )
    assert widget.node_selector.count() == 1
    assert widget.values["IP address"].text() == (
        "169.254.10.20, 192.168.1.20, fe80::abcd"
    )
    assert widget.canvas._phase != initial_phase


def test_topology_shows_all_current_peers_and_connected_devices(qtbot):
    widget = ThreatLandscapeWidget()
    qtbot.addWidget(widget)
    peers = tuple(
        ActiveEndpoint(
            local_address="192.168.1.20",
            local_port=51000 + index,
            remote_address=f"192.168.1.{40 + index}",
            remote_port=445,
            protocol="TCP",
            state="ESTABLISHED",
            pid=None,
            process_name="Unavailable",
            username="Unavailable",
        )
        for index in range(4)
    )
    devices = tuple(
        AttachedDevice(
            instance_id=f"USB\\VID_1234&PID_5678\\DEVICE{index}",
            label=f"Connected USB device {index}",
            kind="usb",
            detail="Connected",
        )
        for index in range(5)
    )
    topology = HostTopology(
        hostname="workstation",
        local_addresses=("192.168.1.20",),
        gateways=(),
        endpoints=peers,
        removable_storage=(),
        warnings=(),
        attached_devices=devices,
    )

    widget.set_snapshot(topology, None, None)

    assert "firewall" not in widget._node_by_key
    assert "router:unknown" not in widget._node_by_key
    assert "internet" not in widget._node_by_key
    assert sum(node.kind == "endpoint" for node in widget._nodes) == 0
    assert sum(node.kind == "usb" for node in widget._nodes) == 5
    assert len(widget._nodes) == 6
    assert widget.node_selector.count() == 6
    assert all(
        "DEVICE" not in widget.node_selector.itemText(i)
        for i in range(widget.node_selector.count())
    )
    assert widget.topology_status.text() == "This device · 5 connected device(s)"
    assert widget.quarantine_button.isHidden()
    assert widget.block_button.isHidden()
    assert widget.view_details_button.isHidden()


def test_selected_usb_device_explicitly_reports_no_network_ip(qtbot):
    widget = ThreatLandscapeWidget()
    qtbot.addWidget(widget)
    device = AttachedDevice(
        instance_id="USB\\VID_1782&PID_4EE7\\PHONE",
        label="Nokia C30",
        kind="usb",
        detail="Connected · Error",
    )
    widget.set_snapshot(
        HostTopology(
            hostname="workstation",
            local_addresses=("192.168.1.20",),
            gateways=(),
            endpoints=(),
            removable_storage=(),
            warnings=(),
            attached_devices=(device,),
        ),
        None,
        None,
    )

    widget.node_selector.setCurrentIndex(
        widget.node_selector.findData("device:USB\\VID_1782&PID_4EE7\\PHONE")
    )

    assert widget.threat_title.text() == "Nokia C30"
    assert widget.values["IP address"].text() == "No IP assigned over USB"
    assert widget.values["Connection"].text() == "Connected · Error"
    assert widget.block_button.isHidden()


def test_topology_details_hide_empty_fields_and_unavailable_actions(qtbot):
    widget = ThreatLandscapeWidget()
    qtbot.addWidget(widget)
    topology = HostTopology(
        hostname="workstation",
        local_addresses=(),
        gateways=(),
        endpoints=(),
        removable_storage=(),
        warnings=(),
    )

    widget.set_snapshot(topology, None, None)

    assert widget._field_rows["Process"][0].isHidden()
    assert widget._field_rows["IP address"][0].isHidden()
    assert not widget._field_rows["Source"][0].isHidden()
    assert widget._field_rows["Connection"][0].isHidden()
    assert widget._field_rows["Details"][0].isHidden()
    assert widget.quarantine_button.isHidden()
    assert widget.block_button.isHidden()
    assert widget.view_details_button.isHidden()


def test_security_health_score_uses_level_colors_and_action_messages(qtbot):
    card = DashboardScoreCard()
    qtbot.addWidget(card)

    def set_score(value: int) -> None:
        card.set_factors(
            {
                "Identity": (value, "measured"),
                "Files": (value, "measured"),
                "Processes": (None, "Active", True),
                "Network": (None, "Active", True),
                "Windows": (None, "Active", True),
            }
        )

    set_score(90)
    assert card.ring._score == 90
    assert card.ring._color.name() == "#18d89b"
    assert card.risk_label.text() == "HEALTHY · MAINTAIN PROTECTION"

    set_score(70)
    assert card.ring._score == 70
    assert card.ring._color.name() == "#f5ad32"
    assert card.risk_label.text() == "FAIR · REVIEW WEAK AREAS"

    set_score(40)
    assert card.ring._score == 40
    assert card.ring._color.name() == "#f04b67"
    assert card.risk_label.text() == "AT RISK · TAKE ACTION"


def test_history_describes_pending_motion_without_claiming_liveness_failure():
    assert (
        _verification_result_label("liveness_failure", "awaiting_basic_motion")
        == "Motion not confirmed"
    )
    assert (
        _liveness_result_label("low_confidence", "awaiting_basic_motion")
        == "Motion not confirmed"
    )
    assert (
        _liveness_result_label("recognized", "basic_motion_observed")
        == "Basic motion observed"
    )
