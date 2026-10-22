import json
import socket
from types import SimpleNamespace

import psutil

from src.endpoint import host_topology
from src.endpoint.host_topology import HostTopologyCollector


def test_active_endpoint_includes_process_and_user_metadata(monkeypatch):
    def address(ip: str, port: int) -> SimpleNamespace:
        return SimpleNamespace(ip=ip, port=port)

    connection = SimpleNamespace(
        laddr=address("192.168.1.20", 51514),
        raddr=address("198.51.100.17", 443),
        pid=321,
        type=socket.SOCK_STREAM,
        status="ESTABLISHED",
    )
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(
        psutil,
        "Process",
        lambda pid: SimpleNamespace(name=lambda: "browser.exe", username=lambda: "user"),
    )

    endpoints = HostTopologyCollector._active_endpoints([])

    assert len(endpoints) == 1
    assert endpoints[0].remote_address == "198.51.100.17"
    assert endpoints[0].process_name == "browser.exe"
    assert endpoints[0].username == "user"


def test_attached_device_inventory_classifies_usb_serial_and_display(monkeypatch):
    inventory = {
        "devices": [
            {
                "Class": "USB",
                "FriendlyName": "USB Composite Device",
                "InstanceId": "USB\\VID_1EA7&PID_0907\\MOUSE",
                "Status": "OK",
                "ContainerId": "{mouse-container}",
                "RemovalPolicy": 3,
                "BusDescription": "2.4G Mouse",
                "BusDescriptionQueried": True,
            },
            {
                "Class": "Ports",
                "FriendlyName": "USB Serial Device (COM4)",
                "InstanceId": "USB\\VID_1EA7&PID_0907&MI_00\\MOUSE",
                "Parent": "USB\\VID_1EA7&PID_0907\\MOUSE",
                "RemovalPolicy": 3,
            },
            {
                "Class": "USB",
                "FriendlyName": "USB Interface",
                "InstanceId": "USB\\VID_1EA7&PID_0907&MI_01\\MOUSE",
                "Status": "OK",
                "ContainerId": "{mouse-container}",
                "RemovalPolicy": 3,
            },
            {
                "Class": "WPD",
                "FriendlyName": "MTP USB Device",
                "InstanceId": "USB\\VID_1782&PID_4EE7\\PHONE",
                "Status": "Error",
                "ContainerId": "{phone-container}",
                "RemovalPolicy": 3,
                "BusDescription": "Nokia C30",
            },
            {
                "Class": "USB",
                "FriendlyName": "Integrated USB Webcam",
                "InstanceId": "USB\\VID_1234&PID_5678\\INTERNAL",
                "Status": "OK",
                "ContainerId": "{internal-container}",
                "RemovalPolicy": 1,
            },
            {
                "Class": "Ports",
                "FriendlyName": "Internal modem (COM6)",
                "InstanceId": "USB\\VID_4321&PID_9876\\MODEM",
                "Parent": "USB\\VID_4321&PID_9876\\MODEM",
                "RemovalPolicy": 1,
            },
            {
                "Class": "Monitor",
                "FriendlyName": "Generic Monitor",
                "InstanceId": "DISPLAY\\ACM123\\MONITOR",
            },
            {
                "Class": "Monitor",
                "FriendlyName": "Disconnected Monitor",
                "InstanceId": "DISPLAY\\OTHER\\MONITOR",
            },
            {
                "Class": "Monitor",
                "FriendlyName": "Integrated Monitor",
                "InstanceId": "DISPLAY\\INTERNAL\\MONITOR",
            },
        ],
        "displays": [
            {
                "InstanceName": "DISPLAY\\ACM123\\MONITOR\\5&1",
                "VideoOutputTechnology": 10,
            },
            {
                "InstanceName": "DISPLAY\\INTERNAL\\MONITOR\\5&2",
                "VideoOutputTechnology": 10,
            },
        ],
    }
    monkeypatch.setattr(host_topology.os, "name", "nt")
    monkeypatch.setattr(
        host_topology.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(inventory)),
    )
    warnings = []
    property_cache = {}

    devices = HostTopologyCollector._attached_devices(
        warnings,
        property_cache,
    )

    assert [(device.kind, device.label) for device in devices] == [
        ("display", "DisplayPort"),
        ("usb", "2.4G Mouse"),
        ("usb", "Nokia C30"),
    ]
    assert "serial COM4" in devices[1].detail
    assert "Connected · Error" in devices[2].detail
    assert (
        property_cache["USB\\VID_1EA7&PID_0907\\MOUSE"]["BusDescription"]
        == "2.4G Mouse"
    )
    assert not warnings


def test_default_gateway_uses_only_the_active_route(monkeypatch):
    monkeypatch.setattr(host_topology.os, "name", "nt")
    monkeypatch.setattr(
        HostTopologyCollector,
        "_local_addresses",
        staticmethod(lambda _warnings: ("192.168.4.105",)),
    )
    commands = []

    def run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(
            stdout=(
                "Active Routes:\n"
                "Network Destination Netmask Gateway Interface Metric\n"
                "0.0.0.0 0.0.0.0 192.168.4.1 192.168.4.105 25\n"
                "0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.20 5\n"
                "Persistent Routes:\n"
                "0.0.0.0 0.0.0.0 10.0.0.1 10.0.0.5 1\n"
            )
        )

    monkeypatch.setattr(host_topology.subprocess, "run", run)
    warnings = []

    gateways = HostTopologyCollector._default_gateways(warnings)
    assert gateways == ("192.168.4.1",)
    assert gateways == ("192.168.4.1",)
    assert commands[0] == ["route.exe", "print", "-4"]
    assert not warnings


def test_local_addresses_include_only_up_non_link_local_interfaces(monkeypatch):
    monkeypatch.setattr(
        psutil,
        "net_if_addrs",
        lambda: {
            "up": [
                SimpleNamespace(family=socket.AF_INET, address="192.168.4.105"),
                SimpleNamespace(family=socket.AF_INET, address="169.254.1.10"),
                SimpleNamespace(family=socket.AF_INET6, address="fe80::1"),
            ],
            "down": [
                SimpleNamespace(family=socket.AF_INET, address="10.0.0.5"),
            ],
        },
    )
    monkeypatch.setattr(
        psutil,
        "net_if_stats",
        lambda: {
            "up": SimpleNamespace(isup=True),
            "down": SimpleNamespace(isup=False),
        },
    )
    warnings = []

    addresses = HostTopologyCollector._local_addresses(warnings)

    assert addresses == ("192.168.4.105",)
    assert not warnings
