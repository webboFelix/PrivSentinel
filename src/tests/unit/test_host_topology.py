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
                "InstanceId": "USB\\VID_1234&PID_5678\\DEVICE",
            },
            {
                "Class": "Ports",
                "FriendlyName": "USB Serial Device (COM4)",
                "InstanceId": "USB\\VID_1234&PID_5678&MI_00\\DEVICE",
            },
            {
                "Class": "USB",
                "FriendlyName": "USB Interface",
                "InstanceId": "USB\\VID_1234&PID_5678&MI_01\\DEVICE",
            },
            {
                "Class": "USB",
                "FriendlyName": "Android USB Device",
                "InstanceId": "USB\\VID_9999&PID_5678\\ANDROID",
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
        ],
        "displays": [
            {
                "InstanceName": "DISPLAY\\ACM123\\MONITOR\\5&1",
                "VideoOutputTechnology": 10,
            }
        ],
    }
    monkeypatch.setattr(host_topology.os, "name", "nt")
    monkeypatch.setattr(
        host_topology.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(inventory)),
    )
    warnings = []

    devices = HostTopologyCollector._attached_devices(warnings)

    assert [(device.kind, device.label) for device in devices] == [
        ("display", "DisplayPort"),
        ("serial", "COM4"),
        ("usb", "Android USB Device"),
    ]
    assert not warnings
