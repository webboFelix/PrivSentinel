import socket
from types import SimpleNamespace

import psutil

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
