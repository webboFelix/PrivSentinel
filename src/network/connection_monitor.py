"""Network connection metadata collector; no packet content is inspected."""

from __future__ import annotations

import psutil

from src.core.event_models import SecurityEvent


class ConnectionMonitor:
    def __init__(self) -> None:
        self._seen: set[tuple[object, ...]] = set()

    def collect(self) -> list[SecurityEvent]:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            raise PermissionError(f"Network connection metadata is unavailable: {exc}") from exc
        current: set[tuple[object, ...]] = set()
        events: list[SecurityEvent] = []
        for connection in connections:
            local = connection.laddr
            remote = connection.raddr
            if not local or not remote:
                continue
            remote_ip, remote_port = remote.ip, remote.port
            key = (
                connection.pid,
                local.ip,
                local.port,
                remote_ip,
                remote_port,
                connection.type,
                connection.status,
            )
            current.add(key)
            if self._seen and key not in self._seen:
                events.append(
                    SecurityEvent(
                        source="network",
                        event_type="network_connection",
                        severity="info",
                        description=f"Network connection observed to {remote_ip}:{remote_port}",
                        attributes={
                            "pid": connection.pid,
                            "local_address": local.ip,
                            "local_port": local.port,
                            "remote_address": remote_ip,
                            "remote_port": remote_port,
                            "protocol": "TCP" if connection.type == 1 else "UDP",
                            "state": connection.status,
                        },
                    )
                )
        self._seen = current
        return events