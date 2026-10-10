"""Metadata-only process snapshot collection with configurable exclusions."""

from __future__ import annotations

import fnmatch

import psutil

from src.core.event_models import SecurityEvent


class ProcessMonitor:
    def __init__(self, exclusions: tuple[str, ...] = ()) -> None:
        self.exclusions = tuple(item.casefold() for item in exclusions)
        self._seen: set[int] = set()

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        current: set[int] = set()
        for process in psutil.process_iter(
            attrs=["pid", "name", "username", "exe", "create_time"]
        ):
            try:
                info = process.info
                pid = info.get("pid")
                name = info.get("name") or "unknown"
                executable = info.get("exe") or ""
                if pid is None or self._excluded(name, executable):
                    continue
                current.add(int(pid))
                if self._seen and int(pid) not in self._seen:
                    events.append(
                        SecurityEvent(
                            source="process",
                            event_type="process_started",
                            severity="info",
                            description=f"New process observed: {name}",
                            attributes={
                                "pid": int(pid),
                                "process_name": name,
                                "user": info.get("username"),
                                "executable": executable,
                                "create_time": info.get("create_time"),
                            },
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self._seen = current
        return events

    def _excluded(self, name: str, executable: str) -> bool:
        return any(
            fnmatch.fnmatch(name.casefold(), pattern)
            or fnmatch.fnmatch(executable.casefold(), pattern)
            for pattern in self.exclusions
        )