"""Process event and live usage collection with configurable exclusions."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

import psutil

from src.core.event_models import SecurityEvent


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    pid: int
    name: str
    cpu_percent: float | None
    memory_bytes: int | None
    user: str | None = None
    executable: str | None = None
    create_time: float | None = None


class ProcessMonitor:
    def __init__(self, exclusions: tuple[str, ...] = ()) -> None:
        self.exclusions = tuple(item.casefold() for item in exclusions)
        self._seen: set[int] = set()
        self._cpu_baselined: set[tuple[int, float | None]] = set()

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

    def snapshot(self, limit: int | None = 4) -> list[ProcessSnapshot]:
        if limit is not None and limit < 1:
            raise ValueError("Process snapshot limit must be positive.")

        processes: list[ProcessSnapshot] = []
        active_process_ids: set[int] = set()
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
                pid = int(pid)
                active_process_ids.add(pid)
                identity = (pid, info.get("create_time"))

                try:
                    measured_cpu = float(process.cpu_percent(interval=None))
                    if identity not in self._cpu_baselined:
                        self._cpu_baselined.add(identity)
                        cpu_percent = None
                    else:
                        cpu_percent = measured_cpu
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    cpu_percent = None
                try:
                    memory_bytes = int(process.memory_info().rss)
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    memory_bytes = None
                processes.append(
                    ProcessSnapshot(
                        pid=pid,
                        name=str(name),
                        cpu_percent=cpu_percent,
                        memory_bytes=memory_bytes,
                        user=(
                            str(info["username"])
                            if info.get("username")
                            else None
                        ),
                        executable=(
                            str(executable) if executable else None
                        ),
                        create_time=(
                            float(info["create_time"])
                            if info.get("create_time") is not None
                            else None
                        ),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._cpu_baselined = {
            identity
            for identity in self._cpu_baselined
            if identity[0] in active_process_ids
        }
        processes.sort(
            key=lambda process: process.cpu_percent
            if process.cpu_percent is not None
            else -1.0,
            reverse=True,
        )
        return processes if limit is None else processes[:limit]

    def _excluded(self, name: str, executable: str) -> bool:
        return any(
            fnmatch.fnmatch(name.casefold(), pattern)
            or fnmatch.fnmatch(executable.casefold(), pattern)
            for pattern in self.exclusions
        )