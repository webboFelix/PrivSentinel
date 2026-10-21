from types import SimpleNamespace

import psutil

from src.endpoint.process_monitor import ProcessMonitor


class _FakeProcess:
    def __init__(self, pid: int, name: str, cpu: float, rss: int) -> None:
        self.info = {
            "pid": pid,
            "name": name,
            "exe": f"C:\\Apps\\{name}",
            "create_time": float(pid),
        }
        self._cpu = cpu
        self._rss = rss

    def cpu_percent(self, interval=None):
        assert interval is None
        return self._cpu

    def memory_info(self):
        return SimpleNamespace(rss=self._rss)


def test_snapshot_returns_live_cpu_and_rss_sorted_by_cpu(monkeypatch):
    processes = [
        _FakeProcess(100, "idle.exe", 0.0, 10 * 1024 * 1024),
        _FakeProcess(200, "busy.exe", 27.4, 80 * 1024 * 1024),
        _FakeProcess(300, "other.exe", 3.1, 25 * 1024 * 1024),
    ]
    monkeypatch.setattr(
        "src.endpoint.process_monitor.psutil.process_iter",
        lambda **_kwargs: processes,
    )

    monitor = ProcessMonitor()
    assert all(process.cpu_percent is None for process in monitor.snapshot())
    snapshot = monitor.snapshot(limit=2)

    assert [process.name for process in snapshot] == ["busy.exe", "other.exe"]
    assert snapshot[0].pid == 200
    assert snapshot[0].cpu_percent == 27.4
    assert snapshot[0].memory_bytes == 80 * 1024 * 1024


def test_snapshot_applies_exclusions_and_preserves_unavailable_metrics(monkeypatch):
    processes = [
        _FakeProcess(100, "excluded.exe", 99.0, 50),
        _FakeProcess(200, "visible.exe", 0.0, 20 * 1024 * 1024),
    ]

    def cpu_percent(interval=None):
        raise psutil.AccessDenied(pid=200)

    processes[1].cpu_percent = cpu_percent
    monkeypatch.setattr(
        "src.endpoint.process_monitor.psutil.process_iter",
        lambda **_kwargs: processes,
    )

    snapshot = ProcessMonitor(("excluded.exe",)).snapshot()

    assert len(snapshot) == 1
    assert snapshot[0].name == "visible.exe"
    assert snapshot[0].cpu_percent is None
    assert snapshot[0].memory_bytes == 20 * 1024 * 1024
