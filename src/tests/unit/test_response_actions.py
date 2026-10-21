from types import SimpleNamespace

import pytest

from src.response.network_actions import allow_ip, block_ip
from src.response.process_actions import terminate_process


class _FakeProcess:
    def __init__(self, name="sample.exe", create_time=123.0):
        self._name = name
        self._create_time = create_time
        self.terminated = False
        self.killed = False

    def name(self):
        return self._name

    def create_time(self):
        return self._create_time

    def terminate(self):
        self.terminated = True

    def wait(self, timeout):
        assert timeout > 0
        if self.killed:
            return 0
        return 0

    def kill(self):
        self.killed = True


def test_terminate_process_checks_identity_before_stopping(monkeypatch):
    process = _FakeProcess()
    monkeypatch.setattr(
        "src.response.process_actions.psutil.Process", lambda _pid: process
    )

    terminate_process(1200, expected_create_time=123.0)

    assert process.terminated
    assert not process.killed


def test_terminate_process_refuses_pid_reuse_and_system_pid(monkeypatch):
    monkeypatch.setattr(
        "src.response.process_actions.psutil.Process",
        lambda _pid: _FakeProcess(create_time=456.0),
    )

    with pytest.raises(ValueError, match="changed since"):
        terminate_process(1200, expected_create_time=123.0)
    with pytest.raises(PermissionError, match="Core Windows"):
        terminate_process(4)


def test_block_and_allow_ip_use_exact_privsentinel_rules(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "src.response.network_actions.shutil.which", lambda _name: "netsh.exe"
    )

    def run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("src.response.network_actions.subprocess.run", run)

    block_ip("2001:db8::1")
    allow_ip("2001:db8::1")

    assert len(calls) == 4
    assert "name=PrivSentinel out block 2001:db8::1" in calls[0]
    assert "name=PrivSentinel in block 2001:db8::1" in calls[1]
    assert calls[2][-1] == "name=PrivSentinel out block 2001:db8::1"
    assert calls[3][-1] == "name=PrivSentinel in block 2001:db8::1"


def test_block_ip_rolls_back_first_rule_if_second_rule_fails(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "src.response.network_actions.shutil.which", lambda _name: "netsh.exe"
    )

    def run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(
            returncode=1 if len(calls) == 2 else 0,
            stdout="firewall rejected rule" if len(calls) == 2 else "",
            stderr="",
        )

    monkeypatch.setattr("src.response.network_actions.subprocess.run", run)

    with pytest.raises(RuntimeError, match="firewall rejected rule"):
        block_ip("203.0.113.5")

    assert len(calls) == 3
    assert calls[2][-1] == "name=PrivSentinel out block 203.0.113.5"


def test_block_ip_rejects_invalid_address_before_running_netsh(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "src.response.network_actions.subprocess.run",
        lambda *_args, **_kwargs: calls.append(True),
    )

    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        block_ip("not-an-ip")

    assert calls == []
