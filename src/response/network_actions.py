"""Windows Firewall actions limited to explicit PrivSentinel IP rules."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess


def block_ip(address: str) -> None:
    """Block one validated IP in both firewall directions."""
    normalized = _normalize_ip(address)
    added: list[str] = []
    try:
        for direction in ("out", "in"):
            _run_firewall(
                "add",
                "rule",
                f"name={_rule_name(direction, normalized)}",
                f"dir={direction}",
                "action=block",
                f"remoteip={normalized}",
                "enable=yes",
                "profile=any",
            )
            added.append(direction)
    except (OSError, RuntimeError) as exc:
        rollback_errors = []
        for direction in reversed(added):
            try:
                _run_firewall(
                    "delete",
                    "rule",
                    f"name={_rule_name(direction, normalized)}",
                )
            except (OSError, RuntimeError) as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        if rollback_errors:
            raise RuntimeError(
                f"{exc}; rollback also failed: {'; '.join(rollback_errors)}"
            ) from exc
        raise


def allow_ip(address: str) -> None:
    """Remove only PrivSentinel's exact firewall rules for one IP."""
    normalized = _normalize_ip(address)
    for direction in ("out", "in"):
        _run_firewall(
            "delete",
            "rule",
            f"name={_rule_name(direction, normalized)}",
        )


def _normalize_ip(address: str) -> str:
    try:
        return str(ipaddress.ip_address(address.strip()))
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc


def _rule_name(direction: str, address: str) -> str:
    return f"PrivSentinel {direction} block {address}"


def _run_firewall(*arguments: str) -> None:
    executable = shutil.which("netsh")
    if executable is None:
        raise OSError("Windows netsh was not found; no firewall rule was changed.")
    try:
        result = subprocess.run(
            [executable, "advfirewall", "firewall", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OSError(f"Windows Firewall action failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            detail or "Windows Firewall rejected the rule; administrator access may be required."
        )