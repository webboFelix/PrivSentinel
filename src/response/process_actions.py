"""Explicit, guarded actions for stopping a selected local process."""

from __future__ import annotations

import os

import psutil

_PROTECTED_PROCESS_NAMES = {
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "system",
    "wininit.exe",
    "winlogon.exe",
}


def terminate_process(
    pid: int,
    expected_create_time: float | None = None,
    timeout: float = 3.0,
) -> None:
    """Terminate a process only if the selected PID still identifies that process."""
    if pid <= 4 or pid == os.getpid():
        raise PermissionError("Core Windows processes and PrivSentinel cannot be stopped here.")
    if timeout <= 0:
        raise ValueError("Process termination timeout must be positive.")

    try:
        process = psutil.Process(pid)
        process_name = process.name().casefold()
        if process_name in _PROTECTED_PROCESS_NAMES:
            raise PermissionError(
                f"Stopping protected Windows process {process_name} is not allowed."
            )
        if expected_create_time is not None:
            current_create_time = process.create_time()
            if abs(current_create_time - expected_create_time) > 0.01:
                raise ValueError(
                    "The process changed since the table was refreshed. Refresh and select it again."
                )
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout)
    except psutil.NoSuchProcess as exc:
        raise ProcessLookupError(f"Process {pid} is no longer running.") from exc
    except psutil.AccessDenied as exc:
        raise PermissionError(
            f"Windows denied permission to stop process {pid}; try an authorized account."
        ) from exc