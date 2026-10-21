"""Optional metadata-only Windows Event Log collector."""

from __future__ import annotations

import os

from src.core.event_models import SecurityEvent


class WindowsEventLogCollector:
    def __init__(self, channels: tuple[str, ...] = ("System", "Application")) -> None:
        self.channels = channels
        self._last_record_number: dict[str, int] = {}
        self._last_read_channels: tuple[str, ...] = ()

    @property
    def last_read_channels(self) -> tuple[str, ...]:
        return self._last_read_channels

    def collect(self, records_per_channel: int = 32) -> list[SecurityEvent]:
        if os.name != "nt":
            raise OSError("Windows Event Log collection is only available on Windows.")
        try:
            import win32evtlog
        except ImportError as exc:
            raise RuntimeError("pywin32 is required for Windows Event Log collection.") from exc
        if not 1 <= records_per_channel <= 256:
            raise ValueError("records_per_channel must be from 1 to 256.")
        events: list[SecurityEvent] = []
        read_channels: list[str] = []
        self._last_read_channels = ()
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        for channel in self.channels:
            handle = win32evtlog.OpenEventLog(None, channel)
            try:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
            finally:
                win32evtlog.CloseEventLog(handle)
            read_channels.append(channel)
            self._last_read_channels = tuple(read_channels)
            if not records:
                continue
            previous = self._last_record_number.get(channel, 0)
            fresh = [
                record
                for record in records
                if int(record.RecordNumber) > previous
            ][:records_per_channel]
            fresh.reverse()
            for record in fresh:
                inserts = tuple(
                    str(value)[:512] for value in (record.StringInserts or ())
                )
                message = " | ".join(inserts) if inserts else (
                    "Event message unavailable from local event resources."
                )
                event_type = {
                    win32evtlog.EVENTLOG_ERROR_TYPE: "error",
                    win32evtlog.EVENTLOG_WARNING_TYPE: "warning",
                    win32evtlog.EVENTLOG_INFORMATION_TYPE: "info",
                }.get(record.EventType, "other")
                severity = {"error": "medium", "warning": "low"}.get(
                    event_type, "info"
                )
                events.append(
                    SecurityEvent(
                        source=f"windows-event-log:{channel}",
                        event_type="windows_event",
                        severity=severity,
                        description=message,
                        attributes={
                            "channel": channel,
                            "source_name": str(record.SourceName),
                            "event_id": int(record.EventID) & 0xFFFF,
                            "record_number": int(record.RecordNumber),
                            "event_type": event_type,
                            "inserts": inserts,
                        },
                    )
                )
            self._last_record_number[channel] = max(
                (int(record.RecordNumber) for record in records),
                default=previous,
            )
        return events