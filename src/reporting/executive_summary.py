"""Build a daily summary from verified local records, without inventing scan results."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol


class _SummaryDatabase(Protocol):
    def fetchone(self, query: str, parameters: tuple[object, ...] = ()):
        ...


class _SummaryRepository(Protocol):
    def list_events(self, limit: int = 500) -> list[dict[str, object]]:
        ...

    def list_alerts(
        self, limit: int = 500, status: str = ""
    ) -> list[dict[str, object]]:
        ...


@dataclass(frozen=True, slots=True)
class DailyExecutiveSummary:
    generated_at: datetime
    period_start: datetime
    events: tuple[dict[str, object], ...]
    alerts: tuple[dict[str, object], ...]
    baseline_file_count: int

    @property
    def high_severity_count(self) -> int:
        return sum(
            str(event.get("severity", "")).casefold() == "high"
            for event in self.events
        )

    @property
    def critical_severity_count(self) -> int:
        return sum(
            str(event.get("severity", "")).casefold() == "critical"
            for event in self.events
        )


def collect_daily_summary(
    database: _SummaryDatabase,
    repository: _SummaryRepository,
    now: datetime | None = None,
) -> DailyExecutiveSummary:
    """Summarize the last 24 hours of local events and active rule alerts."""
    generated_at = now or datetime.now(UTC)
    if generated_at.tzinfo is None:
        raise ValueError("Daily report time must include a timezone.")
    generated_at = generated_at.astimezone(UTC)
    period_start = generated_at - timedelta(hours=24)
    events = tuple(
        event
        for event in repository.list_events(limit=10000)
        if _in_period(event.get("occurred_at"), period_start, generated_at)
    )
    alerts = tuple(
        alert
        for alert in repository.list_alerts(limit=10000)
        if str(alert.get("status", "")).casefold()
        in {"open", "acknowledged", "investigating"}
        and _in_period(alert.get("created_at"), period_start, generated_at)
    )
    count_row = database.fetchone(
        "SELECT COUNT(*) AS count FROM file_integrity_baselines"
    )
    baseline_file_count = int(count_row["count"]) if count_row is not None else 0
    return DailyExecutiveSummary(
        generated_at=generated_at,
        period_start=period_start,
        events=events,
        alerts=alerts,
        baseline_file_count=baseline_file_count,
    )


def _in_period(value: object, start: datetime, end: datetime) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return False
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return start <= timestamp.astimezone(UTC) <= end
