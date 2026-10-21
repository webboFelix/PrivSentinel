"""Daily executive report generation for local security records."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from src.reporting.executive_summary import (
    DailyExecutiveSummary,
    _SummaryDatabase,
    _SummaryRepository,
    collect_daily_summary,
)
from src.reporting.exporters.html_exporter import export_html
from src.reporting.exporters.pdf_exporter import export_pdf
from src.reporting.exporters.xlsx_exporter import export_xlsx

_EXPORTERS = {
    "pdf": export_pdf,
    "xlsx": export_xlsx,
    "html": export_html,
}


def generate_daily_reports(
    reports_directory: str | Path,
    database: _SummaryDatabase,
    repository: _SummaryRepository,
    now: datetime | None = None,
) -> dict[str, Path]:
    """Generate the supported PDF, Excel, and HTML daily report files."""
    summary = collect_daily_summary(database, repository, now)
    directory = Path(reports_directory)
    directory.mkdir(parents=True, exist_ok=True)
    day = summary.generated_at.astimezone().date().isoformat()
    paths = {
        format_name: directory / f"daily-executive-{day}.{format_name}"
        for format_name in _EXPORTERS
    }
    for format_name, exporter in _EXPORTERS.items():
        exporter(summary, paths[format_name])
    return paths


def export_daily_report(
    format_name: str,
    destination: str | Path,
    database: _SummaryDatabase,
    repository: _SummaryRepository,
    now: datetime | None = None,
) -> Path:
    """Export one supported format to a user-selected destination."""
    exporter = _EXPORTERS.get(format_name.casefold())
    if exporter is None:
        raise ValueError("Supported report formats are PDF, Excel (.xlsx), and HTML.")
    summary: DailyExecutiveSummary = collect_daily_summary(database, repository, now)
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    exporter(summary, path)
    return path
