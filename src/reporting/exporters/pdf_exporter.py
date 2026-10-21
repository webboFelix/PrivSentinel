"""PDF export for the local daily executive summary."""

from __future__ import annotations

from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.reporting.executive_summary import DailyExecutiveSummary


def export_pdf(summary: DailyExecutiveSummary, destination: str | Path) -> Path:
    path = Path(destination)
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Compact",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            alignment=TA_LEFT,
        )
    )
    document = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="PrivSentinel daily executive summary",
        author="PrivSentinel",
    )
    story = [
        Paragraph("Daily executive summary", styles["Title"]),
        Paragraph(
            "Generated "
            f"{escape(summary.generated_at.isoformat())}; period starts "
            f"{escape(summary.period_start.isoformat())} (UTC).",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph(
            f"Recorded events: {len(summary.events)} &nbsp; | &nbsp; "
            f"Active rule alerts: {len(summary.alerts)} &nbsp; | &nbsp; "
            f"Critical: {summary.critical_severity_count} &nbsp; | &nbsp; "
            f"High: {summary.high_severity_count} &nbsp; | &nbsp; "
            f"Baseline files: {summary.baseline_file_count}",
            styles["Heading3"],
        ),
        Paragraph(
            "Rule alerts require analyst review and are not confirmed incidents. "
            "Baseline files are integrity-monitoring records, not malware scan results.",
            styles["Italic"],
        ),
        Spacer(1, 10),
        Paragraph("Active rule alerts", styles["Heading2"]),
    ]
    alert_rows: list[list[object]] = [
        [
            Paragraph("<b>Created</b>", styles["Compact"]),
            Paragraph("<b>Severity</b>", styles["Compact"]),
            Paragraph("<b>Alert</b>", styles["Compact"]),
            Paragraph("<b>Source</b>", styles["Compact"]),
            Paragraph("<b>Status</b>", styles["Compact"]),
            Paragraph("<b>Rationale</b>", styles["Compact"]),
        ]
    ]
    alert_rows.extend(
        [
            Paragraph(escape(str(alert.get("created_at", ""))), styles["Compact"]),
            Paragraph(
                escape(str(alert.get("severity", "")).upper()), styles["Compact"]
            ),
            Paragraph(escape(str(alert.get("title", ""))), styles["Compact"]),
            Paragraph(escape(str(alert.get("source", ""))), styles["Compact"]),
            Paragraph(escape(str(alert.get("status", ""))), styles["Compact"]),
            Paragraph(escape(str(alert.get("rationale", ""))), styles["Compact"]),
        ]
        for alert in summary.alerts
    )
    if len(alert_rows) == 1:
        alert_rows.append(
            [Paragraph("No active rule alerts.", styles["Compact"])] + [""] * 5
        )
    story.append(_table(alert_rows))
    story.extend(
        (Spacer(1, 10), Paragraph("Recorded security events", styles["Heading2"]))
    )
    event_rows: list[list[object]] = [
        [
            Paragraph("<b>Time</b>", styles["Compact"]),
            Paragraph("<b>Severity</b>", styles["Compact"]),
            Paragraph("<b>Source / type</b>", styles["Compact"]),
            Paragraph("<b>Details</b>", styles["Compact"]),
        ]
    ]
    event_rows.extend(
        [
            Paragraph(escape(str(event.get("occurred_at", ""))), styles["Compact"]),
            Paragraph(
                escape(str(event.get("severity", "")).upper()), styles["Compact"]
            ),
            Paragraph(
                escape(f"{event.get('source', '')} / {event.get('event_type', '')}"),
                styles["Compact"],
            ),
            Paragraph(escape(str(event.get("description", ""))), styles["Compact"]),
        ]
        for event in summary.events
    )
    if len(event_rows) == 1:
        event_rows.append(
            [Paragraph("No events in this period.", styles["Compact"])] + [""] * 3
        )
    story.append(_table(event_rows))
    document.build(story)
    return path


def _table(rows: list[list[object]]) -> Table:
    table = Table(rows, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123c64")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9cb3ca")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#edf3f8")],
                ),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table