"""HTML export for the local daily executive summary."""

from __future__ import annotations

from html import escape
from pathlib import Path

from src.reporting.executive_summary import DailyExecutiveSummary


def export_html(summary: DailyExecutiveSummary, destination: str | Path) -> Path:
    path = Path(destination)
    event_rows = "".join(
        "<tr>"
        f"<td>{escape(str(event.get('occurred_at', '')))}</td>"
        f"<td>{escape(str(event.get('severity', '')).upper())}</td>"
        f"<td>{escape(str(event.get('source', '')))}</td>"
        f"<td>{escape(str(event.get('description', '')))}</td>"
        "</tr>"
        for event in summary.events
    )
    alert_rows = "".join(
        "<tr>"
        f"<td>{escape(str(alert.get('created_at', '')))}</td>"
        f"<td>{escape(str(alert.get('severity', '')).upper())}</td>"
        f"<td>{escape(str(alert.get('title', '')))}</td>"
        f"<td>{escape(str(alert.get('status', '')))}</td>"
        "</tr>"
        for alert in summary.alerts
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PrivSentinel daily executive summary</title>
<style>
body{{font:16px Segoe UI,Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#10233b}}
h1,h2{{color:#123c64}}.metrics{{display:flex;gap:1rem;flex-wrap:wrap}}
.metric{{border:1px solid #aac1d8;border-radius:8px;padding:1rem;min-width:150px}}
table{{width:100%;border-collapse:collapse;margin:1rem 0 2rem}}
th,td{{border:1px solid #c8d6e4;padding:.55rem;text-align:left;vertical-align:top}}
th{{background:#eaf2fa}}.note{{color:#526a82}}
</style>
</head>
<body>
<h1>Daily executive summary</h1>
<p>Generated {escape(summary.generated_at.isoformat())}; period starts
{escape(summary.period_start.isoformat())} (UTC).</p>
<div class="metrics">
<div class="metric"><strong>{len(summary.events)}</strong><br>Recorded events</div>
<div class="metric"><strong>{len(summary.alerts)}</strong><br>Open rule alerts</div>
<div class="metric"><strong>{summary.critical_severity_count}</strong><br>Critical events</div>
<div class="metric"><strong>{summary.high_severity_count}</strong><br>High-severity events</div>
<div class="metric"><strong>{summary.baseline_file_count}</strong><br>Baseline files</div>
</div>
<p class="note">Counts reflect records stored locally by PrivSentinel.
Rule alerts require analyst review; they are not represented as confirmed incidents.
Baseline files are integrity-monitoring records, not malware scan results.</p>
<h2>Active rule alerts</h2>
<table><thead><tr><th>Created</th><th>Severity</th><th>Alert</th><th>Status</th></tr></thead>
<tbody>{alert_rows or '<tr><td colspan="4">No active rule alerts.</td></tr>'}</tbody></table>
<h2>Recorded security events</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Details</th></tr></thead>
<tbody>{event_rows or '<tr><td colspan="4">No events in this period.</td></tr>'}</tbody></table>
</body></html>"""
    path.write_text(html, encoding="utf-8")
    return path
