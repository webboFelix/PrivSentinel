"""Page metadata and navigation order for the desktop application."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PageDefinition:
    key: str
    title: str
    category: str
    description: str
    columns: tuple[str, ...] = ()


PAGE_DEFINITIONS = (
    PageDefinition("dashboard", "Dashboard", "HOME", "Security overview"),
    PageDefinition(
        "identity-protection",
        "Identity Protection",
        "IDENTITY",
        "Manage local identity verification and privacy controls.",
        ("Identity", "Verification status", "Last verified", "Confidence"),
    ),
    PageDefinition(
        "verification-history",
        "Verification History",
        "IDENTITY",
        "Review locally recorded identity verification results.",
        ("Time", "Result", "Verification method", "Details"),
    ),
    PageDefinition(
        "process-monitor",
        "Process Monitor",
        "ENDPOINT",
        "Review endpoint processes and their security context.",
        ("Process", "PID", "User", "CPU", "Memory", "Risk"),
    ),
    PageDefinition(
        "file-integrity",
        "File Integrity",
        "ENDPOINT",
        "Review file changes and locally managed integrity baselines.",
        ("File", "Change", "Detected", "Integrity status"),
    ),
    PageDefinition(
        "malware-protection",
        "Malware Protection",
        "ENDPOINT",
        "Scan accessible files with YARA or request a Windows Defender full scan.",
        ("Provider", "File", "Detection", "SHA-256", "Status", "Detected"),
    ),
    PageDefinition(
        "web-protection",
        "Browser Protection",
        "ENDPOINT",
        "Review locally evaluated browser URLs, URLhaus matches, and user allow/block decisions.",
        ("Time", "Browser", "Website", "Domain", "Decision", "Source / reason"),
    ),
    PageDefinition(
        "network-monitor",
        "Network Monitor",
        "ENDPOINT",
        "Review live interface throughput, sustained adaptive spikes, connection "
        "records, and explicit IP firewall rules. Rates are aggregate and not "
        "process-attributed; DNS uses the system resolver.",
        (
            "Local endpoint",
            "Remote host",
            "Reverse DNS",
            "Port",
            "Protocol",
            "Process",
            "State",
        ),
    ),
    PageDefinition(
        "windows-logs",
        "Windows Logs",
        "ENDPOINT",
        "Search Windows event records available to this application.",
        ("Time", "Source", "Event ID", "Level", "Message"),
    ),
    PageDefinition(
        "threat-detection",
        "Threat Detection",
        "SECURITY",
        "Review high-severity rule matches that need analyst validation.",
        ("Finding", "Severity", "Source", "Detected", "Status"),
    ),
    PageDefinition(
        "alerts",
        "Alerts",
        "SECURITY",
        "Triage open rule matches and record analyst decisions.",
        ("Alert", "Severity", "Source", "Time", "Status"),
    ),
    PageDefinition(
        "threat-intelligence",
        "Threat Intelligence",
        "SECURITY",
        "Manage local IP, domain, and SHA-256 indicators and match them against "
        "locally stored events; no external feed is enabled.",
        ("Indicator", "Type", "Source", "Last checked", "Status"),
    ),
    PageDefinition(
        "investigations",
        "Investigations",
        "SECURITY",
        "Create investigations, attach local events, and record analyst notes.",
        ("Investigation", "Created", "Updated", "Status", "Notes / events"),
    ),
    PageDefinition(
        "reports",
        "Reports",
        "REPORTING",
        "Generate daily executive summaries from locally recorded security data.",
        ("Report", "Created", "Format", "Status"),
    ),
    PageDefinition(
        "audit-log",
        "Audit Log",
        "REPORTING",
        "Review a local audit trail of configuration and analyst actions.",
        ("Time", "Actor", "Action", "Outcome", "Details"),
    ),
    PageDefinition(
        "settings",
        "Settings",
        "SYSTEM",
        "Configure local privacy, notifications, and application preferences.",
    ),
)

PAGES_BY_KEY = {page.key: page for page in PAGE_DEFINITIONS}