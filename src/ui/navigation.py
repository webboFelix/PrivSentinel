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
        "network-monitor",
        "Network Monitor",
        "ENDPOINT",
        "Review connection metadata without collecting packet contents.",
        ("Remote address", "Port", "Protocol", "Application", "State"),
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
        "Review detection rules and locally generated findings.",
        ("Finding", "Severity", "Source", "Detected", "Status"),
    ),
    PageDefinition(
        "alerts",
        "Alerts",
        "SECURITY",
        "Triage security alerts recorded on this device.",
        ("Alert", "Severity", "Source", "Time", "Status"),
    ),
    PageDefinition(
        "threat-intelligence",
        "Threat Intelligence",
        "SECURITY",
        "Manage optional threat-intelligence sources and local indicators.",
        ("Indicator", "Type", "Source", "Last checked", "Status"),
    ),
    PageDefinition(
        "investigations",
        "Investigations",
        "SECURITY",
        "Organize evidence and notes for local security investigations.",
        ("Investigation", "Owner", "Updated", "Status"),
    ),
    PageDefinition(
        "reports",
        "Reports",
        "REPORTING",
        "Create and review privacy-preserving local security reports.",
        ("Report", "Created", "Format", "Status"),
    ),
    PageDefinition(
        "evidence",
        "Evidence",
        "REPORTING",
        "Review locally collected evidence and its integrity metadata.",
        ("Evidence item", "Type", "Collected", "Integrity"),
    ),
    PageDefinition(
        "settings",
        "Settings",
        "SYSTEM",
        "Configure local privacy, notifications, and application preferences.",
    ),
)

PAGES_BY_KEY = {page.key: page for page in PAGE_DEFINITIONS}