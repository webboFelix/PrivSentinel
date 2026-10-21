"""Page widgets displayed in the main application stack."""

from src.ui.pages.alerts import AlertsPage
from src.ui.pages.audit_log import AuditLogPage
from src.ui.pages.dashboard import DashboardPage
from src.ui.pages.endpoint_monitor import EndpointMonitorPage
from src.ui.pages.file_integrity import FileIntegrityPage
from src.ui.pages.identity_protection import IdentityProtectionPage
from src.ui.pages.investigations import InvestigationsPage
from src.ui.pages.malware_protection import MalwareProtectionPage
from src.ui.pages.network_monitor import NetworkMonitorPage
from src.ui.pages.reports import ReportsPage
from src.ui.pages.settings import SettingsPage
from src.ui.pages.threat_detection import ThreatDetectionPage
from src.ui.pages.threat_intelligence import ThreatIntelligencePage
from src.ui.pages.verification_history import VerificationHistoryPage
from src.ui.pages.web_protection import WebProtectionPage
from src.ui.pages.windows_logs import WindowsLogsPage

PAGE_WIDGETS = {
    "dashboard": DashboardPage,
    "identity-protection": IdentityProtectionPage,
    "verification-history": VerificationHistoryPage,
    "process-monitor": EndpointMonitorPage,
    "file-integrity": FileIntegrityPage,
    "malware-protection": MalwareProtectionPage,
    "web-protection": WebProtectionPage,
    "network-monitor": NetworkMonitorPage,
    "windows-logs": WindowsLogsPage,
    "threat-detection": ThreatDetectionPage,
    "alerts": AlertsPage,
    "threat-intelligence": ThreatIntelligencePage,
    "investigations": InvestigationsPage,
    "reports": ReportsPage,
    "audit-log": AuditLogPage,
    "settings": SettingsPage,
}