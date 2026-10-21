"""Network metadata monitoring page backed by local connection events."""

from src.app.dependencies import ApplicationServices
from src.ui.components.network_traffic import NetworkTrafficPanel
from src.ui.pages.endpoint_data import EndpointDataPage


class NetworkMonitorPage(EndpointDataPage):
    def __init__(
        self,
        services: ApplicationServices,
        parent=None,
    ) -> None:
        super().__init__("network-monitor", services, parent)
        self.traffic_panel = NetworkTrafficPanel(
            enabled=services.settings.network_monitoring_enabled,
            parent=self,
        )
        self.traffic_panel.reviewConnectionsRequested.connect(
            self._review_connections
        )
        page_layout = self.layout()
        if page_layout is None:
            raise RuntimeError("Network monitor page layout was not initialized.")
        page_layout.insertWidget(2, self.traffic_panel)

    def _review_connections(self) -> None:
        self.refresh_data()
        self.table.setFocus()
