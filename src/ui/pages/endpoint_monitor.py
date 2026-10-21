"""Live process usage page backed by the local process monitor."""

from src.app.dependencies import ApplicationServices
from src.ui.pages.endpoint_data import EndpointDataPage


class EndpointMonitorPage(EndpointDataPage):
    def __init__(
        self,
        services: ApplicationServices,
        parent=None,
    ) -> None:
        super().__init__("process-monitor", services, parent)
