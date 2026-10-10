"""Toolbar containing the breadcrumb, global search, and notifications."""

from PySide6.QtCore import Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QWidget

from src.ui.components.search_bar import SearchBar
from src.ui.icon_assets import icon_path
from src.ui.navigation import PAGE_DEFINITIONS, PAGES_BY_KEY


class TopBar(QFrame):
    notificationsRequested = Signal()
    pageSearchRequested = Signal(str)
    globalSearchRequested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("topbar")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 6, 16, 6)
        layout.setSpacing(10)
        self.breadcrumb = QLabel("Dashboard  ›  Security Overview")
        self.breadcrumb.setMinimumWidth(210)
        layout.addWidget(self.breadcrumb, 1)
        self.search_bar = SearchBar([(page.key, page.title) for page in PAGE_DEFINITIONS])
        layout.addWidget(self.search_bar)
        self.search_bar.pageSelected.connect(self.pageSearchRequested)
        self.search_bar.searchSubmitted.connect(self.globalSearchRequested)
        self.notification_button = QPushButton()
        self.notification_button.setObjectName("toolbarIconButton")
        self.notification_button.setIcon(QIcon(icon_path("notification-bell.png")))
        self.notification_button.setFixedSize(36, 34)
        self.notification_button.setToolTip("Open alerts")
        self.notification_button.setAccessibleName("Open alerts")
        self.notification_button.clicked.connect(self.notificationsRequested)
        layout.addWidget(self.notification_button)

    def set_page(self, key: str) -> None:
        page = PAGES_BY_KEY[key]
        self.breadcrumb.setText(
            f"{page.category.title()}  ›  {page.title}"
            if page.key != "dashboard"
            else "Dashboard  ›  Security Overview"
        )
