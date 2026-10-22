"""Toolbar containing the breadcrumb, global search, and notifications."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QWidget,
)

from src.ui.components.search_bar import SearchBar
from src.ui.icon_assets import icon_path
from src.ui.navigation import PAGE_DEFINITIONS, PAGES_BY_KEY


class TopBar(QFrame):
    notificationsRequested = Signal()
    pageSearchRequested = Signal(str)
    globalSearchRequested = Signal(str)
    voiceSearchRequested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("topbar")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 6, 16, 6)
        layout.setSpacing(10)
        self.breadcrumb = QLabel("Dashboard  ›  Security Overview")
        self.breadcrumb.setMinimumWidth(150)
        self.breadcrumb.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        layout.addWidget(self.breadcrumb, 1)
        self.search_bar = SearchBar([(page.key, page.title) for page in PAGE_DEFINITIONS])
        self.search_bar.setMinimumWidth(220)
        layout.addWidget(self.search_bar)
        self.search_bar.pageSelected.connect(self.pageSearchRequested)
        self.search_bar.searchSubmitted.connect(self.globalSearchRequested)
        self.microphone_button = QPushButton()
        self.microphone_button.setObjectName("toolbarIconButton")
        self.microphone_button.setIcon(QIcon(icon_path("microphone.png")))
        self.microphone_button.setFixedSize(36, 34)
        self.microphone_button.setCheckable(True)
        self.microphone_button.setToolTip("Start offline voice search")
        self.microphone_button.setAccessibleName("Start offline voice search")
        self.microphone_button.clicked.connect(self.voiceSearchRequested)
        layout.addWidget(self.microphone_button)
        self.notification_button = QPushButton()
        self.notification_button.setObjectName("toolbarIconButton")
        self.notification_button.setIcon(QIcon(icon_path("notification-bell.png")))
        self.notification_button.setFixedSize(36, 34)
        self.notification_button.setToolTip("Open alerts")
        self.notification_button.setAccessibleName("Open alerts")
        self.notification_button.clicked.connect(self.notificationsRequested)
        notification_holder = QWidget()
        notification_holder.setFixedSize(42, 38)
        notification_layout = QGridLayout(notification_holder)
        notification_layout.setContentsMargins(0, 0, 0, 0)
        notification_layout.addWidget(
            self.notification_button,
            0,
            0,
            Qt.AlignmentFlag.AlignCenter,
        )
        self.alert_count = QLabel()
        self.alert_count.setObjectName("alertCountBadge")
        self.alert_count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.alert_count.setMinimumWidth(18)
        self.alert_count.setFixedHeight(18)
        self.alert_count.setStyleSheet(
            "color: white; background: #b4233b; border-radius: 9px; "
            "font-size: 8pt; font-weight: 700; padding: 1px 5px;"
        )
        self.alert_count.hide()
        notification_layout.addWidget(
            self.alert_count,
            0,
            0,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop,
        )
        layout.addWidget(notification_holder)

    def set_alert_count(self, count: int) -> None:
        self.alert_count.setText(str(count))
        self.alert_count.setVisible(count > 0)
        description = f"Open alerts ({count})" if count else "Open alerts"
        self.notification_button.setToolTip(description)
        self.notification_button.setAccessibleName(description)

    def set_voice_search_active(self, active: bool) -> None:
        self.microphone_button.setEnabled(True)
        self.microphone_button.setChecked(active)
        self.microphone_button.setToolTip(
            "Stop offline voice search" if active else "Start offline voice search"
        )
        self.microphone_button.setAccessibleName(
            "Stop offline voice search" if active else "Start offline voice search"
        )

    def set_page(self, key: str) -> None:
        page = PAGES_BY_KEY[key]
        self.breadcrumb.setText(
            f"{page.category.title()}  ›  {page.title}"
            if page.key != "dashboard"
            else "Dashboard  ›  Security Overview"
        )
