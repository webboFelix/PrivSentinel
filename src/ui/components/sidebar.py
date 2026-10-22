"""Application sidebar and page navigation controls."""

from typing import ClassVar

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from src.ui.icon_assets import icon_path
from src.ui.navigation import PAGE_DEFINITIONS, PageDefinition


class Sidebar(QFrame):
    pageSelected = Signal(str)
    _ICONS: ClassVar[dict[str, str]] = {
        "dashboard": "security-monitor.png",
        "identity-protection": "face-scan.png",
        "verification-history": "identity-verified.png",
        "process-monitor": "processor.png",
        "file-integrity": "verified-document.png",
        "network-monitor": "network-nodes.png",
        "windows-logs": "windows-system-file.png",
        "threat-detection": "radar-scan.png",
        "alerts": "alert-bell.png",
        "threat-intelligence": "internet-search.png",
        "investigations": "file-search.png",
        "reports": "analytics-report.png",
        "audit-log": "analytics-report.png",
        "malware-protection": "shield-check.png",
        "web-protection": "internet-search.png",
        "settings": "settings-gear.png",
    }

    def __init__(
        self,
        definitions: tuple[PageDefinition, ...] = PAGE_DEFINITIONS,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setMinimumWidth(196)
        self.setMaximumWidth(224)
        self.setFixedWidth(214)
        self._buttons: dict[str, QPushButton] = {}
        self._alert_badges: dict[str, QLabel] = {}
        self._previous_category = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(3)
        brand = QWidget()
        brand_layout = QHBoxLayout(brand)
        brand_layout.setContentsMargins(0, 0, 0, 0)
        brand_layout.setSpacing(7)
        brand_icon = QLabel()
        brand_icon.setPixmap(QIcon(icon_path("PrivSentinel.png")).pixmap(34, 34))
        brand_layout.addWidget(brand_icon)
        brand_title = QLabel("PrivSentinel")
        brand_title.setObjectName("sidebarBrand")
        brand_layout.addWidget(brand_title)
        brand_layout.addStretch(1)
        brand.setMinimumHeight(38)
        layout.addWidget(brand)
        tagline = QLabel("Privacy-first endpoint protection")
        tagline.setObjectName("muted")
        tagline.setWordWrap(True)
        layout.addWidget(tagline)
        layout.addSpacing(6)

        navigation = QWidget()
        navigation_layout = QVBoxLayout(navigation)
        navigation_layout.setContentsMargins(0, 0, 0, 0)
        navigation_layout.setSpacing(3)
        for definition in definitions:
            if definition.key == "dashboard":
                self._add_page_button(navigation_layout, definition)
                navigation_layout.addSpacing(6)
                continue
            if not self._buttons or self._previous_category != definition.category:
                heading = QLabel(definition.category)
                heading.setObjectName("caption")
                heading.setStyleSheet("font-size: 8pt; font-weight: 600; margin-top: 8px;")
                navigation_layout.addWidget(heading)
            self._add_page_button(navigation_layout, definition)
            self._previous_category = definition.category

        navigation_layout.addStretch(1)
        navigation_scroll = QScrollArea()
        navigation_scroll.setObjectName("sidebarNavigation")
        navigation_scroll.setWidgetResizable(True)
        navigation_scroll.setFrameShape(QFrame.Shape.NoFrame)
        navigation_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        navigation_scroll.setWidget(navigation)
        layout.addWidget(navigation_scroll, 1)
        footer = QFrame()
        footer.setObjectName("sidebarStatus")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(8, 8, 8, 8)
        self._status_icon = QLabel()
        footer_layout.addWidget(self._status_icon, 0, Qt.AlignmentFlag.AlignTop)
        self.footer_text = QLabel("Monitoring off\nNo active collectors")
        footer_text = self.footer_text
        footer_text.setObjectName("muted")
        footer_text.setWordWrap(True)
        footer_text.setStyleSheet("font-size: 8pt;")
        footer_layout.addWidget(footer_text, 1)
        footer.setStyleSheet(
            "padding: 10px 8px; background: #081d36; border: 1px solid #153b60; border-radius: 8px;"
        )
        layout.addWidget(footer)
        self.set_active_page("dashboard")
        self.set_monitoring_active(False)

    def set_monitoring_active(self, active: bool) -> None:
        self.footer_text.setText(
            "Monitoring active\nCollectors running"
            if active
            else "Monitoring off\nNo active collectors"
        )
        icon_name = "shield-check.png" if active else "info-alert.png"
        self._status_icon.setPixmap(QIcon(icon_path(icon_name)).pixmap(19, 19))

    def set_alert_count(self, count: int) -> None:
        for badge in self._alert_badges.values():
            badge.setText(str(count))
            badge.setVisible(count > 0)

    def _add_page_button(self, layout: QVBoxLayout, definition: PageDefinition) -> None:
        button = QPushButton(definition.title)
        button.setIcon(QIcon(icon_path(self._ICONS[definition.key])))
        button.setIconSize(QSize(17, 17))
        button.setObjectName("navButton")
        button.setCheckable(True)
        button.setProperty("pageKey", definition.key)
        page_key = definition.key
        button.clicked.connect(lambda: self.pageSelected.emit(page_key))
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(4)
        row_layout.addWidget(button, 1)
        if definition.key in {"alerts", "threat-detection"}:
            badge = QLabel("0")
            badge.setObjectName("sidebarAlertCount")
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setMinimumWidth(18)
            badge.setStyleSheet(
                "color: white; background: #b4233b; border-radius: 9px; "
                "font-size: 8pt; font-weight: 700; padding: 1px 5px;"
            )
            badge.hide()
            row_layout.addWidget(badge)
            self._alert_badges[definition.key] = badge
        layout.addWidget(row)
        self._buttons[definition.key] = button

    def set_active_page(self, key: str) -> None:
        if key not in self._buttons:
            raise KeyError(f"Unknown navigation page: {key}")
        for page_key, button in self._buttons.items():
            button.setChecked(page_key == key)

    @property
    def buttons(self) -> dict[str, QPushButton]:
        return self._buttons.copy()
