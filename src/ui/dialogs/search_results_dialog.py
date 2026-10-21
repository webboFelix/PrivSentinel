"""Search results dialog for global UI page search."""

from collections.abc import Sequence

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.ui.navigation import PageDefinition


class SearchResultsDialog(QDialog):
    def __init__(
        self,
        query: str,
        matches: Sequence[PageDefinition],
        parent: QWidget | None = None,
        records: Sequence[tuple[str, str]] = (),
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Search results")
        self.setMinimumSize(420, 300)
        self.selected_key: str | None = None
        layout = QVBoxLayout(self)
        label = QLabel(f"Search results for “{query}”")
        label.setObjectName("sectionTitle")
        self.results = QListWidget()
        for page in matches:
            item = QListWidgetItem(f"{page.title} — {page.description}")
            item.setData(256, page.key)
            self.results.addItem(item)
        for description, page_key in records:
            item = QListWidgetItem(description)
            item.setData(256, page_key)
            self.results.addItem(item)
        if not matches and not records:
            self.results.addItem("No alerts, files, events, or pages match this search.")
        self.results.itemDoubleClicked.connect(lambda item: self._accept_item(item))
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Open
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_selected)
        buttons.rejected.connect(self.reject)
        layout.addWidget(label)
        layout.addWidget(self.results, 1)
        layout.addWidget(buttons)

    def _accept_selected(self) -> None:
        item = self.results.currentItem()
        if item is not None and item.data(256):
            self._accept_item(item)

    def _accept_item(self, item: QListWidgetItem) -> None:
        key = item.data(256)
        if key:
            self.selected_key = str(key)
            self.accept()
