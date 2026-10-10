"""Global page search control used in the application toolbar."""

from collections.abc import Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QCompleter, QLineEdit, QWidget

from src.ui.icon_assets import icon_path


class SearchBar(QLineEdit):
    pageSelected = Signal(str)
    searchSubmitted = Signal(str)

    def __init__(
        self,
        pages: Sequence[tuple[str, str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._key_by_title = {title: key for key, title in pages}
        self.setPlaceholderText("Search alerts, files, events…")
        self.setClearButtonEnabled(True)
        self.setMinimumWidth(250)
        self.setMaximumWidth(440)
        self.setToolTip("Search available pages (Ctrl+K)")
        self.addAction(
            QIcon(icon_path("internet-search.png")),
            QLineEdit.ActionPosition.LeadingPosition,
        )
        completer = QCompleter(list(self._key_by_title), self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self.setCompleter(completer)
        completer.activated[str].connect(self._select_page)
        self.returnPressed.connect(lambda: self.searchSubmitted.emit(self.text().strip()))

    def _select_page(self, title: str) -> None:
        key = self._key_by_title.get(title)
        if key:
            self.pageSelected.emit(key)
