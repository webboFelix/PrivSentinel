"""Application startup orchestration."""

import sys
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.app.dependencies import ApplicationServices
from src.config.settings import SettingsError
from src.ui.icon_assets import icon_path
from src.ui.main_window import MainWindow


def _qt_exception_hook(
    app: QApplication,
    previous: Callable[[type[BaseException], BaseException, TracebackType | None], None],
) -> Callable[[type[BaseException], BaseException, TracebackType | None], None]:
    def handle_exception(
        exc_type: type[BaseException],
        exc_value: BaseException,
        traceback: TracebackType | None,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            app.quit()
            return
        previous(exc_type, exc_value, traceback)

    return handle_exception


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("PrivSentinel")
    app.setOrganizationName("PrivSentinel")
    app.setWindowIcon(QIcon(icon_path("PrivSentinel.png")))
    stylesheet = Path(__file__).resolve().parents[1] / "ui" / "styles" / "theme.qss"
    app.setStyleSheet(stylesheet.read_text(encoding="utf-8-sig"))
    try:
        services = ApplicationServices.create()
    except (OSError, SettingsError, ValueError) as exc:
        QMessageBox.critical(
            None,
            "PrivSentinel could not start",
            f"Application data or settings could not be initialized:\n{exc}",
        )
        return 1
    window = MainWindow(services)
    window.show()
    previous_excepthook = sys.excepthook
    sys.excepthook = _qt_exception_hook(app, previous_excepthook)
    try:
        app.exec()
    except KeyboardInterrupt:
        app.quit()
    finally:
        sys.excepthook = previous_excepthook
    return 0
