"""Application startup orchestration."""

import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import TracebackType

from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.app.dependencies import ApplicationServices
from src.config.settings import SettingsError
from src.endpoint.integrity_baseline import effective_file_integrity_exclusions
from src.identity.face_verifier import FaceRecognitionEngine
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
    if len(sys.argv) == 2 and sys.argv[1] == "--privsentinel-browser-host":
        from src.browser.native_host import main as run_browser_native_host

        return run_browser_native_host()
    if len(sys.argv) == 3 and sys.argv[1] == "--privsentinel-prepare-recognition-model":
        try:
            FaceRecognitionEngine(Path(sys.argv[2]), allow_download=True).load()
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Could not prepare the local recognition model: {exc}", file=sys.stderr)
            return 1
        return 0
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("PrivSentinel")
    app.setOrganizationName("PrivSentinel")
    app.setWindowIcon(QIcon(icon_path("PrivSentinel.png")))
    stylesheet = Path(__file__).resolve().parents[1] / "ui" / "styles" / "theme.qss"
    app.setStyleSheet(stylesheet.read_text(encoding="utf-8-sig"))
    try:
        services = ApplicationServices.create()
        roots = services.settings.file_integrity_roots
        using_first_run_defaults = False
        if (
            not roots
            and services.database.fetchone(
                "SELECT 1 FROM file_integrity_baseline_config WHERE id = 1"
            )
            is None
        ):
            home = Path.home()
            documents = home / "OneDrive" / "Documents"
            if not documents.is_dir():
                documents = home / "Documents"
            default_roots = tuple(
                str(path.resolve())
                for path in (documents, home / "Downloads", home / "Desktop")
                if path.is_dir()
            )
            roots = default_roots
            using_first_run_defaults = bool(default_roots)
        automatic_exclusions = effective_file_integrity_exclusions(
            services.settings.file_integrity_exclusions
        )
        if (
            roots != services.settings.file_integrity_roots
            or automatic_exclusions != services.settings.file_integrity_exclusions
        ):
            services.save_settings(
                replace(
                    services.settings,
                    file_integrity_roots=roots,
                    file_integrity_exclusions=automatic_exclusions,
                    file_integrity_monitoring_enabled=(
                        services.settings.file_integrity_monitoring_enabled
                        or using_first_run_defaults
                    ),
                )
            )
    except (OSError, SettingsError, ValueError) as exc:
        QMessageBox.critical(
            None,
            "PrivSentinel could not start",
            f"Application data or settings could not be initialized:\n{exc}",
        )
        return 1
    window = MainWindow(services)
    window.show()
    QTimer.singleShot(0, window.prepare_recognition_model)
    previous_excepthook = sys.excepthook
    sys.excepthook = _qt_exception_hook(app, previous_excepthook)
    try:
        app.exec()
    except KeyboardInterrupt:
        app.quit()
    finally:
        sys.excepthook = previous_excepthook
    return 0
