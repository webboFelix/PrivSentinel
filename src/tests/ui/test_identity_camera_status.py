from dataclasses import replace

from PySide6.QtCore import QObject, Signal

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.ui.dialogs.enrollment_dialog import EnrollmentDialog
from src.ui.main_window import MainWindow


def test_identity_page_distinguishes_permission_from_camera_connection(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    window = MainWindow(services)
    qtbot.addWidget(window)
    page = window._pages["identity-protection"]

    services.save_settings(replace(services.settings, camera_access_enabled=True))
    assert page.camera_status.text() == "Camera: access enabled · idle"

    services.identity_service.set_camera_state("connected", "Camera opened.")
    assert page.camera_status.text() == "Camera: connected"
    assert page.camera_status.toolTip() == "Camera opened."

    services.identity_service.set_camera_state("connecting", "Opening camera.")
    services.identity_service._on_state_changed(
        "verification_failure", "Recognition model is not available."
    )
    assert page.camera_status.text() == "Camera: access enabled · idle"
    assert "verification setup failed" in page.camera_status.toolTip()

    window.close()


def test_enrollment_uses_settings_camera_consent_and_starts_configured_camera(
    qtbot, monkeypatch, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    services.save_settings(replace(services.settings, camera_access_enabled=True))
    dialog = EnrollmentDialog(
        services,
        services.identity_repository,
    )
    qtbot.addWidget(dialog)

    class FakePreviewWorker(QObject):
        previewReady = Signal(object, object, object, object)
        cameraError = Signal(str)
        finished = Signal()

        def __init__(self, *args, **kwargs):
            super().__init__()
            self.started = False

        def isRunning(self):
            return False

        def start(self):
            self.started = True

    class FakeCameraListWorker(QObject):
        devicesReady = Signal(object)
        failed = Signal(str)
        finished = Signal()

        def __init__(self, *args, **kwargs):
            super().__init__()
            self.started = False

        def isRunning(self):
            return False

        def start(self):
            self.started = True

    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.CameraPreviewWorker",
        FakePreviewWorker,
    )
    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.CameraListWorker",
        FakeCameraListWorker,
    )

    dialog._find_cameras()
    assert dialog._devices_worker is not None
    assert dialog._devices_worker.started
    dialog._camera_list_ready([])

    assert dialog._preview_worker is not None
    assert dialog._preview_worker.started
    assert dialog.camera_combo.currentData() == services.settings.camera_index
    assert services.identity_service.camera_state == "connecting"
    assert "capture an acceptable frame" in dialog.enrollment_requirements.text()
    assert "enable camera access" not in dialog.enrollment_requirements.text()

    dialog.reject()
    services.identity_service.set_camera_state("idle", "Test cleanup.")
