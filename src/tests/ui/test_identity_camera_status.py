from dataclasses import replace

import numpy as np
import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QImage

from src.app.dependencies import ApplicationServices
from src.config.paths import AppPaths
from src.identity.face_detector import DetectedFace, ImageQuality
from src.ui.dialogs.enrollment_dialog import EnrollmentDialog
from src.ui.main_window import MainWindow
from src.ui.pages.settings import SettingsPage


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


def test_enrollment_starts_automatically_after_consent_and_name(qtbot, monkeypatch, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    services.save_settings(replace(services.settings, camera_access_enabled=True))
    services.settings = replace(services.settings, camera_index=4)
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)

    class FakePreviewWorker(QObject):
        previewReady = Signal(object, object, object, object, object)
        cameraError = Signal(str)
        status = Signal(str)
        finished = Signal()

        def __init__(self, *args, **kwargs):
            super().__init__()
            self.camera_index = args[0]
            self.started = False
            self.running = True

        def isRunning(self):
            return self.running

        def start(self):
            self.started = True

        def stop(self):
            self.running = False
            self.finished.emit()

        def wait(self, _timeout=0):
            self.running = False
            return True

    class FakeSpeechPromptWorker(QObject):
        completed = Signal()
        failed = Signal(str)
        finished = Signal()

        def __init__(self, prompt, parent=None):
            super().__init__(parent)
            self.prompt = prompt

        def start(self):
            self.completed.emit()
            self.finished.emit()

    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.CameraPreviewWorker",
        FakePreviewWorker,
    )
    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.SpeechPromptWorker",
        FakeSpeechPromptWorker,
    )

    dialog.display_name.setText("Local user")
    dialog.display_name.editingFinished.emit()
    assert not dialog._camera_discovery_started
    dialog.consent_checkbox.setChecked(True)
    assert not dialog._camera_discovery_started
    assert dialog.model_download_checkbox.isEnabled()
    dialog.model_download_checkbox.setChecked(True)

    assert dialog._camera_discovery_started
    assert dialog._preview_worker is not None
    assert dialog._preview_worker.camera_index == 0
    assert dialog._preview_worker.started
    assert not dialog._speech_ready
    assert dialog.step_prompt.text() == "Preparing local face guidance…"
    assert dialog.readiness_progress.minimum() == 0
    assert dialog.readiness_progress.maximum() == 0
    assert dialog.step_prompt.parentWidget() is dialog
    assert dialog.preview.parentWidget() is dialog
    assert not hasattr(dialog, "capture_button")
    assert "No microphone audio is recorded or saved" in dialog.sequence_label.text()

    dialog.show()
    image = QImage(320, 240, QImage.Format.Format_RGB32)
    image.fill(0xFFFFFF)
    dialog._show_preview(
        image,
        [],
        np.zeros((240, 320, 3), dtype=np.uint8),
        ImageQuality(False, "Face guidance is loading.", 0.0, 0.0),
        {"model_loading": True},
    )
    assert dialog.isVisible()
    assert dialog.preview.pixmap() is not None
    assert "First-time download can take several minutes" in dialog.readiness_indicator.text()
    assert not dialog._speech_ready

    dialog._show_preview(
        image,
        [],
        np.zeros((240, 320, 3), dtype=np.uint8),
        ImageQuality(True, "Face guidance is ready.", 0.0, 0.0),
        {"model_ready": True},
    )
    assert dialog._speech_ready
    assert dialog.step_prompt.text().startswith("Sample 1 of 8")
    assert dialog.readiness_progress.maximum() == 100

    dialog.reject()
    services.identity_service.set_camera_state("idle", "Test cleanup.")


def test_settings_page_hides_camera_index_control(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    page = SettingsPage(services)
    qtbot.addWidget(page)

    assert not hasattr(page, "camera_index")


def test_enrollment_dialog_scales_preview_when_window_resizes(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)
    screen_bounds = dialog.screen().availableGeometry()
    assert dialog.width() <= screen_bounds.width()
    assert dialog.height() <= screen_bounds.height()

    dialog.show()
    image = QImage(320, 240, QImage.Format.Format_RGB32)
    image.fill(0xFFFFFF)
    dialog._show_preview(
        image,
        [],
        np.zeros((240, 320, 3), dtype=np.uint8),
        ImageQuality(False, "Face guidance is loading.", 0.0, 0.0),
        {"model_loading": True},
    )

    dialog.resize(600, 640)
    qtbot.wait(10)
    small_preview = dialog.preview.pixmap()
    assert small_preview is not None
    assert small_preview.width() <= dialog.preview.width()
    assert small_preview.height() <= dialog.preview.height()
    assert small_preview.width() / small_preview.height() == pytest.approx(
        4 / 3,
        abs=0.01,
    )

    dialog.resize(800, 900)
    qtbot.wait(10)
    large_preview = dialog.preview.pixmap()
    assert large_preview is not None
    assert large_preview.width() <= dialog.preview.width()
    assert large_preview.height() <= dialog.preview.height()
    assert large_preview.width() / large_preview.height() == pytest.approx(
        4 / 3,
        abs=0.01,
    )
    dialog.reject()


def test_guided_enrollment_auto_captures_and_finishes_after_final_pose(
    qtbot, monkeypatch, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    services.save_settings(replace(services.settings, camera_access_enabled=True))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)
    dialog.display_name.setText("Local user")
    dialog.repository.enroll = lambda *args: None

    class FakePreviewWorker(QObject):
        finished = Signal()

        def __init__(self):
            super().__init__()
            self.running = True

        def isRunning(self):
            return self.running

        def stop(self):
            self.running = False

        def wait(self, _timeout=0):
            self.running = False
            return True

    class FakeSpeechPromptWorker(QObject):
        completed = Signal()
        failed = Signal(str)
        finished = Signal()

        def __init__(self, prompt, parent=None):
            super().__init__(parent)
            self.prompt = prompt

        def start(self):
            self.completed.emit()
            self.finished.emit()

    beeps = []
    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.SpeechPromptWorker",
        FakeSpeechPromptWorker,
    )
    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.winsound.MessageBeep",
        lambda tone: beeps.append(tone),
    )
    dialog._preview_worker = FakePreviewWorker()
    dialog._speech_ready = True
    dialog._speak_current_step()

    frame = np.zeros((160, 160, 3), dtype=np.uint8)
    image = QImage(160, 160, QImage.Format.Format_RGB32)
    image.fill(0xFFFFFF)
    quality = ImageQuality(True, "Good lighting and focus.", 100.0, 50.0)
    face = DetectedFace(10, 10, 140, 140)
    center_guidance = {
        "yaw": 0.0,
        "pitch": 0.0,
        "eyes_open": True,
        "embedding": np.ones(32, dtype=np.float32),
    }

    def feed(guidance, count=6, *, sample_face=face, image_quality=quality):
        for _ in range(count):
            dialog._show_preview(image, [sample_face], frame, image_quality, guidance)

    blurry = ImageQuality(False, "Face image is blurry; hold still and refocus.", 100.0, 12.0)
    feed(center_guidance, image_quality=blurry)
    assert dialog._step_index == 0
    assert not dialog._enrollment_embeddings
    assert "blurry" in dialog.readiness_indicator.text()

    moving_face = DetectedFace(30, 10, 140, 140)
    feed(center_guidance, count=1, sample_face=moving_face)
    assert dialog._step_index == 0
    assert "stabilizing" in dialog.readiness_indicator.text()

    feed(center_guidance)
    assert dialog._step_index == 1
    feed({**center_guidance, "yaw": 16.0})
    assert dialog._step_index == 2
    feed({**center_guidance, "yaw": -16.0})
    assert dialog._step_index == 3
    feed({**center_guidance, "pitch": -16.0})
    assert dialog._step_index == 4
    feed({**center_guidance, "pitch": 16.0})
    assert dialog._step_index == 5

    feed(center_guidance)
    for eyes_open in (True, True, False, True, True, False, True, True):
        feed({**center_guidance, "eyes_open": eyes_open}, count=1)
    assert dialog._step_index == 5
    feed(center_guidance)
    assert dialog._step_index == 6
    feed(center_guidance)
    feed(center_guidance)
    assert dialog._enrollment_succeeded
    assert len(beeps) == 8
    assert "Enrollment complete" in dialog.enrollment_summary.text()
    assert "Template storage: Encrypted, local device only" in dialog.enrollment_summary.text()

    dialog.close_button.click()


def test_dialog_waits_for_camera_worker_before_rejecting(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)

    class ActivePreviewWorker(QObject):
        finished = Signal()

        def __init__(self):
            super().__init__()
            self.running = True

        def isRunning(self):
            return self.running

        def stop(self):
            self.running = False
            self.finished.emit()

    worker = ActivePreviewWorker()
    dialog._preview_worker = worker
    dialog._preview_worker_finished = False
    worker.finished.connect(lambda: dialog._preview_finished(worker))

    dialog.reject()

    assert dialog._pending_dialog_result == dialog.DialogCode.Rejected
    qtbot.waitUntil(lambda: dialog._pending_dialog_result is None)
    assert dialog.result() == dialog.DialogCode.Rejected


def test_glasses_option_adds_two_front_facing_samples(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)

    dialog.glasses_checkbox.setChecked(True)

    assert len(dialog._sample_steps()) == 10
    assert dialog._sample_steps()[5:7] == (
        ("If you normally wear them, put on your glasses", "center"),
        ("Now remove your glasses", "center"),
    )
    dialog.reject()


def test_enrollment_completion_shows_confidence_and_local_storage_details(
    qtbot, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)
    dialog.show()

    class FakeRepository:
        def enroll(self, display_name, embedding, model_name, consent_recorded_at):
            assert display_name == "Local user"
            assert embedding.shape == (32,)

    dialog.repository = FakeRepository()
    dialog.display_name.setText("Local user")
    dialog._embedding_ready(np.ones(32, dtype=np.float32), 0.9)

    summary = dialog.enrollment_summary.text()
    assert "Enrollment complete" in summary
    assert "Verification confidence: High" in summary
    assert "Template storage: Encrypted, local device only" in summary
    assert "Recovery method: Windows Hello / PIN" in summary
    assert "not a probability" in dialog.enrollment_summary.toolTip()
    assert "High ≥ 0.85" in dialog.enrollment_summary.toolTip()
    assert dialog.isVisible()
    assert dialog.result() != dialog.DialogCode.Accepted

    dialog.close_button.click()
    assert dialog.result() == dialog.DialogCode.Accepted
