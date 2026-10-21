from dataclasses import replace

import numpy as np
import pytest
from PySide6.QtCore import QObject, QProcess, Signal
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QMessageBox

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
    assert page.camera_status.text() == "Camera permission enabled · camera idle"
    assert "select Enroll / Re-enroll" in page.camera_status.toolTip()

    services.identity_service.set_camera_state("connected", "Camera opened.")
    assert page.camera_status.text() == "Camera: connected"
    assert page.camera_status.toolTip() == "Camera opened."

    services.identity_service.set_camera_state("connecting", "Opening camera.")
    services.identity_service._on_state_changed(
        "verification_failure", "Recognition model is not available."
    )
    assert page.camera_status.text() == "Camera permission enabled · camera idle"
    assert "verification setup failed" in page.camera_status.toolTip()

    window.close()


def test_enrollment_starts_after_explicit_consent_and_start(qtbot, monkeypatch, tmp_path):
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
    assert dialog.start_button.isEnabled()
    assert not dialog._camera_discovery_started
    dialog.start_button.click()

    assert dialog._camera_discovery_started
    assert dialog._preview_worker is not None
    assert dialog._preview_worker.camera_index == 4
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


def test_settings_page_exposes_camera_device_index(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    page = SettingsPage(services)
    qtbot.addWidget(page)

    assert page.camera_device.value() == services.settings.camera_index


def test_settings_save_persists_selected_camera_device(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    page = SettingsPage(services)
    qtbot.addWidget(page)
    page.camera_device.setValue(3)

    page._save()

    assert services.settings.camera_index == 3


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


def test_enrollment_preview_uses_fixed_oval_and_blocks_off_center_face(
    qtbot, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)
    dialog._speech_ready = True

    image = QImage(320, 240, QImage.Format.Format_RGB32)
    image.fill(0xFFFFFF)
    frame = np.zeros((240, 320, 3), dtype=np.uint8)
    quality = ImageQuality(True, "Good lighting and focus.", 100.0, 50.0)
    guidance = {
        "yaw": 0.0,
        "pitch": 0.0,
        "eyes_open": True,
        "embedding": np.ones(32, dtype=np.float32),
    }
    centered_face = DetectedFace(110, 70, 100, 100)

    dialog._show_preview(image, [centered_face], frame, quality, guidance)

    preview = dialog._preview_source.toImage()
    assert any(
        preview.pixelColor(x, y).green() > 200
        and preview.pixelColor(x, y).red() < 100
        for x in range(157, 163)
        for y in range(20, 26)
    )
    assert dialog.readiness_progress.value() == 20

    dialog._step_index = 1
    dialog._show_preview(image, [centered_face], frame, quality, guidance)
    assert "turn your head to your left" in dialog.readiness_indicator.text()
    assert dialog.readiness_progress.value() == 0

    off_center_face = DetectedFace(220, 50, 80, 140)
    dialog._show_preview(image, [off_center_face], frame, quality, guidance)

    assert dialog._step_index == 1
    assert dialog.readiness_progress.value() == 0
    assert "center of the oval guide" in dialog.readiness_indicator.text()
    dialog.reject()


def test_dismissing_setup_error_keeps_enrollment_dialog_open(
    qtbot, monkeypatch, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)
    dialog.show()
    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.QMessageBox.exec",
        lambda _box: QMessageBox.StandardButton.Close,
    )

    dialog._camera_error("Recognition model could not initialize.")

    assert dialog.isVisible()
    assert dialog._pending_dialog_result is None
    assert dialog.close_button.text() == "Retry setup"
    assert "select Retry setup" in dialog.readiness_indicator.text()
    retry_calls = []
    monkeypatch.setattr(dialog, "_start_preview", lambda: retry_calls.append(True))
    dialog.close_button.click()
    assert retry_calls == [True]
    assert dialog.isVisible()
    dialog.reject()


def test_startup_model_consent_is_reused_during_enrollment(qtbot, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    services.save_settings(
        replace(
            services.settings,
            recognition_model_download_prompted=True,
            recognition_model_download_allowed=True,
        )
    )

    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)

    assert dialog._model_download_consent_required
    assert dialog.model_download_checkbox.isChecked()
    assert dialog.model_download_checkbox.isEnabled()
    dialog.reject()


def test_enrollment_waits_in_open_dialog_for_startup_model(
    qtbot, tmp_path, monkeypatch
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    services.save_settings(replace(services.settings, camera_access_enabled=True))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)
    dialog.show()
    starts = []
    monkeypatch.setattr(dialog, "_start_preview", lambda: starts.append(True))
    dialog.set_model_preparation_pending()
    dialog.display_name.setText("Local user")
    dialog.consent_checkbox.setChecked(True)
    dialog.model_download_checkbox.setChecked(True)

    assert not starts
    assert dialog.isVisible()
    assert dialog._model_preparation_pending
    assert "ready to start when preparation finishes" in dialog.readiness_indicator.text()

    model_directory = services.paths.models_directory / "models" / "buffalo_l"
    model_directory.mkdir(parents=True)
    (model_directory / "det_10g.onnx").write_bytes(b"detector")
    (model_directory / "w600k_r50.onnx").write_bytes(b"recognizer")
    dialog.model_preparation_finished(True, "Model ready.")

    assert starts == []
    assert not dialog._model_preparation_pending
    assert dialog.model_download_checkbox.isEnabled() is False
    assert dialog.start_button.isEnabled()
    dialog.start_button.click()
    assert starts == [True]
    dialog.reject()


def test_enroll_action_opens_dialog_while_model_preparation_runs(
    qtbot, monkeypatch, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    window = MainWindow(services)
    qtbot.addWidget(window)
    calls = []

    class ActiveProcess:
        def state(self):
            return QProcess.ProcessState.Running

        def terminate(self):
            pass

        def waitForFinished(self, _timeout):
            return True

    class FakeEnrollmentDialog(QObject):
        enrollmentCompleted = Signal()
        finished = Signal(int)

        def __init__(self, *_args):
            super().__init__()
            self.waiting_for_model = False

        def set_model_preparation_pending(self):
            self.waiting_for_model = True

        def model_preparation_finished(self, _succeeded, _message):
            pass

        def exec(self):
            calls.append(self.waiting_for_model)
            self.finished.emit(0)
            return 0

    window._model_preparation_process = ActiveProcess()
    monkeypatch.setattr(
        "src.ui.main_window.EnrollmentDialog",
        FakeEnrollmentDialog,
    )

    window._handle_page_action("identity-enrollment")

    assert calls == [True]
    window._model_preparation_process = None
    window.close()


def test_guided_enrollment_auto_captures_and_finishes_after_final_pose(
    qtbot, monkeypatch, tmp_path
):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    services.save_settings(replace(services.settings, camera_access_enabled=True))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)
    dialog.display_name.setText("Local user")
    enrolled_templates = []
    dialog.repository.enroll = lambda *args: enrolled_templates.append(args[1].copy())

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

    moving_face = DetectedFace(20, 10, 140, 140)
    feed(center_guidance, count=1, sample_face=moving_face)
    assert dialog._step_index == 0
    assert "Position detected" in dialog.readiness_indicator.text()

    for sample_face in (face, moving_face, face, moving_face, face, moving_face):
        dialog._show_preview(image, [sample_face], frame, quality, center_guidance)
    assert dialog._step_index == 1
    left_embedding = np.zeros(32, dtype=np.float32)
    left_embedding[0] = 1.0
    feed({**center_guidance, "yaw": 16.0, "embedding": left_embedding})
    assert dialog._step_index == 2
    right_embedding = np.zeros(32, dtype=np.float32)
    right_embedding[1] = 1.0
    feed({**center_guidance, "yaw": -16.0, "embedding": right_embedding})
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
    assert enrolled_templates[0].shape == (2, 32)
    assert not np.allclose(enrolled_templates[0][0], enrolled_templates[0][1])
    assert len(beeps) == 8
    assert "Enrollment complete" in dialog.enrollment_summary.text()
    assert "Template storage: Encrypted, local device only" in dialog.enrollment_summary.text()

    dialog.close_button.click()


def test_pose_capture_does_not_wait_for_spoken_prompt(qtbot, monkeypatch, tmp_path):
    services = ApplicationServices.create(AppPaths(tmp_path / "local"))
    dialog = EnrollmentDialog(services, services.identity_repository)
    qtbot.addWidget(dialog)

    class RunningWorker(QObject):
        completed = Signal()
        failed = Signal(str)
        finished = Signal()

        def __init__(self, *args, **kwargs):
            super().__init__()
            self.running = True

        def isRunning(self):
            return self.running

        def start(self):
            pass

        def stop(self):
            self.running = False

    monkeypatch.setattr(
        "src.ui.dialogs.enrollment_dialog.SpeechPromptWorker",
        RunningWorker,
    )
    dialog._preview_worker = RunningWorker()
    dialog._speech_ready = False
    dialog._speak_current_step()

    image = QImage(320, 240, QImage.Format.Format_RGB32)
    image.fill(0xFFFFFF)
    frame = np.zeros((240, 320, 3), dtype=np.uint8)
    quality = ImageQuality(True, "Good lighting and focus.", 100.0, 50.0)
    guidance = {
        "yaw": 0.0,
        "pitch": 0.0,
        "eyes_open": True,
        "embedding": np.ones(32, dtype=np.float32),
    }
    face = DetectedFace(110, 70, 100, 100)
    for _ in range(5):
        dialog._show_preview(image, [face], frame, quality, guidance)

    assert dialog._step_index == 1
    assert dialog.enrollment_progress_label.text().startswith(
        "Enrollment progress: 12%"
    )
    dialog._speech_worker.stop()
    dialog._preview_worker.stop()
    dialog.reject()


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
        def enroll(
            self, display_name, embedding, model_name, consent_recorded_at, profile_details
        ):
            assert display_name == "Local user"
            assert embedding.shape == (32,)
            assert profile_details["machine_user"]

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
