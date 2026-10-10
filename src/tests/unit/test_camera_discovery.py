import numpy as np

from src.identity import camera


def test_camera_discovery_tries_media_foundation_when_directshow_fails(monkeypatch):
    attempts = []

    class FakeCapture:
        def __init__(self, index, backend):
            attempts.append((index, backend))
            self.backend = backend

        def isOpened(self):
            return self.backend == camera.cv2.CAP_MSMF

        def read(self):
            return True, np.zeros((2, 2, 3), dtype=np.uint8)

        def release(self):
            pass

    monkeypatch.setattr(camera.cv2, "VideoCapture", FakeCapture)

    devices = camera.CameraCapture.available_devices(max_devices=1)

    assert [(device.index, device.label) for device in devices] == [(0, "Camera 0")]
    assert attempts == [
        (0, camera.cv2.CAP_DSHOW),
        (0, camera.cv2.CAP_MSMF),
    ]
