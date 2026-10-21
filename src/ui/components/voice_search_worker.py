"""Local-only speech-to-text worker for toolbar voice search."""

from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal


class VoiceSearchWorker(QThread):
    recognized = Signal(str)
    failed = Signal(str)

    def __init__(self, model_directory: str | Path, parent=None) -> None:
        super().__init__(parent)
        self.model_directory = Path(model_directory)
        self._stop_requested = threading.Event()
        self._audio: queue.Queue[bytes] = queue.Queue()

    def stop(self) -> None:
        self._stop_requested.set()

    def run(self) -> None:
        try:
            import sounddevice
            from vosk import KaldiRecognizer, Model
        except (ImportError, OSError):
            self.failed.emit(
                "Offline voice search requires Vosk and sounddevice. "
                "Install them with `pip install -e '.[voice]'` and select a local "
                "Vosk model directory."
            )
            return

        try:
            if not self.model_directory.is_dir():
                raise FileNotFoundError(
                    f"Offline speech model directory not found: {self.model_directory}"
                )
            model = Model(str(self.model_directory))
            recognizer = KaldiRecognizer(model, 16000)

            def capture_audio(indata, _frames, _time_info, _status) -> None:
                self._audio.put(bytes(indata))

            with sounddevice.RawInputStream(
                samplerate=16000,
                blocksize=8000,
                dtype="int16",
                channels=1,
                callback=capture_audio,
            ):
                while not self._stop_requested.is_set():
                    try:
                        frame = self._audio.get(timeout=0.25)
                    except queue.Empty:
                        continue
                    if recognizer.AcceptWaveform(frame):
                        phrase = self._recognized_text(recognizer.Result())
                        if phrase:
                            self.recognized.emit(phrase)
                            return
                phrase = self._recognized_text(recognizer.FinalResult())
                if phrase:
                    self.recognized.emit(phrase)
        except (
            OSError,
            ValueError,
            RuntimeError,
            sounddevice.PortAudioError,
        ) as exc:
            self.failed.emit(f"Offline voice search failed: {exc}")

    @staticmethod
    def _recognized_text(result: str) -> str:
        return str(json.loads(result).get("text", "")).strip()
