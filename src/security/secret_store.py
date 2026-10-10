"""Windows DPAPI-backed storage for sensitive application key material."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

_SECRET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_DPAPI_UI_FORBIDDEN = 0x1


class WindowsSecretStore:
    """Encrypts named secrets with the current Windows user's DPAPI context."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def set(self, name: str, secret: bytes) -> None:
        self._validate_name(name)
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("Secret material must be non-empty bytes.")
        win32crypt = self._get_win32crypt()
        protected = win32crypt.CryptProtectData(
            secret,
            name,
            None,
            None,
            None,
            _DPAPI_UI_FORBIDDEN,
        )
        self.directory.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self._path(name), protected)

    def get(self, name: str) -> bytes | None:
        self._validate_name(name)
        path = self._path(name)
        if not path.exists():
            return None
        protected = path.read_bytes()
        win32crypt = self._get_win32crypt()
        _description, plaintext = win32crypt.CryptUnprotectData(
            protected,
            None,
            None,
            None,
            _DPAPI_UI_FORBIDDEN,
        )
        return bytes(plaintext)

    def delete(self, name: str) -> bool:
        self._validate_name(name)
        try:
            self._path(name).unlink()
            return True
        except FileNotFoundError:
            return False

    def contains(self, name: str) -> bool:
        self._validate_name(name)
        return self._path(name).is_file()

    @staticmethod
    def _validate_name(name: str) -> None:
        if not isinstance(name, str) or not _SECRET_NAME.fullmatch(name):
            raise ValueError("Secret names must be 1–128 safe filename characters.")

    def _path(self, name: str) -> Path:
        return self.directory / f"{name}.dpapi"

    @staticmethod
    def _get_win32crypt():
        if os.name != "nt":
            raise OSError("Windows DPAPI secret storage is available only on Windows.")
        try:
            import win32crypt
        except ImportError as exc:
            raise RuntimeError("pywin32 is required to use Windows DPAPI.") from exc
        return win32crypt

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
                delete=False,
            ) as handle:
                temporary_path = Path(handle.name)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)