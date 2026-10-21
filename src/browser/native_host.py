"""Native-messaging bridge for Chromium and Firefox extensions."""

from __future__ import annotations

import json
import sqlite3
import struct
import sys
from typing import BinaryIO

from src.config.paths import AppPaths
from src.security.browser_protection import BrowserProtectionService
from src.security.reputation import ReputationService
from src.security.secret_store import WindowsSecretStore
from src.storage.database import SQLiteDatabase
from src.storage.repositories.security_repository import SecurityRepository

_MAX_MESSAGE_BYTES = 1_048_576
_SUPPORTED_BROWSERS = frozenset({"Chrome", "Edge", "Brave", "Firefox"})


def run_native_host(
    input_stream: BinaryIO | None = None,
    output_stream: BinaryIO | None = None,
) -> int:
    source = input_stream or sys.stdin.buffer
    destination = output_stream or sys.stdout.buffer
    paths = AppPaths.from_environment()
    paths.ensure_directories()
    database = SQLiteDatabase(paths.database_file)
    secrets = WindowsSecretStore(paths.secrets_directory)
    repository = SecurityRepository(database)
    reputation = ReputationService(database, secrets)
    protection = BrowserProtectionService(database, reputation, repository)
    try:
        while True:
            header = _read_exact(source, 4)
            if not header:
                return 0
            if len(header) != 4:
                return 1
            message_length = struct.unpack("<I", header)[0]
            if message_length > _MAX_MESSAGE_BYTES:
                _write_message(
                    destination,
                    {"error": "Native message exceeds the size limit."},
                )
                return 1
            body = _read_exact(source, message_length)
            if len(body) != message_length:
                return 1
            message: object = None
            try:
                message = json.loads(body.decode("utf-8"))
                response = _handle_message(protection, message)
            except (
                UnicodeError,
                json.JSONDecodeError,
                KeyError,
                OSError,
                RuntimeError,
                sqlite3.Error,
                TypeError,
                ValueError,
            ) as exc:
                response = {"error": str(exc)[:1000]}
            if isinstance(message, dict) and isinstance(message.get("requestId"), str):
                response["requestId"] = message["requestId"]
            _write_message(destination, response)
    finally:
        database.close()


def _handle_message(
    protection: BrowserProtectionService,
    message: object,
) -> dict[str, object]:
    if not isinstance(message, dict):
        raise TypeError("Native message must be a JSON object.")
    operation = message.get("type")
    browser = message.get("browser", "browser")
    if not isinstance(browser, str) or browser not in _SUPPORTED_BROWSERS:
        raise ValueError("Unsupported browser identifier.")
    if operation == "get_rules":
        return protection.extension_rules()
    if operation == "visit":
        url = message.get("url")
        if not isinstance(url, str) or len(url) > 8192:
            raise ValueError("A valid website URL is required.")
        return protection.evaluate(url, browser)
    if operation == "allow_domain":
        domain = message.get("domain")
        if not isinstance(domain, str) or len(domain) > 253:
            raise ValueError("A valid domain name is required.")
        protection.set_domain_decision(
            domain,
            "allow",
            "Allowed from browser protection interstitial.",
        )
        return protection.extension_rules()
    raise ValueError("Unsupported browser connector operation.")


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_message(stream: BinaryIO, message: dict[str, object]) -> None:
    encoded = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) > _MAX_MESSAGE_BYTES:
        encoded = b'{"error":"Native response exceeds the size limit."}'
    stream.write(struct.pack("<I", len(encoded)))
    stream.write(encoded)
    stream.flush()


def main() -> int:
    return run_native_host()


if __name__ == "__main__":
    raise SystemExit(main())
