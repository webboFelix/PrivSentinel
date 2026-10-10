"""Paths to the bundled PrivSentinel interface icons."""

from pathlib import Path

ICON_DIRECTORY = Path(__file__).resolve().parent / "resources" / "icons"


def icon_path(name: str) -> str:
    path = ICON_DIRECTORY / name
    if not path.is_file():
        raise FileNotFoundError(f"Bundled UI icon does not exist: {path}")
    return str(path)
