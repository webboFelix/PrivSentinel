"""Bootstrap entry point for launching the desktop application."""

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.app.application import main

if __name__ == "__main__":
    raise SystemExit(main())
