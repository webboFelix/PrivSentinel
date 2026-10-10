"""Hash-based file integrity baseline and change detection."""

from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import hashlib
from pathlib import Path

from src.core.event_models import SecurityEvent
from src.storage.database import SQLiteDatabase


class FileIntegrityMonitor:
    def __init__(
        self,
        database: SQLiteDatabase,
        roots: tuple[str, ...],
        exclusions: tuple[str, ...] = (),
        maximum_files: int = 50000,
    ) -> None:
        self.database = database
        self.roots = tuple(Path(root).expanduser().resolve() for root in roots)
        self.exclusions = tuple(exclusions)
        self.maximum_files = maximum_files
        if not 1 <= maximum_files <= 500000:
            raise ValueError("maximum_files must be between 1 and 500000.")

    def establish_baseline(self) -> int:
        snapshot = self._snapshot()
        now = datetime.now(timezone.utc).isoformat()
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM file_integrity_baselines")
            connection.executemany(
                """
                INSERT INTO file_integrity_baselines
                    (path, sha256, modified_ns, size, captured_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (str(path), digest, mtime, size, now)
                    for path, (digest, mtime, size) in snapshot.items()
                ],
            )
        return len(snapshot)

    def scan(self) -> list[SecurityEvent]:
        baseline_rows = self.database.fetchall(
            "SELECT path, sha256, modified_ns, size FROM file_integrity_baselines"
        )
        if not baseline_rows:
            raise RuntimeError("No file integrity baseline exists. Establish one first.")
        baseline = {
            row["path"]: (row["sha256"], row["modified_ns"], row["size"])
            for row in baseline_rows
        }
        current = self._snapshot()
        events: list[SecurityEvent] = []
        for path, (digest, mtime, size) in current.items():
            old = baseline.get(str(path))
            if old is None:
                event_type = "file_added"
                description = f"File added since baseline: {path.name}"
            elif old[0] != digest:
                event_type = "file_changed"
                description = f"File content changed since baseline: {path.name}"
            else:
                continue
            events.append(
                SecurityEvent(
                    source="file-integrity",
                    event_type=event_type,
                    severity="medium" if event_type == "file_changed" else "low",
                    description=description,
                    attributes={
                        "path": str(path),
                        "sha256": digest,
                        "previous_sha256": old[0] if old else None,
                        "size": size,
                        "observed_mtime_ns": mtime,
                    },
                )
            )
        current_paths = {str(path) for path in current}
        for path in baseline.keys() - current_paths:
            events.append(
                SecurityEvent(
                    source="file-integrity",
                    event_type="file_missing",
                    severity="medium",
                    description=f"Baseline file is no longer present: {Path(path).name}",
                    attributes={"path": path},
                )
            )
        if events:
            self._replace_snapshot(current)
        return events

    def _snapshot(self) -> dict[Path, tuple[str, int, int]]:
        if not self.roots:
            raise ValueError("Select at least one file-integrity folder in Settings.")
        snapshot: dict[Path, tuple[str, int, int]] = {}
        for root in self.roots:
            if not root.exists() or not root.is_dir():
                raise OSError(f"Integrity root is unavailable or not a folder: {root}")
            for path in root.rglob("*"):
                if len(snapshot) >= self.maximum_files:
                    raise RuntimeError(
                        f"File integrity scan exceeds the {self.maximum_files}-file safety cap."
                    )
                if not path.is_file() or self._excluded(path):
                    continue
                try:
                    stat = path.stat()
                    digest = self._hash_file(path)
                except (PermissionError, OSError):
                    continue
                snapshot[path] = (digest, stat.st_mtime_ns, stat.st_size)
        return snapshot

    def _excluded(self, path: Path) -> bool:
        normalized = str(path).casefold()
        return any(
            fnmatch.fnmatch(path.name.casefold(), pattern.casefold())
            or fnmatch.fnmatch(normalized, pattern.casefold())
            for pattern in self.exclusions
        )

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _replace_snapshot(
        self, snapshot: dict[Path, tuple[str, int, int]]
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM file_integrity_baselines")
            connection.executemany(
                """
                INSERT INTO file_integrity_baselines
                    (path, sha256, modified_ns, size, captured_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (str(path), digest, mtime, size, now)
                    for path, (digest, mtime, size) in snapshot.items()
                ],
            )