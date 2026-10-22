"""Hash-based file integrity baseline and change detection."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
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

    def establish_baseline(
        self, progress_callback: Callable[[int], None] | None = None
    ) -> int:
        snapshot = self._snapshot(progress_callback)
        now = datetime.now(UTC).isoformat()
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
            connection.execute(
                """
                INSERT INTO file_integrity_baseline_config
                    (id, roots_json, exclusions_json)
                VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    roots_json = excluded.roots_json,
                    exclusions_json = excluded.exclusions_json
                """,
                (
                    json.dumps([str(root) for root in self.roots]),
                    json.dumps(self.exclusions),
                ),
            )
        return len(snapshot)

    def scan(self) -> list[SecurityEvent]:
        config = self.database.fetchone(
            "SELECT roots_json, exclusions_json "
            "FROM file_integrity_baseline_config WHERE id = 1"
        )
        if config is None:
            raise RuntimeError("No file integrity baseline exists. Establish one first.")
        configured_roots = sorted(json.loads(config["roots_json"]))
        current_roots = sorted(str(root) for root in self.roots)
        configured_exclusions = tuple(json.loads(config["exclusions_json"]))
        if (
            configured_roots != current_roots
            or configured_exclusions != self.exclusions
        ):
            raise RuntimeError(
                "The file integrity baseline does not match the current folders "
                "and exclusions. Establish a new baseline before scanning."
            )
        baseline_rows = self.database.fetchall(
            "SELECT path, sha256, modified_ns, size FROM file_integrity_baselines"
        )
        baseline = {
            row["path"]: (row["sha256"], row["modified_ns"], row["size"])
            for row in baseline_rows
        }
        current = self._snapshot()
        current_paths = {str(path) for path in current}
        missing_paths = set(baseline) - current_paths
        added_by_hash: dict[str, list[Path]] = {}
        missing_by_hash: dict[str, list[str]] = {}
        for path, (digest, _mtime, _size) in current.items():
            if str(path) not in baseline:
                added_by_hash.setdefault(digest, []).append(path)
        for path in missing_paths:
            missing_by_hash.setdefault(str(baseline[path][0]), []).append(path)
        rename_pairs: dict[Path, str] = {}
        renamed_paths: set[str] = set()
        # A unique hash suggests a move but cannot distinguish copy-then-delete.
        for digest, added_paths in added_by_hash.items():
            missing_matches = missing_by_hash.get(digest, [])
            if len(added_paths) == len(missing_matches) == 1:
                rename_pairs[added_paths[0]] = missing_matches[0]
                renamed_paths.add(missing_matches[0])
        events: list[SecurityEvent] = []
        for path, (digest, mtime, size) in current.items():
            old = baseline.get(str(path))
            if old is None:
                previous_path = rename_pairs.get(path)
                event_type = "file_renamed" if previous_path else "file_added"
                description = (
                    f"File path changed since baseline: {Path(previous_path).name} "
                    f"to {path.name}"
                    if previous_path
                    else f"File added since baseline: {path.name}"
                )
            elif old[0] != digest:
                previous_path = None
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
                        "previous_path": previous_path,
                        "sha256": digest,
                        "previous_sha256": old[0] if old else None,
                        "size": size,
                        "observed_mtime_ns": mtime,
                    },
                )
            )
        for path in missing_paths - renamed_paths:
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

    def _snapshot(
        self, progress_callback: Callable[[int], None] | None = None
    ) -> dict[Path, tuple[str, int, int]]:
        if not self.roots:
            raise ValueError("Select at least one file-integrity folder in Settings.")
        snapshot: dict[Path, tuple[str, int, int]] = {}

        def raise_walk_error(error: OSError) -> None:
            raise OSError(
                f"Could not read folder during file-integrity scan "
                f"{error.filename or ''}: {error}"
            ) from error

        for root in self.roots:
            if not root.exists() or not root.is_dir():
                raise OSError(f"Integrity root is unavailable or not a folder: {root}")
            for directory, _, filenames in os.walk(root, onerror=raise_walk_error):
                for filename in filenames:
                    path = Path(directory) / filename
                    if not path.is_file() or self._excluded(path):
                        continue
                    if len(snapshot) >= self.maximum_files:
                        raise RuntimeError(
                            f"File integrity scan exceeds the "
                            f"{self.maximum_files}-file safety cap."
                        )
                    try:
                        stat = path.stat()
                        digest = self._hash_file(path)
                    except OSError as exc:
                        raise OSError(
                            f"Could not read file for integrity baseline {path}: {exc}"
                        ) from exc
                    snapshot[path] = (digest, stat.st_mtime_ns, stat.st_size)
                    if progress_callback is not None and len(snapshot) % 25 == 0:
                        progress_callback(len(snapshot))
        if progress_callback is not None:
            progress_callback(len(snapshot))
        return snapshot

    def _excluded(self, path: Path) -> bool:
        normalized = str(path).replace("\\", "/").casefold()
        return any(
            fnmatch.fnmatch(path.name.casefold(), pattern.casefold())
            or fnmatch.fnmatch(
                normalized, pattern.replace("\\", "/").casefold()
            )
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
        now = datetime.now(UTC).isoformat()
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