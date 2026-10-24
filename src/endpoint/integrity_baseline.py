"""Hash-based file integrity baseline and change detection."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from src.core.event_models import SecurityEvent
from src.storage.database import SQLiteDatabase


class _IntegrityChangeHandler(FileSystemEventHandler):
    def __init__(self, pending_changes: threading.Event) -> None:
        super().__init__()
        self.pending_changes = pending_changes

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.event_type in {"created", "modified", "deleted", "moved"}:
            self.pending_changes.set()


class FileIntegrityMonitor:
    def __init__(
        self,
        database: SQLiteDatabase,
        roots: tuple[str, ...],
        exclusions: tuple[str, ...] = (),
        maximum_files: int = 500000,
    ) -> None:
        self.database = database
        self.roots = tuple(Path(root).expanduser().resolve() for root in roots)
        self.exclusions = tuple(exclusions)
        self.maximum_files = maximum_files
        self._pending_changes = threading.Event()
        self._observer: Observer | None = None
        if not 1 <= maximum_files <= 500000:
            raise ValueError("maximum_files must be between 1 and 500000.")

    def start(self) -> None:
        if self._observer is not None:
            return
        if not self.roots:
            raise ValueError("Select at least one file-integrity folder in Settings.")
        observer = Observer()
        handler = _IntegrityChangeHandler(self._pending_changes)
        try:
            for root in self.roots:
                if not root.exists() or not root.is_dir():
                    raise OSError(f"Integrity root is unavailable or not a folder: {root}")
                observer.schedule(handler, str(root), recursive=True)
            observer.start()
        except (OSError, RuntimeError):
            observer.stop()
            raise
        self._observer = observer
        self._pending_changes.set()

    def stop(self) -> None:
        observer = self._observer
        self._observer = None
        if observer is not None:
            observer.stop()
            observer.join()

    def collect(self) -> list[SecurityEvent]:
        if self._observer is None:
            self.start()
        if not self._pending_changes.is_set():
            return []
        self._pending_changes.clear()
        return self.scan()

    def establish_baseline(
        self,
        progress_callback: Callable[[int], None] | None = None,
        progress_details_callback: Callable[[int, int], None] | None = None,
    ) -> int:
        if self.database.fetchone("SELECT 1 FROM file_integrity_baseline_config WHERE id = 1"):
            raise RuntimeError(
                "A trusted baseline already exists. Use the explicit baseline update action."
            )
        snapshot = self._snapshot(progress_callback, progress_details_callback)
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            connection.executemany(
                """
                INSERT INTO file_integrity_baselines
                    (path, sha256, modified_ns, size, captured_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    sha256 = excluded.sha256,
                    modified_ns = excluded.modified_ns,
                    size = excluded.size,
                    captured_at = excluded.captured_at
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

    def update_baseline(
        self,
        progress_callback: Callable[[int], None] | None = None,
        actor: str = "user",
        progress_details_callback: Callable[[int, int], None] | None = None,
    ) -> int:
        snapshot = self._snapshot(progress_callback, progress_details_callback)
        now = datetime.now(UTC).isoformat()
        roots_json = json.dumps([str(root) for root in self.roots])
        exclusions_json = json.dumps(self.exclusions)
        with self.database.transaction() as connection:
            previous = {
                str(row["path"]): str(row["sha256"])
                for row in connection.execute("SELECT path, sha256 FROM file_integrity_baselines")
            }
            current_paths = {str(path) for path in snapshot}
            for path in sorted(set(previous) | current_paths):
                old_hash = previous.get(path)
                new_hash = snapshot.get(Path(path), (None, 0, 0))[0]
                if old_hash == new_hash:
                    continue
                connection.execute(
                    """
                    INSERT INTO file_integrity_approvals
                        (path, previous_sha256, approved_sha256, actor, approved_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (path, old_hash, new_hash, actor, now),
                )
            connection.executemany(
                """
                INSERT INTO file_integrity_baselines
                    (path, sha256, modified_ns, size, captured_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    sha256 = excluded.sha256,
                    modified_ns = excluded.modified_ns,
                    size = excluded.size,
                    captured_at = excluded.captured_at
                """,
                [
                    (str(path), digest, mtime, size, now)
                    for path, (digest, mtime, size) in snapshot.items()
                ],
            )
            stale_paths = set(previous) - current_paths
            connection.executemany(
                "DELETE FROM file_integrity_baselines WHERE path = ?",
                ((path,) for path in stale_paths),
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
                (roots_json, exclusions_json),
            )
            connection.execute("DELETE FROM file_integrity_findings")
        return len(snapshot)

    def approve_path(self, file_path: str, actor: str = "user") -> str | None:
        path = Path(file_path).expanduser().resolve()
        if not self.is_protected_path(path):
            raise ValueError(f"File is outside the protected folders: {path}")
        now = datetime.now(UTC).isoformat()
        old = self.database.fetchone(
            "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
            (str(path),),
        )
        old_hash = str(old["sha256"]) if old is not None else None
        if path.is_file() and not self.is_excluded(path):
            stat = path.stat()
            new_hash = self.hash_file(path)
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO file_integrity_baselines
                        (path, sha256, modified_ns, size, captured_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        sha256 = excluded.sha256,
                        modified_ns = excluded.modified_ns,
                        size = excluded.size,
                        captured_at = excluded.captured_at
                    """,
                    (str(path), new_hash, stat.st_mtime_ns, stat.st_size, now),
                )
                connection.execute(
                    """
                    INSERT INTO file_integrity_approvals
                        (path, previous_sha256, approved_sha256, actor, approved_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (str(path), old_hash, new_hash, actor, now),
                )
                connection.execute(
                    "DELETE FROM file_integrity_findings WHERE path = ?",
                    (str(path),),
                )
            return new_hash
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM file_integrity_baselines WHERE path = ?", (str(path),))
            connection.execute(
                """
                INSERT INTO file_integrity_approvals
                    (path, previous_sha256, approved_sha256, actor, approved_at)
                VALUES (?, ?, NULL, ?, ?)
                """,
                (str(path), old_hash, actor, now),
            )
            connection.execute("DELETE FROM file_integrity_findings WHERE path = ?", (str(path),))
        return None

    def scan(self) -> list[SecurityEvent]:
        config = self.database.fetchone(
            "SELECT roots_json, exclusions_json FROM file_integrity_baseline_config WHERE id = 1"
        )
        if config is None:
            raise RuntimeError("No file integrity baseline exists. Establish one first.")
        configured_roots = sorted(json.loads(config["roots_json"]))
        current_roots = sorted(str(root) for root in self.roots)
        configured_exclusions = tuple(json.loads(config["exclusions_json"]))
        if configured_roots != current_roots or configured_exclusions != self.exclusions:
            raise RuntimeError(
                "The file integrity baseline does not match the current folders "
                "and exclusions. Establish a new baseline before scanning."
            )
        baseline_rows = self.database.fetchall(
            "SELECT path, sha256, modified_ns, size FROM file_integrity_baselines"
        )
        baseline = {
            row["path"]: (row["sha256"], row["modified_ns"], row["size"]) for row in baseline_rows
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
                    f"File path changed since baseline: {Path(previous_path).name} to {path.name}"
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
        now = datetime.now(UTC).isoformat()
        unique_events: list[SecurityEvent] = []
        active_paths: set[str] = set()
        with self.database.transaction() as connection:
            known = {
                str(row["path"]): str(row["fingerprint"])
                for row in connection.execute(
                    "SELECT path, fingerprint FROM file_integrity_findings"
                )
            }
            for event in events:
                path = str(event.attributes["path"])
                active_paths.add(path)
                fingerprint = "|".join(
                    (
                        event.event_type,
                        str(event.attributes.get("sha256") or ""),
                        str(event.attributes.get("previous_path") or ""),
                    )
                )
                if known.get(path) != fingerprint:
                    unique_events.append(event)
                connection.execute(
                    """
                    INSERT INTO file_integrity_findings
                        (path, fingerprint, first_seen, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        fingerprint = excluded.fingerprint,
                        first_seen = CASE
                            WHEN file_integrity_findings.fingerprint = excluded.fingerprint
                            THEN file_integrity_findings.first_seen
                            ELSE excluded.first_seen
                        END,
                        last_seen = excluded.last_seen
                    """,
                    (path, fingerprint, now, now),
                )
            stale_paths = set(known) - active_paths
            if stale_paths:
                placeholders = ",".join("?" for _ in stale_paths)
                connection.execute(
                    f"DELETE FROM file_integrity_findings WHERE path IN ({placeholders})",
                    tuple(stale_paths),
                )
        return unique_events

    def _snapshot(
        self,
        progress_callback: Callable[[int], None] | None = None,
        progress_details_callback: Callable[[int, int], None] | None = None,
    ) -> dict[Path, tuple[str, int, int]]:
        if not self.roots:
            raise ValueError("Select at least one file-integrity folder in Settings.")
        files: list[Path] = []
        seen_paths: set[Path] = set()

        def raise_walk_error(error: OSError) -> None:
            raise OSError(
                f"Could not read folder during file-integrity scan {error.filename or ''}: {error}"
            ) from error

        if progress_details_callback is not None:
            progress_details_callback(-1, -1)
        for root in self.roots:
            if not root.exists() or not root.is_dir():
                raise OSError(f"Integrity root is unavailable or not a folder: {root}")
            for directory, _, filenames in os.walk(root, onerror=raise_walk_error):
                for filename in filenames:
                    path = Path(directory) / filename
                    if path in seen_paths or not path.is_file() or self._excluded(path):
                        continue
                    if len(files) >= self.maximum_files:
                        raise RuntimeError(
                            "File integrity scan exceeds the configured safety cap "
                            f"of {self.maximum_files:,} files. Narrow the protected "
                            "folders or add exclusions, then retry."
                        )
                    seen_paths.add(path)
                    files.append(path)
        total = len(files)
        if progress_details_callback is not None:
            progress_details_callback(0, total)
        snapshot: dict[Path, tuple[str, int, int]] = {}
        for processed, path in enumerate(files, start=1):
            try:
                stat = path.stat()
                digest = self.hash_file(path)
            except OSError as exc:
                raise OSError(f"Could not read file for integrity baseline {path}: {exc}") from exc
            snapshot[path] = (digest, stat.st_mtime_ns, stat.st_size)
            if processed % 25 == 0 or processed == total:
                if progress_callback is not None:
                    progress_callback(processed)
                if progress_details_callback is not None:
                    progress_details_callback(processed, total)
        if total == 0 and progress_callback is not None:
            progress_callback(total)
        return snapshot

    def _excluded(self, path: Path) -> bool:
        normalized = str(path).replace("\\", "/").casefold()
        return any(
            fnmatch.fnmatch(path.name.casefold(), pattern.casefold())
            or fnmatch.fnmatch(normalized, pattern.replace("\\", "/").casefold())
            for pattern in self.exclusions
        )

    def is_excluded(self, path: Path) -> bool:
        return self._excluded(path)

    def is_protected_path(self, path: Path) -> bool:
        candidate = path.expanduser().resolve()
        for root in self.roots:
            try:
                common = os.path.commonpath((str(candidate), str(root)))
            except ValueError:
                continue
            if os.path.normcase(common) == os.path.normcase(str(root)):
                return True
        return False

    @staticmethod
    def hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
