"""Hash-based file integrity baseline and change detection."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from src.core.event_models import SecurityEvent
from src.storage.database import SQLiteDatabase

DEFAULT_FILE_INTEGRITY_EXCLUSIONS = (
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/Temp/**",
    "**/Caches/**",
    "**/.cache/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
    "*.pyc",
    "*.tmp",
    "*.temp",
)


def effective_file_integrity_exclusions(
    configured: tuple[str, ...] = (),
) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*DEFAULT_FILE_INTEGRITY_EXCLUSIONS, *configured)))


class ScanCancelledError(RuntimeError):
    """Raised when a user cancels a file-integrity scan."""


class _IntegrityChangeHandler(FileSystemEventHandler):
    def __init__(
        self,
        record_change: Callable[[str, str, str | None, bool], None],
    ) -> None:
        super().__init__()
        self.record_change = record_change

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.event_type in {"created", "modified", "deleted", "moved"}:
            if event.is_directory and event.event_type == "modified":
                return
            destination = getattr(event, "dest_path", None)
            self.record_change(
                event.event_type,
                os.fsdecode(event.src_path),
                os.fsdecode(destination) if destination is not None else None,
                event.is_directory,
            )


class FileIntegrityMonitor:
    FULL_VERIFICATION_INTERVAL = timedelta(hours=24)
    PERIODIC_SCAN_INTERVAL_SECONDS = 300
    EVENT_SETTLE_SECONDS = 0.25

    def __init__(
        self,
        database: SQLiteDatabase,
        roots: tuple[str, ...],
        exclusions: tuple[str, ...] = DEFAULT_FILE_INTEGRITY_EXCLUSIONS,
        maximum_files: int = 500000,
    ) -> None:
        self.database = database
        normalized_roots: list[Path] = []
        seen_roots: set[str] = set()
        for root in roots:
            resolved = Path(root).expanduser().resolve()
            key = os.path.normcase(str(resolved))
            if key not in seen_roots:
                normalized_roots.append(resolved)
                seen_roots.add(key)
        self.roots = tuple(normalized_roots)
        self.exclusions = tuple(exclusions)
        self.maximum_files = maximum_files
        self._pending_changes = threading.Event()
        self._change_lock = threading.Lock()
        self._last_change_monotonic = 0.0
        self._pending_changes_queue: list[tuple[str, str, str | None, bool]] = []
        self._known_directories = {
            os.path.normcase(str(root)) for root in self.roots
        }
        self._observer: BaseObserver | None = None
        self._last_scan_monotonic = 0.0
        if not 1 <= maximum_files <= 500000:
            raise ValueError("maximum_files must be between 1 and 500000.")

    def start(self) -> None:
        if self._observer is not None:
            return
        if not self.roots:
            raise ValueError("Select at least one file-integrity folder in Settings.")
        observer = Observer()
        handler = _IntegrityChangeHandler(self._record_change)
        try:
            for root in self.roots:
                if not root.exists() or not root.is_dir():
                    raise OSError(f"Integrity root is unavailable or not a folder: {root}")
                observer.schedule(handler, str(root), recursive=True)
            self._seed_inventory_from_baseline()
            observer.start()
        except (OSError, RuntimeError):
            observer.stop()
            raise
        self._observer = observer
        self._last_scan_monotonic = time.monotonic()

    def stop(self) -> None:
        observer = self._observer
        self._observer = None
        if observer is not None:
            observer.stop()
            observer.join()

    def collect(self) -> list[SecurityEvent]:
        if self._observer is None:
            self.start()
        now = time.monotonic()
        with self._change_lock:
            periodic_scan_due = (
                now - self._last_scan_monotonic >= self.PERIODIC_SCAN_INTERVAL_SECONDS
            )
            if self._pending_changes.is_set():
                if now - self._last_change_monotonic < self.EVENT_SETTLE_SECONDS:
                    return []
                self._pending_changes.clear()
                changes = self._pending_changes_queue
                self._pending_changes_queue = []
            elif now - self._last_scan_monotonic < self.PERIODIC_SCAN_INTERVAL_SECONDS:
                return []
            else:
                changes = []
        directory_changes = [change for change in changes if change[3]]
        file_changes = [change for change in changes if not change[3]]
        directory_events = [
            self._directory_event(event_type, source, destination)
            for event_type, source, destination, is_directory in directory_changes
            if is_directory and event_type in {"created", "deleted", "moved"}
            and not self.is_excluded(Path(destination or source))
        ]
        for event_type, directory_path, _, _ in directory_changes:
            directory = Path(directory_path)
            if event_type == "created" and directory.is_dir():
                file_changes.extend(
                    ("created", str(path.resolve()), None, False)
                    for path in self._iter_directory_files(directory)
                )
        if periodic_scan_due or any(
            event_type in {"deleted", "moved"} for event_type, *_ in directory_changes
        ):
            events = self.scan()
        elif file_changes:
            events = self._scan_changed_files(file_changes)
        else:
            events = []
        self._last_scan_monotonic = time.monotonic()
        return [*directory_events, *events]

    @staticmethod
    def _directory_event(
        event_type: str,
        source: str,
        destination: str | None,
    ) -> SecurityEvent:
        if event_type == "moved" and destination is not None:
            normalized_type = "folder_renamed"
            path = destination
            description = f"Protected folder renamed: {Path(source).name} to {Path(destination).name}"
        elif event_type == "deleted":
            normalized_type = "folder_deleted"
            path = source
            description = f"Protected folder deleted: {Path(source).name}"
        else:
            normalized_type = "folder_added"
            path = source
            description = f"Folder added to a protected location: {Path(source).name}"
        return SecurityEvent(
            source="file-integrity",
            event_type=normalized_type,
            severity="medium" if normalized_type != "folder_added" else "low",
            description=description,
            attributes={
                "path": path,
                "previous_path": source if normalized_type == "folder_renamed" else None,
                "is_directory": True,
            },
        )

    def _record_change(
        self,
        event_type: str,
        source_path: str,
        destination_path: str | None,
        is_directory: bool,
    ) -> None:
        source = str(Path(source_path).resolve())
        destination = (
            str(Path(destination_path).resolve()) if destination_path is not None else None
        )
        source_key = os.path.normcase(source)
        destination_key = os.path.normcase(destination) if destination is not None else None
        with self._change_lock:
            if event_type in {"deleted", "moved"} and source_key in self._known_directories:
                is_directory = True
            if is_directory and event_type == "created":
                self._known_directories.add(source_key)
            elif is_directory and event_type == "deleted":
                self._known_directories = {
                    path
                    for path in self._known_directories
                    if path != source_key and not path.startswith(f"{source_key}{os.sep}")
                }
            elif is_directory and event_type == "moved":
                self._known_directories = {
                    path
                    for path in self._known_directories
                    if path != source_key and not path.startswith(f"{source_key}{os.sep}")
                }
                if destination_key is not None:
                    self._known_directories.add(destination_key)
            self._last_change_monotonic = time.monotonic()
            self._pending_changes_queue.append(
                (
                    event_type,
                    source,
                    destination,
                    is_directory,
                )
            )
            self._pending_changes.set()

    def _seed_inventory_from_baseline(self) -> None:
        with self.database.transaction() as connection:
            if connection.execute("SELECT 1 FROM file_integrity_inventory LIMIT 1").fetchone():
                return
            connection.execute(
                """
                INSERT OR IGNORE INTO file_integrity_inventory
                    (path, sha256, modified_ns, size)
                SELECT path, sha256, modified_ns, size
                FROM file_integrity_baselines
                """,
            )

    def _scan_changed_files(
        self,
        changes: list[tuple[str, str, str | None, bool]],
    ) -> list[SecurityEvent]:
        moves = [
            (source, destination)
            for event_type, source, destination, _ in changes
            if event_type == "moved" and destination is not None
        ]
        moved_paths = {path for pair in moves for path in pair}
        changed_paths = {
            source
            for event_type, source, destination, _ in changes
            if not (event_type == "moved" and destination is not None)
            for path in (source, destination)
            if path is not None
        } - moved_paths
        observations: dict[str, tuple[str, int, int] | None] = {}
        for path in changed_paths | {destination for _, destination in moves}:
            candidate = Path(path)
            if not self.is_protected_path(candidate) or self.is_excluded(candidate):
                observations[path] = None
                continue
            try:
                if not candidate.is_file():
                    observations[path] = None
                    continue
                digest = self.hash_file(candidate)
                current_stat = candidate.stat()
            except FileNotFoundError:
                observations[path] = None
            except OSError as exc:
                raise OSError(f"Could not inspect changed file {candidate}: {exc}") from exc
            else:
                observations[path] = (digest, current_stat.st_mtime_ns, current_stat.st_size)

        now = datetime.now(UTC).isoformat()
        events: list[SecurityEvent] = []
        resolved_events: list[SecurityEvent] = []
        resolved_paths: set[str] = set()
        with self.database.transaction() as connection:
            root_deltas = {str(root): 0 for root in self.roots}

            def inventory(path: str):
                return connection.execute(
                    "SELECT sha256, modified_ns, size FROM file_integrity_inventory WHERE path = ?",
                    (path,),
                ).fetchone()

            def baseline(path: str):
                return connection.execute(
                    "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
                    (path,),
                ).fetchone()

            def update_inventory(
                path: str,
                value: tuple[str, int, int] | None,
                was_present: bool,
            ) -> None:
                is_present = value is not None
                for root in self._matching_roots(Path(path)):
                    root_key = str(root)
                    root_deltas[root_key] += int(is_present) - int(was_present)
                if value is None:
                    connection.execute(
                        "DELETE FROM file_integrity_inventory WHERE path = ?",
                        (path,),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO file_integrity_inventory
                            (path, sha256, modified_ns, size)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(path) DO UPDATE SET
                            sha256 = excluded.sha256,
                            modified_ns = excluded.modified_ns,
                            size = excluded.size
                        """,
                        (path, *value),
                    )

            for source, destination in moves:
                source_inventory = inventory(source)
                source_baseline = baseline(source)
                destination_inventory = inventory(destination)
                destination_value = observations.get(destination)
                source_was_present = source_inventory is not None
                destination_was_present = destination_inventory is not None
                if destination_value is not None:
                    destination_baseline = baseline(destination)
                    if source_was_present or source_baseline is not None:
                        event_type = "file_renamed"
                        description = (
                            f"File path changed since baseline: "
                            f"{Path(source).name} to {Path(destination).name}"
                        )
                        previous_hash = (
                            source_inventory["sha256"]
                            if source_inventory is not None
                            else source_baseline["sha256"]
                        )
                    else:
                        event_type = "file_added"
                        description = f"File added since baseline: {Path(destination).name}"
                        previous_hash = None
                    if (
                        destination_baseline is not None
                        and destination_value[0] == destination_baseline["sha256"]
                    ):
                        resolved_paths.update((source, destination))
                    events.append(
                        SecurityEvent(
                            source="file-integrity",
                            event_type=event_type,
                            severity="low",
                            description=description,
                            attributes={
                                "path": destination,
                                "previous_path": source if event_type == "file_renamed" else None,
                                "sha256": destination_value[0],
                                "previous_sha256": previous_hash,
                                "size": destination_value[2],
                                "observed_mtime_ns": destination_value[1],
                            },
                        )
                    )
                    update_inventory(source, None, source_was_present)
                    update_inventory(destination, destination_value, destination_was_present)
                elif source_was_present or source_baseline is not None:
                    events.append(
                        SecurityEvent(
                            source="file-integrity",
                            event_type="file_missing",
                            severity="medium",
                            description=f"Baseline file is no longer present: {Path(source).name}",
                            attributes={
                                "path": source,
                                "previous_sha256": (
                                    source_inventory["sha256"]
                                    if source_inventory is not None
                                    else source_baseline["sha256"]
                                ),
                            },
                        )
                    )
                    update_inventory(source, None, source_was_present)

            for path in changed_paths:
                current = observations.get(path)
                previous = inventory(path)
                trusted = baseline(path)
                was_present = previous is not None
                if current is None:
                    if was_present or trusted is not None:
                        events.append(
                            SecurityEvent(
                                source="file-integrity",
                                event_type="file_missing",
                                severity="medium",
                                description=f"File is no longer present: {Path(path).name}",
                                attributes={
                                    "path": path,
                                    "previous_sha256": (
                                        previous["sha256"]
                                        if previous is not None
                                        else trusted["sha256"]
                                    ),
                                },
                            )
                        )
                    update_inventory(path, None, was_present)
                    continue

                digest, modified_ns, size = current
                previous_hash = previous["sha256"] if previous is not None else None
                trusted_hash = trusted["sha256"] if trusted is not None else None
                if not was_present and trusted is None:
                    event_type = "file_added"
                    description = f"File added since baseline: {Path(path).name}"
                elif previous_hash != digest and (
                    previous_hash is not None or trusted_hash != digest
                ):
                    event_type = "file_changed"
                    description = f"File content changed since baseline: {Path(path).name}"
                else:
                    event_type = ""
                    description = ""
                if event_type:
                    event = SecurityEvent(
                        source="file-integrity",
                        event_type=event_type,
                        severity=(
                            "low"
                            if trusted_hash is not None and trusted_hash == digest
                            else "medium"
                            if event_type == "file_changed"
                            else "low"
                        ),
                        description=(
                            f"File content restored to trusted baseline: {Path(path).name}"
                            if trusted_hash is not None and trusted_hash == digest
                            else description
                        ),
                        attributes={
                            "path": path,
                            "previous_path": None,
                            "sha256": digest,
                            "previous_sha256": previous_hash or trusted_hash,
                            "size": size,
                            "observed_mtime_ns": modified_ns,
                        },
                    )
                    if trusted_hash is not None and trusted_hash == digest:
                        resolved_events.append(event)
                        resolved_paths.add(path)
                    else:
                        events.append(event)
                update_inventory(path, current, was_present)

            unique_events = self._persist_findings(connection, events, now)
            unique_events.extend(resolved_events)
            for path in resolved_paths:
                connection.execute(
                    "DELETE FROM file_integrity_findings WHERE path = ?",
                    (path,),
                )
            for root, delta in root_deltas.items():
                if delta:
                    connection.execute(
                        """
                        INSERT INTO file_integrity_folder_stats
                            (root, file_count, scanned_at)
                        VALUES (?, ?, ?)
                        ON CONFLICT(root) DO UPDATE SET
                            file_count = MAX(0, file_integrity_folder_stats.file_count + ?),
                            scanned_at = excluded.scanned_at
                        """,
                        (root, max(0, delta), now, delta),
                    )
                else:
                    connection.execute(
                        "UPDATE file_integrity_folder_stats SET scanned_at = ? WHERE root = ?",
                        (now, root),
                    )
        return unique_events

    @staticmethod
    def _persist_findings(
        connection: sqlite3.Connection,
        events: list[SecurityEvent],
        now: str,
    ) -> list[SecurityEvent]:
        unique_events: list[SecurityEvent] = []
        for event in events:
            path = str(event.attributes["path"])
            fingerprint = "|".join(
                (
                    event.event_type,
                    str(event.attributes.get("sha256") or ""),
                    str(event.attributes.get("previous_path") or ""),
                )
            )
            existing = connection.execute(
                "SELECT fingerprint FROM file_integrity_findings WHERE path = ?",
                (path,),
            ).fetchone()
            if existing is None or str(existing["fingerprint"]) != fingerprint:
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
        return unique_events

    def establish_baseline(
        self,
        progress_callback: Callable[[int], None] | None = None,
        progress_details_callback: Callable[[int, int], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> int:
        if self.database.fetchone("SELECT 1 FROM file_integrity_baseline_config WHERE id = 1"):
            raise RuntimeError(
                "A trusted baseline already exists. Use the explicit baseline update action."
            )
        snapshot = self._snapshot(
            progress_callback,
            progress_details_callback,
            cancel_event=cancel_event,
        )
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
            self._replace_inventory(connection, snapshot)
            self._persist_folder_stats(connection, snapshot, now)
            connection.execute(
                """
                INSERT INTO file_integrity_scan_state (id, last_full_verified_at)
                VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET last_full_verified_at = excluded.last_full_verified_at
                """,
                (now,),
            )
        return len(snapshot)

    def update_baseline(
        self,
        progress_callback: Callable[[int], None] | None = None,
        actor: str = "user",
        progress_details_callback: Callable[[int, int], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> int:
        snapshot = self._snapshot(
            progress_callback,
            progress_details_callback,
            cancel_event=cancel_event,
        )
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
            self._replace_inventory(connection, snapshot)
            self._persist_folder_stats(connection, snapshot, now)
            connection.execute(
                """
                INSERT INTO file_integrity_scan_state (id, last_full_verified_at)
                VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET last_full_verified_at = excluded.last_full_verified_at
                """,
                (now,),
            )
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
                    INSERT INTO file_integrity_inventory
                        (path, sha256, modified_ns, size)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        sha256 = excluded.sha256,
                        modified_ns = excluded.modified_ns,
                        size = excluded.size
                    """,
                    (str(path), new_hash, stat.st_mtime_ns, stat.st_size),
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
            connection.execute("DELETE FROM file_integrity_inventory WHERE path = ?", (str(path),))
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

    def approve_directory(
        self,
        directory_path: str,
        actor: str = "user",
        previous_directory_path: str | None = None,
    ) -> int:
        path = Path(directory_path).expanduser().resolve()
        if not self.is_protected_path(path):
            raise ValueError(f"Folder is outside the protected folders: {path}")
        previous_path = (
            Path(previous_directory_path).expanduser().resolve()
            if previous_directory_path
            else None
        )
        affected_roots = [path]
        if previous_path is not None:
            if not self.is_protected_path(previous_path):
                raise ValueError(f"Previous folder is outside the protected folders: {previous_path}")
            affected_roots.append(previous_path)

        snapshot: dict[str, tuple[str, int, int]] = {}
        if path.is_dir():
            for candidate in self._iter_directory_files(path):
                if not self.is_protected_path(candidate):
                    continue
                try:
                    stat = candidate.stat()
                    digest = self.hash_file(candidate)
                except OSError as exc:
                    raise OSError(f"Could not approve file in monitored folder {candidate}: {exc}") from exc
                snapshot[str(candidate.resolve())] = (
                    digest,
                    stat.st_mtime_ns,
                    stat.st_size,
                )

        def is_affected(candidate: str) -> bool:
            try:
                normalized = os.path.normcase(str(Path(candidate).resolve()))
                return any(
                    os.path.commonpath((normalized, os.path.normcase(str(root))))
                    == os.path.normcase(str(root))
                    for root in affected_roots
                )
            except ValueError:
                return False

        old_paths = {
            str(row["path"])
            for row in self.database.fetchall(
                "SELECT path FROM file_integrity_baselines UNION "
                "SELECT path FROM file_integrity_inventory"
            )
            if is_affected(str(row["path"]))
        }
        affected_paths = old_paths | set(snapshot)
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            for current_path in affected_paths:
                old = connection.execute(
                    "SELECT sha256 FROM file_integrity_baselines WHERE path = ?",
                    (current_path,),
                ).fetchone()
                old_hash = str(old["sha256"]) if old is not None else None
                current = snapshot.get(current_path)
                if current is None:
                    connection.execute(
                        "DELETE FROM file_integrity_baselines WHERE path = ?",
                        (current_path,),
                    )
                    connection.execute(
                        "DELETE FROM file_integrity_inventory WHERE path = ?",
                        (current_path,),
                    )
                    approved_hash = None
                else:
                    digest, modified_ns, size = current
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
                        (current_path, digest, modified_ns, size, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO file_integrity_inventory (path, sha256, modified_ns, size)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(path) DO UPDATE SET
                            sha256 = excluded.sha256,
                            modified_ns = excluded.modified_ns,
                            size = excluded.size
                        """,
                        (current_path, digest, modified_ns, size),
                    )
                    approved_hash = digest
                connection.execute(
                    """
                    INSERT INTO file_integrity_approvals
                        (path, previous_sha256, approved_sha256, actor, approved_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (current_path, old_hash, approved_hash, actor, now),
                )
                connection.execute(
                    "DELETE FROM file_integrity_findings WHERE path = ?",
                    (current_path,),
                )

            inventory_paths = [
                str(row["path"])
                for row in connection.execute("SELECT path FROM file_integrity_inventory")
            ]
            counts = {
                str(root): sum(
                    1
                    for inventory_path in inventory_paths
                    if self._path_is_within(Path(inventory_path), root)
                )
                for root in self.roots
            }
            connection.executemany(
                """
                INSERT INTO file_integrity_folder_stats (root, file_count, scanned_at)
                VALUES (?, ?, ?)
                ON CONFLICT(root) DO UPDATE SET
                    file_count = excluded.file_count,
                    scanned_at = excluded.scanned_at
                """,
                ((root, count, now) for root, count in counts.items()),
            )
        return len(snapshot)

    @staticmethod
    def _path_is_within(path: Path, root: Path) -> bool:
        try:
            return os.path.normcase(os.path.commonpath((str(path), str(root)))) == os.path.normcase(
                str(root)
            )
        except ValueError:
            return False

    def _iter_directory_files(self, root: Path):
        def raise_walk_error(error: OSError) -> None:
            raise error

        for current, directories, filenames in os.walk(root, onerror=raise_walk_error):
            current_path = Path(current)
            directories[:] = [
                name
                for name in directories
                if not self.is_excluded(current_path / name)
            ]
            for filename in filenames:
                candidate = current_path / filename
                if candidate.is_file() and not self.is_excluded(candidate):
                    yield candidate

    def scan(
        self,
        progress_details_callback: Callable[[int, int], None] | None = None,
        cancel_event: threading.Event | None = None,
        force_full_verification: bool = False,
        force_hash_paths: set[str] | None = None,
    ) -> list[SecurityEvent]:
        config = self.database.fetchone(
            "SELECT roots_json, exclusions_json FROM file_integrity_baseline_config WHERE id = 1"
        )
        if config is None:
            raise RuntimeError("No file integrity baseline exists. Establish one first.")
        configured_roots = sorted(
            {
                os.path.normcase(str(Path(root).expanduser().resolve()))
                for root in json.loads(config["roots_json"])
            }
        )
        current_roots = sorted(str(root) for root in self.roots)
        configured_exclusions = tuple(json.loads(config["exclusions_json"]))
        current_roots = sorted(os.path.normcase(root) for root in current_roots)
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
        inventory_rows = self.database.fetchall(
            "SELECT path, sha256, modified_ns, size FROM file_integrity_inventory"
        )
        inventory = {
            row["path"]: (row["sha256"], row["modified_ns"], row["size"])
            for row in inventory_rows
        }
        scan_state = self.database.fetchone(
            "SELECT last_full_verified_at FROM file_integrity_scan_state WHERE id = 1"
        )
        last_full_verified_at = (
            datetime.fromisoformat(str(scan_state["last_full_verified_at"]))
            if scan_state is not None and scan_state["last_full_verified_at"]
            else None
        )
        now_utc = datetime.now(UTC)
        full_verification_due = force_full_verification or (
            last_full_verified_at is None
            or now_utc - (
                last_full_verified_at.replace(tzinfo=UTC)
                if last_full_verified_at.tzinfo is None
                else last_full_verified_at.astimezone(UTC)
            )
            >= self.FULL_VERIFICATION_INTERVAL
        )
        current = self._snapshot(
            progress_details_callback=progress_details_callback,
            baseline=baseline,
            force_hash=full_verification_due,
            force_hash_paths=force_hash_paths,
            cancel_event=cancel_event,
        )
        current_paths = {str(path) for path in current}
        missing_paths = (set(baseline) | set(inventory)) - current_paths
        events: list[SecurityEvent] = []
        for path, (digest, mtime, size) in current.items():
            path_text = str(path)
            old = baseline.get(path_text)
            old_inventory = inventory.get(path_text)
            if old is None and old_inventory is not None and old_inventory[0] != digest:
                previous_path = None
                event_type = "file_changed"
                description = f"File content changed since last scan: {path.name}"
            elif old is None and old_inventory is None:
                previous_path = None
                event_type = "file_added"
                description = f"File added since baseline: {path.name}"
            elif old is not None and old[0] != digest:
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
                        "previous_sha256": (
                            old[0] if old is not None else old_inventory[0] if old_inventory else None
                        ),
                        "size": size,
                        "observed_mtime_ns": mtime,
                    },
                )
            )
        for path in missing_paths:
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
            unique_events = self._persist_findings(connection, events, now)
            active_paths.update(str(event.attributes["path"]) for event in events)
            stale_paths = set(known) - active_paths
            if stale_paths:
                placeholders = ",".join("?" for _ in stale_paths)
                connection.execute(
                    f"DELETE FROM file_integrity_findings WHERE path IN ({placeholders})",
                    tuple(stale_paths),
                )
            self._replace_inventory(connection, current)
            self._persist_folder_stats(connection, current, now)
            if full_verification_due:
                connection.execute(
                    """
                    INSERT INTO file_integrity_scan_state (id, last_full_verified_at)
                    VALUES (1, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        last_full_verified_at = excluded.last_full_verified_at
                    """,
                    (now,),
                )
        return unique_events

    def _snapshot(
        self,
        progress_callback: Callable[[int], None] | None = None,
        progress_details_callback: Callable[[int, int], None] | None = None,
        *,
        baseline: dict[str, tuple[str, int, int]] | None = None,
        force_hash: bool = True,
        force_hash_paths: set[str] | None = None,
        cancel_event: threading.Event | None = None,
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
            self._check_cancelled(cancel_event)
            if not root.exists() or not root.is_dir():
                raise OSError(f"Integrity root is unavailable or not a folder: {root}")
            for directory, directory_names, filenames in os.walk(root, onerror=raise_walk_error):
                self._check_cancelled(cancel_event)
                directory_names[:] = [
                    name
                    for name in directory_names
                    if not self._excluded(Path(directory) / name)
                    and not self._excluded(Path(directory) / name / "__integrity_entry__")
                ]
                for filename in filenames:
                    self._check_cancelled(cancel_event)
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
            self._check_cancelled(cancel_event)
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise OSError(f"Could not read file for integrity baseline {path}: {exc}") from exc
            old = baseline.get(str(path)) if baseline is not None else None
            if (
                not force_hash
                and old is not None
                and (
                    force_hash_paths is None
                    or os.path.normcase(str(path.resolve())) not in force_hash_paths
                )
                and old[1] == stat.st_mtime_ns
                and old[2] == stat.st_size
            ):
                digest = old[0]
            else:
                try:
                    digest = self.hash_file(path, cancel_event=cancel_event)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise OSError(
                        f"Could not read file for integrity baseline {path}: {exc}"
                    ) from exc
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
        candidate = Path(os.path.abspath(os.fspath(path.expanduser())))
        for pattern in self.exclusions:
            normalized_pattern = pattern.replace("\\", "/").casefold()
            if fnmatch.fnmatch(candidate.name.casefold(), normalized_pattern):
                return True
            if Path(pattern).is_absolute():
                normalized_path = str(candidate).replace("\\", "/").casefold()
                if fnmatch.fnmatch(normalized_path, normalized_pattern):
                    return True
                continue
            for root in self._matching_roots(candidate, resolve=False):
                try:
                    relative_path = candidate.relative_to(root).as_posix().casefold()
                except ValueError:
                    continue
                if fnmatch.fnmatch(relative_path, normalized_pattern) or fnmatch.fnmatch(
                    f"/{relative_path}", normalized_pattern
                ):
                    return True
        return False

    def is_excluded(self, path: Path) -> bool:
        return self._excluded(path)

    def _matching_roots(
        self,
        path: Path,
        *,
        resolve: bool = True,
    ) -> tuple[Path, ...]:
        candidate = (
            path.expanduser().resolve()
            if resolve
            else Path(os.path.abspath(os.fspath(path.expanduser())))
        )
        matches: list[Path] = []
        for root in self.roots:
            try:
                common = os.path.commonpath((str(candidate), str(root)))
            except ValueError:
                continue
            if os.path.normcase(common) == os.path.normcase(str(root)):
                matches.append(root)
        return tuple(matches)

    def is_protected_path(self, path: Path) -> bool:
        return bool(self._matching_roots(path))

    @staticmethod
    def hash_file(
        path: Path,
        cancel_event: threading.Event | None = None,
    ) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                FileIntegrityMonitor._check_cancelled(cancel_event)
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _check_cancelled(cancel_event: threading.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelledError("File-integrity scan was cancelled.")

    def _persist_folder_stats(
        self,
        connection: sqlite3.Connection,
        snapshot: dict[Path, tuple[str, int, int]],
        scanned_at: str,
    ) -> None:
        counts = {str(root): 0 for root in self.roots}
        for path in snapshot:
            for root in self.roots:
                try:
                    if os.path.normcase(
                        os.path.commonpath((str(path), str(root)))
                    ) == os.path.normcase(str(root)):
                        counts[str(root)] += 1
                except ValueError:
                    continue
        connection.executemany(
            """
            INSERT INTO file_integrity_folder_stats (root, file_count, scanned_at)
            VALUES (?, ?, ?)
            ON CONFLICT(root) DO UPDATE SET
                file_count = excluded.file_count,
                scanned_at = excluded.scanned_at
            """,
            ((root, count, scanned_at) for root, count in counts.items()),
        )
        if counts:
            placeholders = ",".join("?" for _ in counts)
            connection.execute(
                f"DELETE FROM file_integrity_folder_stats WHERE root NOT IN ({placeholders})",
                tuple(counts),
            )

    @staticmethod
    def _replace_inventory(
        connection: sqlite3.Connection,
        snapshot: dict[Path, tuple[str, int, int]],
    ) -> None:
        connection.execute("DELETE FROM file_integrity_inventory")
        connection.executemany(
            """
            INSERT INTO file_integrity_inventory
                (path, sha256, modified_ns, size)
            VALUES (?, ?, ?, ?)
            """,
            (
                (str(path), digest, modified_ns, size)
                for path, (digest, modified_ns, size) in snapshot.items()
            ),
        )
