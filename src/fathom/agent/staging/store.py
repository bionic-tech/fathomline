"""SQLite (WAL) staging store with idempotent, change-guarded upserts (ADD 02, ADD 09).

SQLite access is synchronous by nature; the async reader batches entries and calls these
methods through ``asyncio.to_thread`` so the event loop is never blocked. The upsert key
``(host_id, volume_id, dev, inode)`` plus a change guard on ``(mtime, size_logical)`` make
re-staging an unchanged entry a no-op — the property that makes a push resumable without
duplicate ingest. ``dev`` (st_dev) is in the key because a cross_mounts walk spans ZFS child
datasets that each reuse low inode numbers, so inode alone collides across datasets; it
defaults to 0 for single-filesystem scans. All SQL is parameterised (ADD 09 §5).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from importlib import resources
from pathlib import Path
from types import TracebackType
from typing import Literal

from fathom.backends.base import FsEntry
from fathom.logging import get_logger

_log = get_logger("fathom.agent.staging")

ScanMode = Literal["metadata", "fullbit"]

_UPSERT = """
INSERT INTO staged_entry (
    host_id, volume_id, dev, inode, path, name, is_dir, is_symlink,
    size_logical, size_on_disk, mtime, ctime, uid, gid, flags, scan_run_id, pushed
) VALUES (
    :host_id, :volume_id, :dev, :inode, :path, :name, :is_dir, :is_symlink,
    :size_logical, :size_on_disk, :mtime, :ctime, :uid, :gid, :flags, :scan_run_id, 0
)
ON CONFLICT(host_id, volume_id, dev, inode) DO UPDATE SET
    path = excluded.path,
    name = excluded.name,
    is_dir = excluded.is_dir,
    is_symlink = excluded.is_symlink,
    size_logical = excluded.size_logical,
    size_on_disk = excluded.size_on_disk,
    mtime = excluded.mtime,
    ctime = excluded.ctime,
    uid = excluded.uid,
    gid = excluded.gid,
    flags = excluded.flags,
    scan_run_id = excluded.scan_run_id,
    pushed = 0
WHERE excluded.mtime != staged_entry.mtime
   OR excluded.size_logical != staged_entry.size_logical
"""


class StagingStore:
    """A local, disposable staging queue backed by SQLite in WAL mode."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        # The async reader stages via ``asyncio.to_thread``, so the connection is touched
        # from pooled worker threads (one at a time). ``check_same_thread=False`` plus a
        # serializing lock makes that safe without blocking the event loop.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._apply_schema()

    def __enter__(self) -> StagingStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _apply_schema(self) -> None:
        schema = resources.files("fathom.agent.staging").joinpath("schema.sql").read_text("utf-8")
        self._conn.executescript(schema)

    def start_run(
        self,
        *,
        host_id: str,
        volume_id: str,
        mode: ScanMode,
        root: str,
        started_at: float,
        warning_ack: dict[str, object] | None = None,
        volume: dict[str, object] | None = None,
    ) -> int:
        """Open a scan run and return its id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scan_run "
                "(host_id, volume_id, mode, root, started_at, warning_ack, volume_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    host_id,
                    volume_id,
                    mode,
                    root,
                    started_at,
                    json.dumps(warning_ack) if warning_ack is not None else None,
                    json.dumps(volume) if volume is not None else None,
                ),
            )
            run_id = cur.lastrowid
        if run_id is None:  # pragma: no cover — sqlite always assigns a rowid here
            raise RuntimeError("sqlite did not assign a rowid for the scan run")
        return run_id

    def stage_batch(
        self,
        *,
        run_id: int,
        host_id: str,
        volume_id: str,
        entries: Sequence[FsEntry],
    ) -> int:
        """Idempotently stage a batch. Returns the number of new-or-changed rows written."""
        rows = [
            {
                "host_id": host_id,
                "volume_id": volume_id,
                "dev": e.dev,
                "inode": e.inode,
                "path": e.path,
                "name": e.name,
                "is_dir": int(e.is_dir),
                "is_symlink": int(e.is_symlink),
                "size_logical": e.size_logical,
                "size_on_disk": e.size_on_disk,
                "mtime": e.mtime,
                "ctime": e.ctime,
                "uid": e.uid,
                "gid": e.gid,
                "flags": json.dumps(e.flags, separators=(",", ":")),
                "scan_run_id": run_id,
            }
            for e in entries
        ]
        with self._lock, self._conn:
            before = self._conn.total_changes
            self._conn.executemany(_UPSERT, rows)
            return self._conn.total_changes - before

    def finish_run(self, run_id: int, *, finished_at: float, entry_count: int) -> None:
        """Mark a run finished and record its entry count."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scan_run SET finished_at = ?, entry_count = ? WHERE id = ?",
                (finished_at, entry_count, run_id),
            )

    def stage_removals(
        self,
        *,
        run_id: int,
        host_id: str,
        volume_id: str,
        removals: Sequence[tuple[int, int, str]],
    ) -> int:
        """Stage the (dev, inode, path) triples the change feed observed removed (incremental).

        Idempotent on ``(host_id, volume_id, dev, inode)``: re-staging the same removal re-attaches
        it to this run and re-marks it unpushed (so a resumed cycle re-pushes it harmlessly — the
        server's removal is itself idempotent). Returns the number of removal rows written.

        The change feed reports the real ``st_dev`` per removal so the staged removal — and the
        server's ``present=False`` flip — keys on the full catalogue identity ``(dev, inode)``: a
        cross-dataset inode collision (ZFS child datasets reuse low inode numbers) no longer flips
        the wrong device's row. ``dev`` defaults to 0 for single-filesystem / remote backends.
        """
        rows = [
            {
                "host_id": host_id,
                "volume_id": volume_id,
                "dev": dev,
                "inode": inode,
                "path": path,
                "scan_run_id": run_id,
            }
            for dev, inode, path in removals
        ]
        if not rows:
            return 0
        with self._lock, self._conn:
            before = self._conn.total_changes
            self._conn.executemany(
                "INSERT INTO staged_removal "
                "(host_id, volume_id, dev, inode, path, scan_run_id, pushed) "
                "VALUES (:host_id, :volume_id, :dev, :inode, :path, :scan_run_id, 0) "
                "ON CONFLICT(host_id, volume_id, dev, inode) DO UPDATE SET "
                "path = excluded.path, scan_run_id = excluded.scan_run_id, pushed = 0",
                rows,
            )
            return self._conn.total_changes - before

    def unpushed_removals_for_run(self, run_id: int, *, limit: int) -> list[sqlite3.Row]:
        """Return up to ``limit`` unpushed removal rows for one run (for the push client)."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM staged_removal WHERE scan_run_id = ? AND pushed = 0 "
                "ORDER BY rowid LIMIT ?",
                (run_id, limit),
            ).fetchall()

    def mark_removals_pushed(self, keys: Sequence[tuple[str, str, int, int]]) -> int:
        """Mark the given (host_id, volume_id, dev, inode) removals pushed. Returns rows updated."""
        if not keys:
            return 0
        with self._lock, self._conn:
            before = self._conn.total_changes
            self._conn.executemany(
                "UPDATE staged_removal SET pushed = 1 "
                "WHERE host_id = ? AND volume_id = ? AND dev = ? AND inode = ?",
                keys,
            )
            return self._conn.total_changes - before

    def stage_hash(
        self,
        *,
        host_id: str,
        volume_id: str,
        inode: int,
        partial_hash: str,
        full_hash: str,
        scan_run_id: int,
        dev: int = 0,
    ) -> None:
        """Record the content hashes for one full-bit-hashed entry (resumable, ADD 02 §Mode 2).

        Updates the already-staged ``(host_id, volume_id, dev, inode)`` row in place and re-marks
        it unpushed so the next drain carries the hashes. Re-running a full-bit scan can call this
        idempotently — the same (path, hash) just rewrites the same values. ``dev`` defaults to 0;
        the full-bit funnel does not yet thread the real ``st_dev`` (see module TODO), so a
        cross-dataset full-bit scan would need that before it can hash colliding inodes apart.
        """
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE staged_entry "
                "SET partial_hash = ?, full_hash = ?, scan_run_id = ?, pushed = 0 "
                "WHERE host_id = ? AND volume_id = ? AND dev = ? AND inode = ?",
                (partial_hash, full_hash, scan_run_id, host_id, volume_id, dev, inode),
            )

    def has_baseline_run(self, *, host_id: str, volume_id: str) -> bool:
        """Return whether a *completed* metadata scan already baselined this ``(host, volume)``.

        The incremental contract (ADR-006): the first scan of a target is a full walk; once a
        baseline metadata run has *finished* (``finished_at`` set), subsequent cycles switch to the
        light-touch change feed. A run still in flight (no ``finished_at``) does not count as a
        baseline — so a crash mid-first-walk re-walks rather than feeding off a partial baseline.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM scan_run WHERE host_id = ? AND volume_id = ? "
                "AND mode = 'metadata' AND finished_at IS NOT NULL LIMIT 1",
                (host_id, volume_id),
            ).fetchone()
        return row is not None

    def load_baseline(
        self, *, host_id: str, volume_id: str
    ) -> dict[tuple[int, int], tuple[float, str]]:
        """Load the prior cycle's ``{(dev, inode): (mtime, path)}`` for this ``(host, volume)``.

        This is the baseline a :class:`~fathom.agent.reader.feed.RestatFeed` diffs the fresh walk
        against: a new ``(dev, inode)`` is a CREATE, a changed ``mtime``/``path`` a MODIFY, and a
        baseline ``(dev, inode)`` absent from the fresh walk a DELETE. The staged rows persist
        across cycles (the queue marks them ``pushed`` rather than deleting them), so the last
        walk's state is recoverable without a separate journal. Keyed on ``(dev, inode)`` — the
        catalogue identity — so colliding inodes on different ZFS child datasets of a
        ``cross_mounts`` volume don't collapse into one slot (``dev`` defaults to 0 for a single
        filesystem, where inode alone is already unique).
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT dev, inode, mtime, path FROM staged_entry "
                "WHERE host_id = ? AND volume_id = ?",
                (host_id, volume_id),
            ).fetchall()
        return {(row["dev"], row["inode"]): (row["mtime"], row["path"]) for row in rows}

    def iter_candidates(
        self, *, host_id: str, volume_id: str, scope_prefix: str
    ) -> list[sqlite3.Row]:
        """Return staged file rows under ``scope_prefix`` for the full-bit funnel.

        Only non-dir, non-symlink files within the scope are returned (the funnel never opens
        directories or symlinks). Empty (zero-byte) files are excluded at the funnel layer.
        """
        like = scope_prefix.rstrip("/") + "/%"
        with self._lock:
            return self._conn.execute(
                "SELECT host_id, volume_id, dev, inode, path, size_logical FROM staged_entry "
                "WHERE host_id = ? AND volume_id = ? AND is_dir = 0 AND is_symlink = 0 "
                "AND (path = ? OR path LIKE ?) ORDER BY rowid",
                (host_id, volume_id, scope_prefix, like),
            ).fetchall()

    def collision_sizes(self, *, host_id: str, volume_id: str, scope_prefix: str) -> list[int]:
        """Return the distinct non-zero file sizes shared by >=2 files under ``scope_prefix``.

        These are the ONLY sizes the full-bit funnel ever opens — a file with a unique size can
        never have a content duplicate, so it is never hashed (progressive-funnel correctness).
        Returning just the colliding sizes (a small set) lets the funnel stream one size-group at
        a time via :meth:`candidates_of_size` instead of materialising every candidate, which is
        what OOM-killed the scanner on million-file hosts (ADR-025 scan-fix). Ascending order.
        """
        like = scope_prefix.rstrip("/") + "/%"
        with self._lock:
            rows = self._conn.execute(
                "SELECT size_logical FROM staged_entry "
                "WHERE host_id = ? AND volume_id = ? AND is_dir = 0 AND is_symlink = 0 "
                "AND size_logical > 0 AND (path = ? OR path LIKE ?) "
                "GROUP BY size_logical HAVING COUNT(*) >= 2 ORDER BY size_logical",
                (host_id, volume_id, scope_prefix, like),
            ).fetchall()
        return [int(r["size_logical"]) for r in rows]

    def candidates_of_size(
        self, *, host_id: str, volume_id: str, scope_prefix: str, size: int
    ) -> list[sqlite3.Row]:
        """Return the staged file rows of exactly ``size`` under ``scope_prefix`` (one group).

        One call materialises a single size-group, so peak full-bit memory is bounded by the
        largest same-size group rather than the whole candidate set (ADR-025 scan-fix).
        """
        like = scope_prefix.rstrip("/") + "/%"
        with self._lock:
            return self._conn.execute(
                "SELECT host_id, volume_id, dev, inode, path, size_logical FROM staged_entry "
                "WHERE host_id = ? AND volume_id = ? AND is_dir = 0 AND is_symlink = 0 "
                "AND size_logical = ? AND (path = ? OR path LIKE ?) ORDER BY rowid",
                (host_id, volume_id, size, scope_prefix, like),
            ).fetchall()

    def iter_unpushed_hashes(self, *, limit: int = 1000) -> list[sqlite3.Row]:
        """Return staged rows carrying not-yet-pushed content hashes (for the fullbit drain)."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM staged_entry "
                "WHERE pushed = 0 AND full_hash IS NOT NULL ORDER BY scan_run_id LIMIT ?",
                (limit,),
            ).fetchall()

    def iter_unpushed(self, *, limit: int = 1000) -> Iterator[sqlite3.Row]:
        """Return staged rows not yet pushed, oldest run first (for the later push client)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM staged_entry WHERE pushed = 0 ORDER BY scan_run_id LIMIT ?",
                (limit,),
            ).fetchall()
        return iter(rows)

    def count_unpushed(self) -> int:
        """Return how many staged rows await push."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM staged_entry WHERE pushed = 0"
            ).fetchone()
        return int(row["n"])

    def pending_runs(self) -> list[sqlite3.Row]:
        """Return scan runs with unpushed entries OR removals, oldest first (resumable push).

        A delete-only incremental cycle stages removals but no entries; including runs that have
        only unpushed removals means such a cycle still drains (incremental subsystem).
        """
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM scan_run WHERE id IN "
                "(SELECT DISTINCT scan_run_id FROM staged_entry WHERE pushed = 0 "
                " UNION SELECT DISTINCT scan_run_id FROM staged_removal WHERE pushed = 0) "
                "ORDER BY id"
            ).fetchall()

    def unpushed_for_run(self, run_id: int, *, limit: int) -> list[sqlite3.Row]:
        """Return up to ``limit`` unpushed rows for one run."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM staged_entry WHERE scan_run_id = ? AND pushed = 0 "
                "ORDER BY rowid LIMIT ?",
                (run_id, limit),
            ).fetchall()

    def mark_pushed(self, keys: Sequence[tuple[str, str, int, int]]) -> int:
        """Mark the given (host_id, volume_id, dev, inode) rows pushed. Returns rows updated."""
        if not keys:
            return 0
        with self._lock, self._conn:
            before = self._conn.total_changes
            self._conn.executemany(
                "UPDATE staged_entry SET pushed = 1 "
                "WHERE host_id = ? AND volume_id = ? AND dev = ? AND inode = ?",
                keys,
            )
            return self._conn.total_changes - before
