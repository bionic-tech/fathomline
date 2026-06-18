"""Incremental change feed — light-touch deltas after the first index (ADR-006, ADD 02 §incr).

After the warned first full index, repeated full walks are unacceptable at 50M+ files. The
change feed reports only what changed since the last cycle, per backend (ADD 02 table):

* **ZFS** — ``zfs diff <bookmark/snapA> <snapB>`` between successive snapshots: ZFS already
  knows what changed, so this is the cheapest feed at scale (:class:`ZfsDiffFeed`).
* **Other Linux FS / fallback** — re-``stat`` only the entries whose ``mtime`` is newer than the
  last cycle, plus a set difference against the prior inode set to find removals
  (:class:`RestatFeed`). This is the portable fallback; a ``fanotify`` mount-watch is a future
  optimisation behind the same :class:`ChangeFeed` shape.

A feed yields :class:`ChangeEvent`\\ s. CREATE/MODIFY carry the entry (re-``stat``'d, staged and
pushed like any walk entry); DELETE carries just the removed inode (the server flips its row to
not-present). A **rename** is reported as a cheap MODIFY (same inode, new path) where the feed can
see the inode move; where it cannot, it falls out as a DELETE of the old path + a CREATE of the
new (incremental owner ruling: "rename = cheap path update where detectable else DELETE+CREATE").

The feed never opens file contents (it is metadata-only, like the walk) and never widens scope:
it operates strictly within the same ``root`` the metadata scanner was given, which the server
re-enforces against the volume mountpoint regardless (AR-0012).
"""

from __future__ import annotations

import asyncio
import shlex
from collections.abc import AsyncIterator, Collection
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

from fathom.backends.base import FsEntry, StorageBackend
from fathom.backends.posix import is_excluded_path, normalise_excludes
from fathom.logging import get_logger

_log = get_logger("fathom.agent.feed")

ChangeKind = Literal["create", "modify", "delete"]


@dataclass(frozen=True, slots=True)
class ChangeEvent:
    """One change the feed observed since the last cycle.

    CREATE/MODIFY carry the re-``stat``'d :class:`FsEntry`; DELETE carries only ``inode`` (the
    server marks that ``(host, volume, inode)`` row not-present). ``path`` is always set for logs.
    """

    kind: ChangeKind
    path: str
    inode: int
    entry: FsEntry | None = None

    def __post_init__(self) -> None:
        if self.kind in ("create", "modify") and self.entry is None:
            raise ValueError(f"{self.kind} change for {self.path!r} requires an entry")


@dataclass(slots=True)
class ChangeDelta:
    """The reconciled delta of one feed cycle: entries to upsert + (inode, path) removals.

    ``removals`` carries the path the feed last knew for each removed inode so the staged removal
    (and the server's DELETE churn row) records a real path, not just an inode.
    """

    upserts: list[FsEntry] = field(default_factory=list)
    removals: list[tuple[int, str]] = field(default_factory=list)

    @property
    def removed_inodes(self) -> list[int]:
        """The removed inodes only (the wire/ingest signal)."""
        return [inode for inode, _path in self.removals]

    @property
    def is_empty(self) -> bool:
        return not self.upserts and not self.removals


@runtime_checkable
class ChangeFeed(Protocol):
    """A backend-specific incremental change feed (ADR-006). Metadata-only, no content reads.

    ``changes`` is declared as a plain method returning an ``AsyncIterator`` (not ``async def``):
    an async-generator implementation satisfies it, and the caller ``async for``-iterates the
    returned iterator — the same shape the :class:`~fathom.backends.base.StorageBackend.walk`
    protocol uses.
    """

    def changes(self, root: str) -> AsyncIterator[ChangeEvent]:
        """Yield the changes under ``root`` since the last cycle (create/modify/delete)."""
        ...


async def collect_delta(feed: ChangeFeed, root: str) -> ChangeDelta:
    """Drain ``feed`` for ``root`` into a :class:`ChangeDelta` of upserts + removed inodes.

    De-duplicates within a cycle so the pushed delta is minimal and consistent:

    * a CREATE-then-DELETE of the same inode in one cycle **cancels** — the file came and went
      within the cycle, so there is nothing to upsert and nothing in the catalogue to remove;
    * a DELETE-then-CREATE of the same inode (a rename the feed split into delete+create on the
      same inode) collapses to a single upsert — the later create cancels the earlier delete.

    Only inodes the catalogue could actually hold (a delete that was *not* freshly created this
    cycle) end up in ``removed_inodes``.
    """
    upserts: dict[int, FsEntry] = {}
    removed: dict[int, str] = {}
    created_this_cycle: set[int] = set()
    async for ev in feed.changes(root):
        if ev.kind == "delete":
            had_pending = upserts.pop(ev.inode, None) is not None
            if had_pending and ev.inode in created_this_cycle:
                # Created then deleted within this cycle → net nothing (never persisted).
                created_this_cycle.discard(ev.inode)
                continue
            removed[ev.inode] = ev.path
        else:
            assert ev.entry is not None  # noqa: S101 — guaranteed by ChangeEvent.__post_init__
            upserts[ev.inode] = ev.entry
            removed.pop(ev.inode, None)  # a re-create cancels an earlier delete of this inode
            if ev.kind == "create":
                created_this_cycle.add(ev.inode)
    removals = sorted(removed.items())
    return ChangeDelta(upserts=list(upserts.values()), removals=removals)


class RestatFeed:
    """Portable fallback feed: re-``stat`` by ``mtime`` + inode-set diff for removals (ADR-006).

    Given the prior cycle's ``{inode: (mtime, path)}`` baseline, a fresh metadata walk yields the
    current set; this feed emits CREATE for new inodes, MODIFY for inodes whose ``mtime``/path
    changed, and DELETE for baseline inodes absent from the fresh walk. It re-walks the tree (no
    kernel change-journal), so it is the bounded-window fallback ADD 02 names — cheaper than a full
    re-ingest because only changed entries are staged/pushed, never the unchanged majority.
    """

    def __init__(
        self,
        backend: StorageBackend,
        baseline: dict[int, tuple[float, str]],
        *,
        exclude: Collection[str] = (),
    ) -> None:
        self._backend = backend
        self._baseline = baseline
        # ADR-034: prune excluded subtrees on the re-walk so a cycle never re-adds them.
        self._exclude: tuple[str, ...] = tuple(exclude)

    async def changes(self, root: str) -> AsyncIterator[ChangeEvent]:
        seen: set[int] = set()
        async for entry in self._backend.walk(root, one_filesystem=True, exclude=self._exclude):
            seen.add(entry.inode)
            prior = self._baseline.get(entry.inode)
            if prior is None:
                yield ChangeEvent(kind="create", path=entry.path, inode=entry.inode, entry=entry)
            elif prior[0] != entry.mtime or prior[1] != entry.path:
                # mtime changed (content/metadata touch) OR path changed (a detected rename →
                # cheap path update, same inode): both are a MODIFY upsert (incremental ruling).
                yield ChangeEvent(kind="modify", path=entry.path, inode=entry.inode, entry=entry)
        for inode, (_mtime, path) in self._baseline.items():
            if inode not in seen:
                yield ChangeEvent(kind="delete", path=path, inode=inode)


class ZfsDiffFeed:
    """ZFS feed: parse ``zfs diff <from> <to>`` into change events (ADR-006, cheapest at scale).

    ``zfs diff`` reports, one record per line: a change-type column (``+`` added, ``-`` removed,
    ``M`` modified, ``R`` renamed) then the affected path(s). Added/modified paths are re-``stat``'d
    through the backend so the catalogue gets full metadata; a removed path resolves to the inode
    of the catalogue's prior baseline entry; a rename (``R old new``) is a cheap path MODIFY on the
    same inode where the new path can be ``stat``'d, else a delete+create (incremental ruling).

    The ``zfs`` command is invoked through an injectable ``runner`` (defaults to a bounded
    ``asyncio`` subprocess) so the parser is unit-tested without ZFS, and the dataset/snapshot
    names are passed as argv (never a shell string) so a crafted dataset name cannot inject a
    command (S-602, no shell=True).
    """

    def __init__(
        self,
        backend: StorageBackend,
        *,
        baseline_paths: dict[str, int],
        runner: ZfsDiffRunner | None = None,
        exclude: Collection[str] = (),
    ) -> None:
        self._backend = backend
        # path -> inode of the prior baseline, so a removed/renamed path resolves to its inode.
        self._baseline_paths = baseline_paths
        # ADR-034: drop change events under an excluded subtree so we never re-add them. Already
        # catalogued excluded entries are purged by the next full walk (which prunes + removes).
        self._excluded = normalise_excludes(exclude)
        self._runner = runner or _run_zfs_diff

    async def changes_between(
        self, root: str, *, dataset: str, from_snap: str, to_snap: str
    ) -> AsyncIterator[ChangeEvent]:
        """Yield events from ``zfs diff dataset@from dataset@to`` under ``root``."""
        lines = await self._runner(dataset, from_snap, to_snap)
        for line in lines:
            event = await self._parse_line(line, root)
            if event is not None:
                yield event

    async def changes(self, root: str) -> AsyncIterator[ChangeEvent]:  # pragma: no cover
        """:class:`ChangeFeed` shape; ZFS needs explicit snapshots → use ``changes_between``."""
        raise NotImplementedError("ZfsDiffFeed requires explicit snapshots; use changes_between()")
        yield  # pragma: no cover — makes this an async generator for the Protocol

    async def _parse_line(self, line: str, root: str) -> ChangeEvent | None:
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) < 2:
            return None
        change, path = parts[0], parts[1]
        if not path.startswith(root):
            return None  # outside the scanned root — never widen scope
        if is_excluded_path(path, self._excluded):
            return None  # ADR-034: an excluded subtree's changes are not catalogued
        if change == "-":
            inode = self._baseline_paths.get(path)
            return None if inode is None else ChangeEvent("delete", path=path, inode=inode)
        if change in ("+", "M"):
            entry = await self._stat_one(path)
            if entry is None:
                return None
            kind: ChangeKind = "create" if change == "+" else "modify"
            return ChangeEvent(kind, path=path, inode=entry.inode, entry=entry)
        if change == "R" and len(parts) >= 3:
            return await self._rename_event(old=parts[1], new=parts[2], root=root)
        return None

    async def _rename_event(self, *, old: str, new: str, root: str) -> ChangeEvent | None:
        """A rename is a cheap path MODIFY on the same inode where ``new`` can be ``stat``'d."""
        if not new.startswith(root) or is_excluded_path(new, self._excluded):
            # Renamed out of scope OR into an excluded subtree → a removal of the old path (DELETE).
            inode = self._baseline_paths.get(old)
            return None if inode is None else ChangeEvent("delete", path=old, inode=inode)
        entry = await self._stat_one(new)
        if entry is None:
            return None
        # Same inode, new path → a single MODIFY upsert (cheap path update, incremental ruling).
        return ChangeEvent("modify", path=new, inode=entry.inode, entry=entry)

    async def _stat_one(self, path: str) -> FsEntry | None:
        """Re-``stat`` a single changed path via a scoped one-entry walk (metadata only).

        A changed file's parent directory is walked and the matching entry returned. Falls back to
        ``None`` (logged) if the path vanished between the diff and the re-stat — a TOCTOU the next
        cycle reconciles, never a crash.
        """
        async for entry in self._backend.walk(path, one_filesystem=True):
            if entry.path == path:
                return entry
        _log.info("zfs-diff path vanished before re-stat", extra={"path": path})
        return None


@runtime_checkable
class ZfsDiffRunner(Protocol):
    """Runs ``zfs diff`` and returns its output lines (injectable for tests)."""

    async def __call__(self, dataset: str, from_snap: str, to_snap: str) -> list[str]: ...


async def _run_zfs_diff(dataset: str, from_snap: str, to_snap: str) -> list[str]:
    """Invoke ``zfs diff -H`` via argv (no shell) and return its output lines.

    ``-H`` gives tab-delimited, script-stable output. Dataset/snapshot names are argv tokens, never
    interpolated into a shell string, so a crafted name cannot inject a command (no ``shell=True``).
    The ``--`` end-of-options marker additionally stops ``zfs`` parsing a leading-dash dataset name
    as an option (argument-injection hardening, review LOW).
    """
    argv = ["zfs", "diff", "-H", "--", f"{dataset}@{from_snap}", f"{dataset}@{to_snap}"]
    _log.info("running zfs diff", extra={"cmd": shlex.join(argv)})
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise ZfsDiffError(
            f"zfs diff failed (rc={proc.returncode}): {stderr.decode('utf-8', 'replace').strip()}"
        )
    return stdout.decode("utf-8", "replace").splitlines()


class ZfsDiffError(RuntimeError):
    """Raised when ``zfs diff`` exits non-zero (missing snapshot, permission, etc.)."""
