"""Change-feed unit tests (incremental test_plan) — RestatFeed, ZfsDiffFeed, collect_delta.

Covers the agent-side incremental change feed (ADR-006):
- RestatFeed emits CREATE/MODIFY/DELETE by diffing a fresh walk against the prior baseline;
- a same-inode path change is a cheap MODIFY (rename = path update where detectable);
- collect_delta reconciles a cycle's events into the minimal (upserts, removed_inodes) delta and
  cancels a create-then-delete and a delete-then-recreate of the same inode;
- ZfsDiffFeed parses ``zfs diff -H`` records (+ / M / - / R), stays within root (never widens
  scope), and resolves a removed path to its baseline inode;
- the zfs runner builds an argv (no shell) so a crafted dataset name cannot inject a command.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Collection

import pytest

from fathom.agent.reader.feed import (
    ChangeEvent,
    RestatFeed,
    ZfsDiffFeed,
    collect_delta,
)
from fathom.backends.base import FsEntry, VolumeInfo

ROOT = "/mnt/pool"


def _entry(path: str, inode: int, *, size: int = 10, mtime: float = 1000.0) -> FsEntry:
    return FsEntry(
        path=path,
        name=path.rsplit("/", 1)[-1],
        is_dir=False,
        is_symlink=False,
        size_logical=size,
        size_on_disk=size,
        mtime=mtime,
        ctime=mtime,
        uid=0,
        gid=0,
        inode=inode,
        flags={},
    )


class _FakeBackend:
    """A minimal StorageBackend stand-in that walks a fixed entry list (metadata only)."""

    def __init__(self, entries: list[FsEntry]) -> None:
        self._entries = entries

    async def walk(
        self,
        root: str,
        *,
        follow_symlinks: bool = False,
        one_filesystem: bool = True,
        exclude: Collection[str] = (),
    ) -> AsyncIterator[FsEntry]:
        ex = [e.rstrip("/") for e in exclude]
        for e in self._entries:
            if not e.path.startswith(root):
                continue
            # ADR-034: a faithful double honours exclude (prefix match on path components).
            if any(e.path == x or e.path.startswith(x + "/") for x in ex):
                continue
            yield e

    async def volume_info(self, mountpoint: str) -> VolumeInfo:  # pragma: no cover - unused here
        return VolumeInfo(
            mountpoint=mountpoint,
            fs_type="zfs",
            total=0,
            used=0,
            free=0,
            device="tank",
            transport="sata",
        )


async def _drain(feed_iter: AsyncIterator[ChangeEvent]) -> list[ChangeEvent]:
    return [ev async for ev in feed_iter]


async def test_restat_feed_create_modify_delete() -> None:
    # Baseline: inode 1 (a) and inode 2 (b). Fresh walk: a modified (mtime), c new, b gone.
    baseline = {1: (1000.0, f"{ROOT}/a"), 2: (1000.0, f"{ROOT}/b")}
    backend = _FakeBackend([_entry(f"{ROOT}/a", 1, mtime=2000.0), _entry(f"{ROOT}/c", 3)])
    feed = RestatFeed(backend, baseline)
    events = await _drain(feed.changes(ROOT))
    by_inode = {ev.inode: ev for ev in events}
    assert by_inode[1].kind == "modify"
    assert by_inode[3].kind == "create"
    assert by_inode[2].kind == "delete"
    assert by_inode[2].path == f"{ROOT}/b"  # baseline path carried on the delete


async def test_restat_feed_rename_is_cheap_path_modify() -> None:
    # Same inode (1), new path → a MODIFY (cheap path update), not delete+create.
    baseline = {1: (1000.0, f"{ROOT}/old")}
    backend = _FakeBackend([_entry(f"{ROOT}/new", 1)])
    feed = RestatFeed(backend, baseline)
    events = await _drain(feed.changes(ROOT))
    assert len(events) == 1
    assert events[0].kind == "modify"
    assert events[0].path == f"{ROOT}/new"


async def test_collect_delta_minimises_and_cancels() -> None:
    class _Scripted:
        def __init__(self, events: list[ChangeEvent]) -> None:
            self._events = events

        async def changes(self, root: str) -> AsyncIterator[ChangeEvent]:
            for ev in self._events:
                yield ev

    events = [
        ChangeEvent("create", path=f"{ROOT}/a", inode=1, entry=_entry(f"{ROOT}/a", 1)),
        ChangeEvent("delete", path=f"{ROOT}/a", inode=1),  # came and went this cycle → cancels
        ChangeEvent("delete", path=f"{ROOT}/b", inode=2),
        ChangeEvent("create", path=f"{ROOT}/b", inode=2, entry=_entry(f"{ROOT}/b", 2)),  # re-add
        ChangeEvent("modify", path=f"{ROOT}/c", inode=3, entry=_entry(f"{ROOT}/c", 3)),
    ]
    delta = await collect_delta(_Scripted(events), ROOT)
    upsert_inodes = {e.inode for e in delta.upserts}
    assert upsert_inodes == {2, 3}  # inode 1 cancelled; inode 2 re-added; inode 3 modified
    assert delta.removed_inodes == []  # no net removals this cycle


async def test_collect_delta_net_removal() -> None:
    class _Scripted:
        async def changes(self, root: str) -> AsyncIterator[ChangeEvent]:
            yield ChangeEvent("delete", path=f"{ROOT}/gone", inode=9)

    delta = await collect_delta(_Scripted(), ROOT)
    assert delta.upserts == []
    assert delta.removed_inodes == [9]


async def test_zfs_diff_feed_parses_records() -> None:
    walk_entries = [_entry(f"{ROOT}/added", 11), _entry(f"{ROOT}/changed", 12)]
    backend = _FakeBackend(walk_entries)

    async def runner(dataset: str, from_snap: str, to_snap: str) -> list[str]:
        assert dataset == "tank/data"
        return [
            f"+\t{ROOT}/added",
            f"M\t{ROOT}/changed",
            f"-\t{ROOT}/removed",
            "+\t/other/outside",  # outside root → ignored (never widen scope)
        ]

    feed = ZfsDiffFeed(backend, baseline_paths={f"{ROOT}/removed": 20}, runner=runner)
    events = await _drain(
        feed.changes_between(ROOT, dataset="tank/data", from_snap="s1", to_snap="s2")
    )
    kinds = {ev.path: ev.kind for ev in events}
    assert kinds[f"{ROOT}/added"] == "create"
    assert kinds[f"{ROOT}/changed"] == "modify"
    assert kinds[f"{ROOT}/removed"] == "delete"
    assert all(not ev.path.startswith("/other") for ev in events)  # out-of-scope dropped
    removed = next(ev for ev in events if ev.kind == "delete")
    assert removed.inode == 20  # resolved from the baseline path map


async def test_zfs_diff_feed_rename_within_scope_is_modify() -> None:
    backend = _FakeBackend([_entry(f"{ROOT}/new", 30)])

    async def runner(dataset: str, from_snap: str, to_snap: str) -> list[str]:
        return [f"R\t{ROOT}/old\t{ROOT}/new"]

    feed = ZfsDiffFeed(backend, baseline_paths={f"{ROOT}/old": 30}, runner=runner)
    events = await _drain(
        feed.changes_between(ROOT, dataset="tank/data", from_snap="s1", to_snap="s2")
    )
    assert len(events) == 1
    assert events[0].kind == "modify"
    assert events[0].path == f"{ROOT}/new"
    assert events[0].inode == 30


async def test_zfs_diff_feed_rename_out_of_scope_is_delete() -> None:
    backend = _FakeBackend([])

    async def runner(dataset: str, from_snap: str, to_snap: str) -> list[str]:
        return [f"R\t{ROOT}/old\t/elsewhere/new"]

    feed = ZfsDiffFeed(backend, baseline_paths={f"{ROOT}/old": 40}, runner=runner)
    events = await _drain(
        feed.changes_between(ROOT, dataset="tank/data", from_snap="s1", to_snap="s2")
    )
    assert len(events) == 1
    assert events[0].kind == "delete"  # renamed out of scope → a removal of the old path
    assert events[0].inode == 40


async def test_change_event_requires_entry_for_create_modify() -> None:
    with pytest.raises(ValueError, match="requires an entry"):
        ChangeEvent("create", path=f"{ROOT}/x", inode=1)  # no entry → invalid


async def test_zfs_diff_runner_uses_argv_not_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """A crafted dataset name must be an argv token, never interpolated into a shell string.

    Patches ``asyncio.create_subprocess_exec`` to capture the argv and asserts the (malicious)
    dataset name lands as one positional token — there is no ``shell=True`` / string command for
    a ``; rm -rf /`` payload to break out of (S-602, no-shell guarantee).
    """
    import fathom.agent.reader.feed as feed_mod

    captured: dict[str, tuple[str, ...]] = {}

    class _Proc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", b""

    async def fake_exec(*argv: str, **_kw: object) -> _Proc:
        captured["argv"] = argv
        return _Proc()

    monkeypatch.setattr(feed_mod.asyncio, "create_subprocess_exec", fake_exec)
    evil = "tank/data; rm -rf /"
    lines = await feed_mod._run_zfs_diff(evil, "s1", "s2")
    assert lines == []
    argv = captured["argv"]
    assert argv[0] == "zfs"  # argv form, never a shell string
    # The malicious name is a single positional token (snapshot suffix appended), not parsed.
    assert f"{evil}@s1" in argv
    assert f"{evil}@s2" in argv
