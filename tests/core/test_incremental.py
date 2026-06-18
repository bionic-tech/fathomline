"""ChangeReconciler + prune_change_log unit tests (incremental test_plan).

Covers the server-side incremental reconciliation:
- CREATE vs MODIFY classification (new inode, changed size/mtime, unchanged → no churn);
- explicit DELETE via removed_inodes flips present=False + removed_at and emits a DELETE churn row
  with a negative size_delta (NOT snapshot-staleness inference);
- resurrection: a previously-removed inode re-appearing classifies CREATE;
- feed-disabled volume writes NO change_log rows but still maintains presence markers;
- a duplicate removal in a later cycle is a no-op (no double-count, no re-stamp);
- prune_change_log honours the retention window and rejects a bad window.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.core.catalogue.models import Base, ChangeLog, FsEntryRow, Host, Volume
from fathom.core.incremental import (
    CHANGE_LOG_RETENTION_DAYS,
    ChangeReconciler,
    prune_change_log,
)

_T0 = datetime(2026, 6, 6, 12, 0, 0, tzinfo=UTC)


def _naive(value: datetime | None) -> datetime | None:
    """SQLite drops tz on readback; normalise both sides to naive for comparison."""
    return value.replace(tzinfo=None) if value is not None else None


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _seed_volume(s: AsyncSession, *, change_log_enabled: bool = True) -> Volume:
    host = Host(name="h", cert_fingerprint="fp")
    s.add(host)
    await s.flush()
    vol = Volume(
        host_id=host.id,
        mountpoint="/mnt/pool",
        fs_type="zfs",
        device="tank",
        transport="sata",
        total=0,
        used=0,
        free=0,
        change_log_enabled=change_log_enabled,
    )
    s.add(vol)
    await s.flush()
    return vol


async def _add_entry(
    s: AsyncSession,
    vol: Volume,
    *,
    inode: int,
    path: str,
    size: int,
    mtime: float,
    present: bool = True,
    removed_at: datetime | None = None,
) -> FsEntryRow:
    row = FsEntryRow(
        host_id=vol.host_id,
        volume_id=vol.id,
        name=path.rsplit("/", 1)[-1],
        path=path,
        depth=1,
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
        present=present,
        removed_at=removed_at,
    )
    s.add(row)
    await s.flush()
    return row


def _row(inode: int, path: str, *, size: int, mtime: float) -> dict[str, object]:
    return {"inode": inode, "path": path, "size_logical": size, "mtime": mtime}


async def _churn(s: AsyncSession) -> list[ChangeLog]:
    return list((await s.execute(select(ChangeLog).order_by(ChangeLog.id))).scalars().all())


async def test_create_modify_unchanged_classification(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    # Pre-existing, present row for inode 1 (will be MODIFY); inode 2 is brand-new (CREATE);
    # inode 3 is present and unchanged (no churn).
    await _add_entry(session, vol, inode=1, path="/mnt/pool/a", size=100, mtime=1000.0)
    await _add_entry(session, vol, inode=3, path="/mnt/pool/c", size=50, mtime=1000.0)
    rec = ChangeReconciler(session)
    rows = [
        _row(1, "/mnt/pool/a", size=200, mtime=2000.0),  # modify (size+mtime changed)
        _row(2, "/mnt/pool/b", size=10, mtime=1000.0),  # create (new inode)
        _row(3, "/mnt/pool/c", size=50, mtime=1000.0),  # unchanged → no churn
    ]
    prior = await rec.snapshot_prior(host_id=vol.host_id, volume_id=vol.id, inodes=[1, 2, 3])
    result = await rec.reconcile(
        host_id=vol.host_id,
        volume_id=vol.id,
        rows=rows,
        prior=prior,
        removed_inodes=[],
        log_changes=True,
        now=_T0,
    )
    assert result.changes_logged == 2
    churn = await _churn(session)
    by_path = {c.path: c for c in churn}
    assert by_path["/mnt/pool/a"].change_type == "modify"
    assert by_path["/mnt/pool/a"].size_delta == 100  # 200 - 100
    assert by_path["/mnt/pool/b"].change_type == "create"
    assert by_path["/mnt/pool/b"].size_delta == 10
    assert "/mnt/pool/c" not in by_path


async def test_explicit_delete_marks_not_present_with_negative_delta(
    session: AsyncSession,
) -> None:
    vol = await _seed_volume(session)
    await _add_entry(session, vol, inode=1, path="/mnt/pool/gone", size=512, mtime=1000.0)
    rec = ChangeReconciler(session)
    result = await rec.reconcile(
        host_id=vol.host_id,
        volume_id=vol.id,
        rows=[],
        prior={},
        removed_inodes=[1],
        log_changes=True,
        now=_T0,
    )
    assert result.removed == 1
    entry = (await session.execute(select(FsEntryRow).where(FsEntryRow.inode == 1))).scalar_one()
    # Soft-deleted, NOT removed: the row survives so its history does (incremental ruling).
    assert entry.present is False
    assert _naive(entry.removed_at) == _T0.replace(tzinfo=None)
    churn = await _churn(session)
    assert len(churn) == 1
    assert churn[0].change_type == "delete"
    assert churn[0].size_delta == -512


async def test_resurrection_of_removed_inode_is_create(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    # An inode previously removed (present=False) re-appears; classification must be CREATE.
    await _add_entry(
        session,
        vol,
        inode=7,
        path="/mnt/pool/back",
        size=64,
        mtime=1000.0,
        present=False,
        removed_at=_T0 - timedelta(days=1),
    )
    rec = ChangeReconciler(session)
    prior = await rec.snapshot_prior(host_id=vol.host_id, volume_id=vol.id, inodes=[7])
    result = await rec.reconcile(
        host_id=vol.host_id,
        volume_id=vol.id,
        rows=[_row(7, "/mnt/pool/back", size=64, mtime=1000.0)],
        prior=prior,
        removed_inodes=[],
        log_changes=True,
        now=_T0,
    )
    assert result.changes_logged == 1
    churn = await _churn(session)
    assert churn[0].change_type == "create"


async def test_feed_disabled_writes_no_change_log_but_keeps_markers(
    session: AsyncSession,
) -> None:
    vol = await _seed_volume(session, change_log_enabled=False)
    await _add_entry(session, vol, inode=1, path="/mnt/pool/x", size=100, mtime=1000.0)
    rec = ChangeReconciler(session)
    prior = await rec.snapshot_prior(host_id=vol.host_id, volume_id=vol.id, inodes=[1])
    result = await rec.reconcile(
        host_id=vol.host_id,
        volume_id=vol.id,
        rows=[_row(2, "/mnt/pool/y", size=5, mtime=1000.0)],  # a create
        prior=prior,
        removed_inodes=[1],  # a delete
        log_changes=False,
        now=_T0,
    )
    # Presence markers are still maintained (removal applied)…
    assert result.removed == 1
    # …but NO churn rows are written when the per-volume feed is off.
    assert result.changes_logged == 0
    assert await _churn(session) == []


async def test_duplicate_removal_is_noop(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    await _add_entry(session, vol, inode=1, path="/mnt/pool/gone", size=100, mtime=1000.0)
    rec = ChangeReconciler(session)
    first = await rec.reconcile(
        host_id=vol.host_id,
        volume_id=vol.id,
        rows=[],
        prior={},
        removed_inodes=[1],
        log_changes=True,
        now=_T0,
    )
    assert first.removed == 1
    later = _T0 + timedelta(hours=1)
    second = await rec.reconcile(
        host_id=vol.host_id,
        volume_id=vol.id,
        rows=[],
        prior={},
        removed_inodes=[1],  # already removed → no-op
        log_changes=True,
        now=later,
    )
    assert second.removed == 0
    assert second.changes_logged == 0  # no second DELETE churn row
    entry = (await session.execute(select(FsEntryRow).where(FsEntryRow.inode == 1))).scalar_one()
    assert _naive(entry.removed_at) == _T0.replace(tzinfo=None)  # not re-stamped


async def test_prune_change_log_respects_window(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    old = ChangeLog(
        volume_id=vol.id,
        path="/mnt/pool/old",
        change_type="create",
        size_delta=1,
        ts=_T0 - timedelta(days=CHANGE_LOG_RETENTION_DAYS + 1),
    )
    fresh = ChangeLog(
        volume_id=vol.id,
        path="/mnt/pool/new",
        change_type="create",
        size_delta=1,
        ts=_T0 - timedelta(days=1),
    )
    session.add_all([old, fresh])
    await session.flush()
    removed = await prune_change_log(session, now=_T0)
    assert removed == 1
    remaining = await _churn(session)
    assert [c.path for c in remaining] == ["/mnt/pool/new"]


async def test_prune_change_log_rejects_bad_window(session: AsyncSession) -> None:
    with pytest.raises(ValueError, match="retention_days"):
        await prune_change_log(session, retention_days=0)
