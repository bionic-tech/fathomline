"""Concierge query tests (ADR-035) — last-seen/deleted lookup, hot folders, fleet storage, scope.

These cover the scope-enforcing catalogue "tools" the concierge dispatches to: that a soft-deleted
file is still findable with its ``removed_at`` + last-catalogued time, that hot-folder ranking
excludes OS (``kind='system'``) volumes, that fleet storage rolls up per host with disk types, and
— the security core — that an out-of-scope host/volume never appears in any result.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.models import (
    Base,
    ChangeLog,
    FsEntryRow,
    Host,
    SizeHistory,
    Snapshot,
    Volume,
)
from fathom.core.concierge import queries


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _host(session: AsyncSession, name: str) -> Host:
    host = Host(name=name, cert_fingerprint=f"fp:{name}")
    session.add(host)
    await session.flush()
    return host


async def _volume(
    session: AsyncSession,
    host: Host,
    mountpoint: str,
    *,
    fs_type: str = "zfs",
    kind: str = "data",
    total: int = 1000,
    used: int = 400,
    free: int = 600,
) -> Volume:
    vol = Volume(
        host_id=host.id,
        mountpoint=mountpoint,
        fs_type=fs_type,
        device="dev",
        transport="sata",
        kind=kind,
        total=total,
        used=used,
        free=free,
    )
    session.add(vol)
    await session.flush()
    return vol


async def _entry(
    session: AsyncSession,
    vol: Volume,
    path: str,
    inode: int,
    *,
    present: bool = True,
    removed_at: datetime | None = None,
    last_seen_snapshot_id: int | None = None,
    size: int = 100,
) -> FsEntryRow:
    row = FsEntryRow(
        host_id=vol.host_id,
        volume_id=vol.id,
        name=path.rsplit("/", 1)[-1],
        path=path,
        inode=inode,
        size_logical=size,
        size_on_disk=size,
        present=present,
        removed_at=removed_at,
        last_seen_snapshot_id=last_seen_snapshot_id,
    )
    session.add(row)
    await session.flush()
    return row


# --- find_last_seen: the "I can't find this file" answer ---------------------------------


async def test_find_last_seen_surfaces_deleted_with_timestamps(session: AsyncSession) -> None:
    host = await _host(session, "nas-1")
    vol = await _volume(session, host, "/mnt/data")
    seen_at = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    snap = Snapshot(host_id=host.id, volume_id=vol.id, mode="metadata", finished=seen_at)
    session.add(snap)
    await session.flush()
    removed = datetime(2026, 6, 12, 9, 30, tzinfo=UTC)
    await _entry(
        session,
        vol,
        "/mnt/data/budget.xlsx",
        inode=11,
        present=False,
        removed_at=removed,
        last_seen_snapshot_id=snap.id,
    )

    hits = await queries.find_last_seen(session, name_or_fragment="budget")
    assert len(hits) == 1
    hit = hits[0]
    assert hit.present is False
    # SQLite stores no tz, so compare naive wall-clock values (the value, not the tzinfo).
    assert hit.removed_at is not None
    assert hit.removed_at.replace(tzinfo=None) == removed.replace(tzinfo=None)
    assert hit.last_seen_at is not None
    assert hit.last_seen_at.replace(tzinfo=None) == seen_at.replace(tzinfo=None)


async def test_find_last_seen_orders_deleted_first(session: AsyncSession) -> None:
    host = await _host(session, "nas-1")
    vol = await _volume(session, host, "/mnt/data")
    await _entry(session, vol, "/mnt/data/report.xlsx", inode=1, present=True)
    await _entry(
        session,
        vol,
        "/mnt/data/old.xlsx",
        inode=2,
        present=False,
        removed_at=datetime(2026, 6, 12, tzinfo=UTC),
    )
    hits = await queries.find_last_seen(session, name_or_fragment="xlsx")
    assert [h.name for h in hits] == ["old.xlsx", "report.xlsx"]  # deleted first

    only_deleted = await queries.find_last_seen(
        session, name_or_fragment="xlsx", include_present=False
    )
    assert [h.name for h in only_deleted] == ["old.xlsx"]


async def test_find_last_seen_scope_hides_out_of_scope(session: AsyncSession) -> None:
    host_a = await _host(session, "nas-1")
    host_b = await _host(session, "nas-2")
    vol_a = await _volume(session, host_a, "/mnt/a")
    vol_b = await _volume(session, host_b, "/mnt/b")
    await _entry(session, vol_a, "/mnt/a/secret.txt", inode=1)
    await _entry(session, vol_b, "/mnt/b/secret.txt", inode=2)

    scope = ScopeFilter(is_global=False, volume_ids=frozenset({vol_a.id}))
    hits = await queries.find_last_seen(session, name_or_fragment="secret", scope=scope)
    assert [h.volume_id for h in hits] == [vol_a.id]  # vol_b never leaks


# --- hot_folders: non-OS churn ranking --------------------------------------------------


async def test_hot_folders_excludes_system_and_ranks(session: AsyncSession) -> None:
    host = await _host(session, "nas-1")
    data = await _volume(session, host, "/mnt/data", kind="data")
    system = await _volume(session, host, "/", kind="system")
    now = datetime(2026, 6, 18, 12, 0, tzinfo=UTC)
    # media/ churns 3x, docs/ once; the OS volume churns a lot but must be excluded.
    for i in range(3):
        session.add(
            ChangeLog(
                volume_id=data.id,
                path=f"/mnt/data/media/film{i}.mkv",
                change_type="modify",
                size_delta=10,
                ts=now - timedelta(hours=i),
            )
        )
    session.add(
        ChangeLog(
            volume_id=data.id,
            path="/mnt/data/docs/a.txt",
            change_type="create",
            size_delta=5,
            ts=now,
        )
    )
    for i in range(5):
        session.add(
            ChangeLog(
                volume_id=system.id,
                path=f"/var/log/sys{i}.log",
                change_type="modify",
                size_delta=1,
                ts=now,
            )
        )
    await session.flush()

    folders = await queries.hot_folders(session, since=now - timedelta(days=1))
    paths = [f.path for f in folders]
    assert "/mnt/data/media" in paths
    assert "/mnt/data/docs" in paths
    assert all(not p.startswith("/var") for p in paths)  # system volume excluded
    assert folders[0].path == "/mnt/data/media"  # most-changed first
    assert folders[0].change_count == 3


# --- fleet_storage: per-host roll-up of space + disk types -------------------------------


async def test_fleet_storage_rolls_up_per_host(session: AsyncSession) -> None:
    host_a = await _host(session, "nas-1")
    host_b = await _host(session, "nas-2")
    await _volume(session, host_a, "/mnt/a1", fs_type="zfs", total=1000, used=600, free=400)
    await _volume(session, host_a, "/mnt/a2", fs_type="xfs", total=500, used=100, free=400)
    await _volume(session, host_b, "/mnt/b1", fs_type="ext4", total=2000, used=1500, free=500)

    hosts = await queries.fleet_storage(session)
    by_name = {h.host_name: h for h in hosts}
    assert by_name["nas-1"].total == 1500
    assert by_name["nas-1"].free == 800
    assert {v.fs_type for v in by_name["nas-1"].volumes} == {"zfs", "xfs"}
    assert by_name["nas-2"].total == 2000


async def test_fleet_storage_scope_filters_hosts(session: AsyncSession) -> None:
    host_a = await _host(session, "nas-1")
    host_b = await _host(session, "nas-2")
    await _volume(session, host_a, "/mnt/a1")
    await _volume(session, host_b, "/mnt/b1")
    scope = ScopeFilter(is_global=False, host_ids=frozenset({host_a.id}))
    hosts = await queries.fleet_storage(session, scope=scope)
    assert [h.host_name for h in hosts] == ["nas-1"]


# --- growth_forecast: linear days-to-full -----------------------------------------------


async def test_growth_forecast_projects_days_to_full(session: AsyncSession) -> None:
    host = await _host(session, "nas-1")
    vol = await _volume(session, host, "/mnt/data", free=1000)
    now = datetime(2026, 6, 18, tzinfo=UTC)
    # +100 bytes/day over 5 days.
    for d in range(5):
        session.add(
            SizeHistory(
                volume_id=vol.id,
                path="/mnt/data",
                ts=now - timedelta(days=4 - d),
                total_size_on_disk=100 * d,
            )
        )
    await session.flush()
    fc = await queries.growth_forecast(
        session, volume_id=vol.id, path="/mnt/data", lookback_days=30, now=now
    )
    assert fc is not None
    assert fc.daily_growth_bytes == pytest.approx(100.0, rel=0.01)
    assert fc.days_to_full == pytest.approx(10.0, rel=0.05)  # 1000 free / 100 per day


async def test_growth_forecast_none_without_history(session: AsyncSession) -> None:
    host = await _host(session, "nas-1")
    vol = await _volume(session, host, "/mnt/data")
    fc = await queries.growth_forecast(session, volume_id=vol.id, path="/mnt/data")
    assert fc is None  # <2 points → no forecast
