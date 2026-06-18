"""FinalizeService unit tests — post-drain rollup recompute, scoped to the calling host.

Covers the server side of the rollup-finalize wiring (ADD 09 §8):
- a host with a freshly-ingested volume and no rollup yet → finalize recomputes it (and the
  tree/treemap now have subtree sizes + a size_history point);
- the recompute is scoped to the CALLING host's fingerprint — another host's volume is never
  touched (AR-0012);
- a re-finalize with nothing new since last time is a no-op (idempotent / cheap to repeat);
- a new snapshot after a rollup makes the volume stale again → the next finalize recomputes it;
- an unknown fingerprint finalizes nothing (it has ingested nothing).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.core.catalogue.models import (
    Base,
    FsEntryRow,
    Host,
    SizeHistory,
    Snapshot,
    SubtreeRollup,
    Volume,
)
from fathom.core.finalize import FinalizeService

_T0 = datetime(2026, 6, 6, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _seed_host(s: AsyncSession, *, name: str, fingerprint: str) -> Host:
    host = Host(name=name, cert_fingerprint=fingerprint)
    s.add(host)
    await s.flush()
    return host


async def _seed_volume_with_entries(
    s: AsyncSession, *, host: Host, mount: str, snapshot_at: datetime
) -> Volume:
    """Seed a volume with a tiny tree (mount/dir/file) and one snapshot at ``snapshot_at``."""
    vol = Volume(host_id=host.id, mountpoint=mount, fs_type="zfs", device="tank", transport="sata")
    s.add(vol)
    await s.flush()
    s.add(Snapshot(host_id=host.id, volume_id=vol.id, mode="metadata", started=snapshot_at))
    s.add_all(
        [
            FsEntryRow(
                host_id=host.id, volume_id=vol.id, path=mount, name="pool", inode=1, is_dir=True
            ),
            FsEntryRow(
                host_id=host.id,
                volume_id=vol.id,
                path=f"{mount}/d",
                name="d",
                inode=2,
                is_dir=True,
            ),
            FsEntryRow(
                host_id=host.id,
                volume_id=vol.id,
                path=f"{mount}/d/f",
                name="f",
                inode=3,
                size_logical=100,
                size_on_disk=128,
            ),
        ]
    )
    await s.flush()
    return vol


async def test_finalize_recomputes_rollups_for_host_volume(session: AsyncSession) -> None:
    host = await _seed_host(session, name="nas-1", fingerprint="fp-nas-1")
    vol = await _seed_volume_with_entries(session, host=host, mount="/mnt/pool", snapshot_at=_T0)

    result = await FinalizeService(session).finalize_host(cert_fingerprint="fp-nas-1")

    assert result.host_id == host.id
    assert result.volume_ids == [vol.id]
    assert result.rollup_rows > 0
    # The mount + the 'd' dir got rollup rows; the mount's rollup totals the whole subtree.
    rollups = (
        (await session.execute(select(SubtreeRollup).where(SubtreeRollup.volume_id == vol.id)))
        .scalars()
        .all()
    )
    by_path = {r.path: r for r in rollups}
    assert by_path["/mnt/pool"].total_size_logical == 100
    assert by_path["/mnt/pool"].file_count == 1
    # recompute_full also appended a size_history point for the volume root.
    hist = (
        await session.execute(
            select(func.count()).select_from(SizeHistory).where(SizeHistory.volume_id == vol.id)
        )
    ).scalar_one()
    assert hist == 1


async def test_finalize_is_scoped_to_the_calling_host(session: AsyncSession) -> None:
    host_a = await _seed_host(session, name="nas-1", fingerprint="fp-a")
    host_b = await _seed_host(session, name="worker-1", fingerprint="fp-b")
    vol_a = await _seed_volume_with_entries(session, host=host_a, mount="/mnt/a", snapshot_at=_T0)
    vol_b = await _seed_volume_with_entries(session, host=host_b, mount="/mnt/b", snapshot_at=_T0)

    result = await FinalizeService(session).finalize_host(cert_fingerprint="fp-a")

    assert result.volume_ids == [vol_a.id]
    # host_b's volume must NOT have been recomputed (no rollup rows for it).
    b_rollups = (
        await session.execute(
            select(func.count())
            .select_from(SubtreeRollup)
            .where(SubtreeRollup.volume_id == vol_b.id)
        )
    ).scalar_one()
    assert b_rollups == 0


async def test_finalize_is_a_noop_when_nothing_new(session: AsyncSession) -> None:
    host = await _seed_host(session, name="nas-1", fingerprint="fp")
    await _seed_volume_with_entries(session, host=host, mount="/mnt/pool", snapshot_at=_T0)

    svc = FinalizeService(session)
    first = await svc.finalize_host(cert_fingerprint="fp")
    assert len(first.volume_ids) == 1
    # No new snapshot since the rollup → the second finalize recomputes nothing.
    second = await svc.finalize_host(cert_fingerprint="fp")
    assert second.volume_ids == []
    assert second.rollup_rows == 0
    # Exactly one size_history point (the first finalize), not two.
    hist = (await session.execute(select(func.count()).select_from(SizeHistory))).scalar_one()
    assert hist == 1


async def test_finalize_recomputes_again_after_a_newer_snapshot(session: AsyncSession) -> None:
    host = await _seed_host(session, name="nas-1", fingerprint="fp")
    vol = await _seed_volume_with_entries(session, host=host, mount="/mnt/pool", snapshot_at=_T0)

    svc = FinalizeService(session)
    await svc.finalize_host(cert_fingerprint="fp")
    # The rollup stamps computed_at with wall-clock now; a genuinely *later* scan lands a snapshot
    # after that → the volume is stale again. Base the new snapshot on the rollup's actual time so
    # the test is independent of the fixed seed timestamp.
    last_computed = (
        await session.execute(select(func.max(SubtreeRollup.computed_at)))
    ).scalar_one()
    session.add(
        Snapshot(
            host_id=host.id,
            volume_id=vol.id,
            mode="metadata",
            started=last_computed + timedelta(hours=1),
        )
    )
    await session.flush()

    again = await svc.finalize_host(cert_fingerprint="fp")
    assert again.volume_ids == [vol.id]


async def test_finalize_unknown_fingerprint_does_nothing(session: AsyncSession) -> None:
    result = await FinalizeService(session).finalize_host(cert_fingerprint="never-seen")
    assert result == result.__class__(host_id=0, volume_ids=[], rollup_rows=0)


async def _add_hashed_pair(s: AsyncSession, vol: Volume, host: Host) -> None:
    """Stamp the full-bit hash onto two of the volume's files so they form a dup group."""
    for inode in (2, 3):
        s.add(
            FsEntryRow(
                host_id=host.id,
                volume_id=vol.id,
                path=f"{vol.mountpoint}/dup{inode}",
                name=f"dup{inode}",
                inode=inode + 10,  # fresh identity; avoids the seeded tree's inodes
                size_logical=100,
                size_on_disk=100,
                mtime=1.0,
                ctime=1.0,
                full_hash="a" * 64,
                partial_hash="b" * 64,
            )
        )
    await s.flush()


async def test_finalize_builds_dedup_group_when_hashes_present(session: AsyncSession) -> None:
    # When the catalogue carries full hashes, finalize rebuilds the report-only dup groups inline.
    host = await _seed_host(session, name="nas-1", fingerprint="fp")
    vol = await _seed_volume_with_entries(session, host=host, mount="/mnt/pool", snapshot_at=_T0)
    await _add_hashed_pair(session, vol, host)

    result = await FinalizeService(session).finalize_host(cert_fingerprint="fp")
    assert result.dup_groups == 1


async def test_finalize_metadata_only_builds_no_groups(session: AsyncSession) -> None:
    # No full hashes anywhere → no dedup work, dup_groups == 0 (existing deployments unchanged).
    host = await _seed_host(session, name="nas-1", fingerprint="fp")
    await _seed_volume_with_entries(session, host=host, mount="/mnt/pool", snapshot_at=_T0)
    result = await FinalizeService(session).finalize_host(cert_fingerprint="fp")
    assert result.dup_groups == 0


async def test_finalize_build_dedup_flag_disables_inline_grouping(session: AsyncSession) -> None:
    # A deployment driving dedup from the arq queue can turn the inline rebuild off.
    host = await _seed_host(session, name="nas-1", fingerprint="fp")
    vol = await _seed_volume_with_entries(session, host=host, mount="/mnt/pool", snapshot_at=_T0)
    await _add_hashed_pair(session, vol, host)

    result = await FinalizeService(session, build_dedup=False).finalize_host(cert_fingerprint="fp")
    assert result.dup_groups == 0
