"""Provider-hash duplicate grouping (ADR-028 phase 2) — read-only, zero-egress dedup."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.core.catalogue.models import Base, FsEntryRow, Host, Volume
from fathom.core.provider_dedup import (
    find_provider_hash_duplicates,
    iter_provider_hash_duplicates,
)


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _seed_volume(s: AsyncSession, vid: int) -> None:
    s.add(Host(id=vid, name=f"h{vid}", cert_fingerprint=f"fp{vid}"))
    s.add(
        Volume(
            id=vid,
            host_id=vid,
            mountpoint=f"rclone://r{vid}/",
            fs_type="rclone",
            device=f"r{vid}:",
            transport="network",
            total=0,
            used=0,
            free=0,
        )
    )


def _entry(
    eid: int,
    vid: int,
    path: str,
    size: int,
    *,
    algo: str | None = None,
    phash: str | None = None,
) -> FsEntryRow:
    return FsEntryRow(
        id=eid,
        host_id=vid,
        volume_id=vid,
        name=path.rsplit("/", 1)[-1],
        path=path,
        inode=eid,
        size_logical=size,
        size_on_disk=size,
        provider_hash=phash,
        provider_hash_algo=algo,
    )


async def test_groups_same_provider_hash_across_volumes(session: AsyncSession) -> None:
    await _seed_volume(session, 1)
    await _seed_volume(session, 2)
    # Same md5 + size on two different cloud remotes → one duplicate group of 2 (zero egress).
    session.add(_entry(1, 1, "/a.bin", 100, algo="md5", phash="a" * 32))
    session.add(_entry(2, 2, "/b.bin", 100, algo="md5", phash="a" * 32))
    session.add(_entry(3, 1, "/c.bin", 50, algo="md5", phash="b" * 32))  # lone hash
    session.add(_entry(4, 1, "/d.bin", 100))  # no provider hash → ignored
    await session.flush()

    groups = await find_provider_hash_duplicates(session)

    assert len(groups) == 1
    g = groups[0]
    assert g.algo == "md5" and g.provider_hash == "a" * 32 and g.size == 100
    assert {m.entry_id for m in g.members} == {1, 2}
    assert g.reclaimable_bytes == 100  # one copy kept, one reclaimable


async def test_different_algos_never_compared(session: AsyncSession) -> None:
    await _seed_volume(session, 1)
    # Same hex but different algorithms must NOT group (md5 vs sha1 are incomparable).
    session.add(_entry(1, 1, "/a", 10, algo="md5", phash="f" * 32))
    session.add(_entry(2, 1, "/b", 10, algo="sha1", phash="f" * 32))
    await session.flush()
    assert await find_provider_hash_duplicates(session) == []


async def test_same_hash_different_size_not_grouped(session: AsyncSession) -> None:
    await _seed_volume(session, 1)
    session.add(_entry(1, 1, "/a", 10, algo="md5", phash="c" * 32))
    session.add(_entry(2, 1, "/b", 20, algo="md5", phash="c" * 32))
    await session.flush()
    assert await find_provider_hash_duplicates(session) == []


async def test_volume_scope_filter(session: AsyncSession) -> None:
    await _seed_volume(session, 1)
    await _seed_volume(session, 2)
    session.add(_entry(1, 1, "/a", 100, algo="md5", phash="e" * 32))
    session.add(_entry(2, 2, "/b", 100, algo="md5", phash="e" * 32))
    await session.flush()
    # Restricting to volume 1 drops the pair below the duplicate threshold.
    assert await find_provider_hash_duplicates(session, volume_ids=[1]) == []
    assert await find_provider_hash_duplicates(session, volume_ids=[]) == []  # empty scope
    assert len(await find_provider_hash_duplicates(session, volume_ids=[1, 2])) == 1


async def test_iter_variant_yields_groups_one_at_a_time(session: AsyncSession) -> None:
    # The bounded generator (for estate-scale API use) yields the same groups as the list wrapper.
    await _seed_volume(session, 1)
    session.add(_entry(1, 1, "/a", 100, algo="md5", phash="a" * 32))
    session.add(_entry(2, 1, "/b", 100, algo="md5", phash="a" * 32))
    session.add(_entry(3, 1, "/c", 100, algo="md5", phash="z" * 32))  # singleton, not yielded
    await session.flush()

    seen = [g async for g in iter_provider_hash_duplicates(session)]
    assert len(seen) == 1
    assert {m.entry_id for m in seen[0].members} == {1, 2}
    # Empty scope short-circuits the generator (yields nothing).
    assert [g async for g in iter_provider_hash_duplicates(session, volume_ids=[])] == []
