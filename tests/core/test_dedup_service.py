"""DedupService tests — full-hash-confirmed grouping, reclaimable, keeper rank, report-only.

Covers the fullbit-dedup test_plan core cases:
- groups form only on a full BLAKE3 match (size-equal/partial-equal-but-full-different not
  grouped) — the named ``test_dedup_full_hash_confirm_required`` (file-mgmt §5.7);
- ``reclaimable_bytes = size * (members - 1)`` and the non-binding keeper rank/reason;
- the service is report-only: it writes only report tables and makes no filesystem change.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.core.catalogue.models import Base, DupGroup, DupMember, FsEntryRow, Host, Volume
from fathom.core.dedup_service import (
    DedupScope,
    DedupService,
    EntryRef,
    rank_oldest_then_preferred_then_shortest,
)


def _h(suffix: str) -> str:
    return (suffix * 64)[:64]


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _seed_volume(s: AsyncSession, *, mountpoint: str = "/mnt/pool") -> Volume:
    host = Host(name=f"host-{mountpoint}", cert_fingerprint=f"fp-{mountpoint}")
    s.add(host)
    await s.flush()
    vol = Volume(
        host_id=host.id,
        mountpoint=mountpoint,
        fs_type="zfs",
        device="tank",
        transport="sata",
        total=0,
        used=0,
        free=0,
    )
    s.add(vol)
    await s.flush()
    return vol


async def _add_entry(
    s: AsyncSession,
    vol: Volume,
    *,
    path: str,
    inode: int,
    size: int,
    full_hash: str | None,
    mtime: float = 1000.0,
    ctime: float = 1000.0,
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
        ctime=ctime,
        uid=0,
        gid=0,
        inode=inode,
        full_hash=full_hash,
        partial_hash=_h("p") if full_hash else None,
        hashed_at=datetime.now(tz=UTC) if full_hash else None,
    )
    s.add(row)
    await s.flush()
    return row


async def test_dedup_full_hash_confirm_required(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    # a & b: same size, same full hash → grouped. c: same size, DIFFERENT full hash → not grouped.
    await _add_entry(session, vol, path="/mnt/pool/a", inode=1, size=100, full_hash=_h("a"))
    await _add_entry(session, vol, path="/mnt/pool/b", inode=2, size=100, full_hash=_h("a"))
    await _add_entry(session, vol, path="/mnt/pool/c", inode=3, size=100, full_hash=_h("c"))
    # d: never full-bit-hashed (NULL) → never grouped even though size matches.
    await _add_entry(session, vol, path="/mnt/pool/d", inode=4, size=100, full_hash=None)

    groups = await DedupService(session).build()
    assert len(groups) == 1
    g = groups[0]
    assert g.full_hash == _h("a")
    assert g.member_count == 2
    member_paths = {m.path for m in g.members}
    assert member_paths == {"/mnt/pool/a", "/mnt/pool/b"}


async def test_dedup_excludes_not_present_entries(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    # Two present copies + one DELETED copy, all the same full hash. The deleted entry must not be
    # a group member (and so can never be suggested as the keeper) — it no longer exists on disk.
    await _add_entry(session, vol, path="/mnt/pool/keep", inode=1, size=100, full_hash=_h("x"))
    await _add_entry(session, vol, path="/mnt/pool/dup", inode=2, size=100, full_hash=_h("x"))
    gone = await _add_entry(
        session, vol, path="/mnt/pool/deleted", inode=3, size=100, full_hash=_h("x")
    )
    gone.present = False
    await session.flush()

    groups = await DedupService(session).build()
    assert len(groups) == 1
    assert groups[0].member_count == 2
    assert {m.path for m in groups[0].members} == {"/mnt/pool/keep", "/mnt/pool/dup"}


async def test_dedup_reclaimable_bytes(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    for i in range(3):  # three identical 500-byte copies
        await _add_entry(
            session, vol, path=f"/mnt/pool/copy{i}", inode=10 + i, size=500, full_hash=_h("z")
        )
    groups = await DedupService(session).build()
    assert len(groups) == 1
    # reclaimable = size * (members - 1) = 500 * 2
    assert groups[0].reclaimable_bytes == 1000
    assert groups[0].member_count == 3


async def test_keeper_prefers_oldest(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    old = await _add_entry(
        session, vol, path="/mnt/pool/deep/old", inode=20, size=42, full_hash=_h("k"), mtime=100.0
    )
    await _add_entry(
        session, vol, path="/mnt/pool/new", inode=21, size=42, full_hash=_h("k"), mtime=900.0
    )
    groups = await DedupService(session).build()
    g = groups[0]
    # Oldest copy wins even though its path is deeper/longer (rank step 1).
    assert g.suggested_keeper_entry_id == old.id
    assert g.suggested_keeper_reason == "oldest copy"


def test_keeper_tie_breaks_preferred_then_shortest() -> None:
    # All same age → step (2) preferred volume, then step (3) shortest path.
    members = [
        EntryRef(
            1,
            host_id=1,
            volume_id=9,
            path="/a/very/deep/path",
            size=1,
            mtime=5,
            ctime=5,
            full_hash=_h("t"),
        ),
        EntryRef(
            2, host_id=1, volume_id=7, path="/a/short", size=1, mtime=5, ctime=5, full_hash=_h("t")
        ),
        EntryRef(
            3, host_id=1, volume_id=7, path="/a/b/c", size=1, mtime=5, ctime=5, full_hash=_h("t")
        ),
    ]
    scope = DedupScope(preferred_volume_ids=frozenset({7}))
    choice = rank_oldest_then_preferred_then_shortest(members, scope)
    # Preferred volume 7 has two members; shortest path among them is /a/short.
    assert choice.entry_id == 2
    assert "preferred" in choice.reason


async def test_dedup_is_report_only(session: AsyncSession, tmp_path) -> None:  # type: ignore[no-untyped-def]
    # The service must touch no filesystem: create a real file and assert it is untouched.
    victim = tmp_path / "must_not_be_deleted.bin"
    victim.write_bytes(b"keepme")
    vol = await _seed_volume(session)
    await _add_entry(session, vol, path=str(victim), inode=30, size=6, full_hash=_h("r"))
    await _add_entry(
        session, vol, path=str(tmp_path / "copy.bin"), inode=31, size=6, full_hash=_h("r")
    )
    groups = await DedupService(session).build()
    assert len(groups) == 1
    # Report-only: the actual files on disk are never opened, moved, or deleted.
    assert victim.exists()
    assert victim.read_bytes() == b"keepme"


async def test_dedup_estate_wide_across_volumes(session: AsyncSession) -> None:
    # The server groups identical hashes ACROSS hosts/volumes (owner ruling: server groups
    # by full_hash across hosts).
    v1 = await _seed_volume(session, mountpoint="/mnt/a")
    v2 = await _seed_volume(session, mountpoint="/mnt/b")
    await _add_entry(session, v1, path="/mnt/a/f", inode=40, size=10, full_hash=_h("x"))
    await _add_entry(session, v2, path="/mnt/b/f", inode=41, size=10, full_hash=_h("x"))
    groups = await DedupService(session).build()
    assert len(groups) == 1
    hosts = {m.host_id for m in groups[0].members}
    assert len(hosts) == 2  # cross-host group


async def test_dedup_scope_restricts_to_volume(session: AsyncSession) -> None:
    v1 = await _seed_volume(session, mountpoint="/mnt/a")
    v2 = await _seed_volume(session, mountpoint="/mnt/b")
    # A pair unique to v1 and a cross-volume pair: scoping to v1 only must drop the v2 member.
    await _add_entry(session, v1, path="/mnt/a/x1", inode=50, size=10, full_hash=_h("s"))
    await _add_entry(session, v1, path="/mnt/a/x2", inode=51, size=10, full_hash=_h("s"))
    await _add_entry(session, v2, path="/mnt/b/x", inode=52, size=10, full_hash=_h("s"))
    groups = await DedupService(session).build(scope=DedupScope(volume_ids=frozenset({v1.id})))
    assert len(groups) == 1
    assert all(m.volume_id == v1.id for m in groups[0].members)
    assert groups[0].member_count == 2


async def test_dedup_rebuild_is_idempotent(session: AsyncSession) -> None:
    vol = await _seed_volume(session)
    await _add_entry(session, vol, path="/mnt/pool/a", inode=60, size=10, full_hash=_h("i"))
    await _add_entry(session, vol, path="/mnt/pool/b", inode=61, size=10, full_hash=_h("i"))
    svc = DedupService(session)
    await svc.build()
    await svc.build()  # same scope → replaces, does not double
    total_groups = len((await session.execute(select(DupGroup))).all())
    total_members = len((await session.execute(select(DupMember))).all())
    assert total_groups == 1
    assert total_members == 2


async def _seed_volume_fs(
    s: AsyncSession, *, mountpoint: str, fs_type: str, transport: str = "sata"
) -> Volume:
    """Seed a volume with an explicit fs_type (drives cross-mount alias detection)."""
    host = Host(name=f"host-{mountpoint}", cert_fingerprint=f"fp-{mountpoint}")
    s.add(host)
    await s.flush()
    vol = Volume(
        host_id=host.id,
        mountpoint=mountpoint,
        fs_type=fs_type,
        device="dev",
        transport=transport,
        total=0,
        used=0,
        free=0,
    )
    s.add(vol)
    await s.flush()
    return vol


async def test_network_mount_member_is_aliased_and_not_reclaimable(session: AsyncSession) -> None:
    # The cross-mount false positive: the SAME physical file hashed natively (e.g. node-1, zfs)
    # AND via its NFS mount on another host (e.g. nas-1, nfs) shares one full_hash. The nfs member
    # is a remote VIEW, not a reclaimable copy — flag it and exclude it from reclaimable (ADR-002).
    native = await _seed_volume_fs(session, mountpoint="/mnt/pool", fs_type="zfs")
    nfs = await _seed_volume_fs(session, mountpoint="/scan/ncdata", fs_type="nfs")
    h = _h("a")
    # Make the ALIAS the older copy, to prove the keeper still prefers a native over an alias.
    await _add_entry(
        session, native, path="/mnt/pool/a", inode=1, size=100, full_hash=h, mtime=2000
    )
    await _add_entry(session, nfs, path="/scan/ncdata/a", inode=2, size=100, full_hash=h, mtime=500)

    groups = await DedupService(session).build()
    assert len(groups) == 1
    g = groups[0]
    assert g.member_count == 2
    assert g.reclaimable_bytes == 0  # 1 native + 1 alias → nothing reclaimable
    members = {m.path: m for m in g.members}
    assert members["/scan/ncdata/a"].is_mount_alias is True
    assert members["/mnt/pool/a"].is_mount_alias is False
    # Keeper is the NATIVE copy even though the alias is older (an alias is never a keeper).
    assert g.suggested_keeper_entry_id == members["/mnt/pool/a"].entry_id


async def test_two_native_copies_still_reclaimable(session: AsyncSession) -> None:
    # Regression: a genuine cross-host duplicate (two NATIVE copies) is still fully reclaimable and
    # neither member is flagged as an alias.
    a = await _seed_volume_fs(session, mountpoint="/mnt/a", fs_type="zfs")
    b = await _seed_volume_fs(session, mountpoint="/mnt/b", fs_type="ext4")
    h = _h("b")
    await _add_entry(session, a, path="/mnt/a/f", inode=1, size=100, full_hash=h)
    await _add_entry(session, b, path="/mnt/b/f", inode=2, size=100, full_hash=h)

    groups = await DedupService(session).build()
    assert len(groups) == 1
    assert groups[0].reclaimable_bytes == 100  # size * (2 native - 1)
    assert all(not m.is_mount_alias for m in groups[0].members)


async def test_all_alias_group_reclaims_nothing(session: AsyncSession) -> None:
    # Two NFS/SMB mounts of the same export (the native host is not scanned): all members are
    # aliases → nothing reclaimable, all flagged (we cannot reclaim via a mount view).
    n1 = await _seed_volume_fs(session, mountpoint="/scan/m1", fs_type="nfs4")
    n2 = await _seed_volume_fs(session, mountpoint="/scan/m2", fs_type="cifs")
    h = _h("c")
    await _add_entry(session, n1, path="/scan/m1/f", inode=1, size=100, full_hash=h)
    await _add_entry(session, n2, path="/scan/m2/f", inode=2, size=100, full_hash=h)

    groups = await DedupService(session).build()
    assert len(groups) == 1
    assert groups[0].reclaimable_bytes == 0
    assert all(m.is_mount_alias for m in groups[0].members)
