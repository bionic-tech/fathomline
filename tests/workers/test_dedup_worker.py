"""Dedup worker tests — the 'dedup' task body builds groups post-ingest (ADD 02 §7.1).

The task is a thin wrapper over :class:`DedupService` (documented design choice: no broker
dependency in the gate). These tests exercise the shared body :func:`run_dedup` and the arq
entrypoint :func:`dedup_task` against a real (temp SQLite) catalogue.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fathom.core import db
from fathom.core.catalogue.models import Base, FsEntryRow, Host, Volume
from fathom.core.dedup_service import DedupScope
from fathom.core.settings import Settings
from fathom.workers.dedup import dedup_task, run_dedup


def _h(suffix: str) -> str:
    return (suffix * 64)[:64]


@pytest.fixture
async def catalogue(tmp_path: Path) -> AsyncIterator[int]:
    """A temp catalogue with two identical full-bit-hashed entries; yields the volume id."""
    await db.dispose_engine()
    engine = db.init_engine(Settings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'c.db'}"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with db.session_scope() as session:
        host = Host(name="nas-1", cert_fingerprint="fp")
        session.add(host)
        await session.flush()
        vol = Volume(
            host_id=host.id,
            mountpoint="/mnt/pool",
            fs_type="zfs",
            device="tank",
            transport="sata",
            total=0,
            used=0,
            free=0,
        )
        session.add(vol)
        await session.flush()
        for i in range(2):
            session.add(
                FsEntryRow(
                    host_id=host.id,
                    volume_id=vol.id,
                    name=f"f{i}",
                    path=f"/mnt/pool/f{i}",
                    depth=1,
                    is_dir=False,
                    is_symlink=False,
                    size_logical=100,
                    size_on_disk=100,
                    mtime=1.0,
                    ctime=1.0,
                    uid=0,
                    gid=0,
                    inode=i,
                    full_hash=_h("a"),
                    partial_hash=_h("p"),
                    hashed_at=datetime.now(tz=UTC),
                )
            )
        volume_id = vol.id
    yield volume_id
    await db.dispose_engine()


async def test_run_dedup_builds_groups(catalogue: int) -> None:
    n = await run_dedup(DedupScope(volume_ids=frozenset({catalogue})), job_id="job-1")
    assert n == 1


async def test_dedup_task_entrypoint(catalogue: int) -> None:
    # The arq entrypoint reconstructs the scope from volume_ids and runs the same body.
    n = await dedup_task({}, volume_ids=[catalogue], job_id="arq-job")
    assert n == 1


async def test_run_dedup_estate_wide_default(catalogue: int) -> None:
    # No scope → estate-wide; still finds the single group.
    assert await run_dedup() == 1
