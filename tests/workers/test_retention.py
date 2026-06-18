"""Retention worker tests — the change_log pruner (incremental test_plan).

The worker is a stdlib-asyncio periodic loop (documented design choice: no broker dependency in
the gate). These tests exercise the shared body :func:`run_retention` against a real (temp SQLite)
catalogue, plus the :class:`RetentionWorker` tick + cancellable lifecycle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from fathom.core import db
from fathom.core.catalogue.models import Base, ChangeLog, Host, Volume
from fathom.core.incremental import CHANGE_LOG_RETENTION_DAYS
from fathom.core.settings import Settings
from fathom.workers.retention import RetentionWorker, run_retention


@pytest.fixture
async def catalogue(tmp_path: Path) -> AsyncIterator[int]:
    """A temp catalogue with one old + one fresh churn row; yields the volume id."""
    await db.dispose_engine()
    engine = db.init_engine(Settings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'c.db'}"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    now = datetime.now(tz=UTC)
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
        session.add_all(
            [
                ChangeLog(
                    volume_id=vol.id,
                    path="/mnt/pool/old",
                    change_type="create",
                    size_delta=1,
                    ts=now - timedelta(days=CHANGE_LOG_RETENTION_DAYS + 5),
                ),
                ChangeLog(
                    volume_id=vol.id,
                    path="/mnt/pool/new",
                    change_type="create",
                    size_delta=1,
                    ts=now - timedelta(days=1),
                ),
            ]
        )
        volume_id = vol.id
    yield volume_id
    await db.dispose_engine()


async def _remaining_paths() -> list[str]:
    async with db.session_scope() as session:
        rows = (await session.execute(select(ChangeLog.path))).scalars().all()
    return sorted(rows)


async def test_run_retention_prunes_old_rows(catalogue: int) -> None:
    removed = await run_retention()
    assert removed == 1
    assert await _remaining_paths() == ["/mnt/pool/new"]


async def test_worker_tick_prunes(catalogue: int) -> None:
    worker = RetentionWorker(interval_seconds=3600)
    assert await worker.tick() == 1
    assert await _remaining_paths() == ["/mnt/pool/new"]


async def test_worker_start_stop_is_clean(catalogue: int) -> None:
    # A very short interval: start, let one tick run, then stop cleanly (no leaked task).
    worker = RetentionWorker(interval_seconds=0.01)
    worker.start()
    # Poll until the old row is pruned (the first tick ran), bounded so the test can't hang.
    for _ in range(200):
        if await _row_count() == 1:
            break
        await _sleep_a_tick()
    await worker.stop()
    assert await _remaining_paths() == ["/mnt/pool/new"]


async def test_worker_rejects_bad_interval() -> None:
    with pytest.raises(ValueError, match="interval_seconds"):
        RetentionWorker(interval_seconds=0)


async def _row_count() -> int:
    async with db.session_scope() as session:
        return int((await session.execute(select(func.count(ChangeLog.id)))).scalar_one())


async def _sleep_a_tick() -> None:
    import asyncio

    await asyncio.sleep(0.01)
