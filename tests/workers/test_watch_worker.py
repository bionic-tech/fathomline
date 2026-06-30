"""Watch worker tests (ADR-040) — gating, emitting to the bell, and dedup coalescing.

The worker self-gates on watch_enabled + notifications_enabled; when on it raises capacity alerts
into the bell, and a repeated condition coalesces on the dedup key (no restacking each tick).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from fathom.core import db, notifications
from fathom.core.catalogue.models import Base, Host, Volume
from fathom.core.settings import Settings
from fathom.workers.watch import WatchWorker


@pytest.fixture
async def catalogue(tmp_path: Path) -> AsyncIterator[None]:
    await db.dispose_engine()
    engine = db.init_engine(Settings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'c.db'}"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with db.session_scope() as session:
        host = Host(name="nas-1", cert_fingerprint="fp")
        session.add(host)
        await session.flush()
        session.add(
            Volume(
                host_id=host.id,
                mountpoint="/mnt/full",
                fs_type="zfs",
                device="tank",
                transport="sata",
                total=100,
                used=98,
                free=2,
            )
        )
    yield
    await db.dispose_engine()


def _noop_secret(ref: str) -> str:  # pragma: no cover - never reached (no channels enabled)
    raise AssertionError("secret provider should not be called without channels")


async def _unread() -> int:
    async with db.session_scope() as session:
        return await notifications.unread_count(session)


async def test_tick_is_gated_off(catalogue: None) -> None:
    worker = WatchWorker(
        lambda: Settings(watch_enabled=False, notifications_enabled=True), _noop_secret
    )
    assert await worker.tick() == 0
    assert await _unread() == 0


async def test_tick_requires_notifications_enabled(catalogue: None) -> None:
    worker = WatchWorker(
        lambda: Settings(watch_enabled=True, notifications_enabled=False), _noop_secret
    )
    assert await worker.tick() == 0
    assert await _unread() == 0


async def test_tick_raises_capacity_alert(catalogue: None) -> None:
    settings = Settings(
        watch_enabled=True,
        notifications_enabled=True,
        watch_capacity_warn_percent=90,
        watch_capacity_critical_percent=97,
    )
    worker = WatchWorker(lambda: settings, _noop_secret)
    raised = await worker.tick()
    assert raised == 1
    assert await _unread() == 1
    async with db.session_scope() as session:
        notes = await notifications.list_notifications(session)
    assert notes[0].category == "problem"
    assert notes[0].severity == "critical"  # 98% ≥ critical threshold
    assert notes[0].source == "watch"


async def test_repeated_tick_coalesces(catalogue: None) -> None:
    settings = Settings(watch_enabled=True, notifications_enabled=True)
    worker = WatchWorker(lambda: settings, _noop_secret)
    await worker.tick()
    await worker.tick()  # same condition → coalesced on dedup_key, not restacked
    assert await _unread() == 1
