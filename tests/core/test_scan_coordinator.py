"""Scan coordinator tests (ADR-036) — heaviness, grant/defer serialization, release, advisories.

The coordinator's job: a light scan always runs; a heavy scan runs only if no other heavy scan
holds a lease, else it's deferred with an advisory (why + blocking host + retry-after); a released
or TTL-expired lease frees the next heavy scan. These cover that decision matrix directly against a
DB session, plus the scope-filtered advisory read.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.auth.scope import ScopeFilter
from fathom.core import scan_coordinator
from fathom.core.catalogue.models import AgentRun, Base, Host
from fathom.core.catalogue.scan_lease_meta import LEASE_ACTIVE, ScanLease
from fathom.core.settings import Settings

_NOW = datetime(2026, 6, 19, 12, 0, tzinfo=UTC)
_SETTINGS = Settings(scan_coordinator_enabled=True)  # defaults: heavy>=500k, max_concurrent_heavy=1


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


async def _run(session: AsyncSession, host: Host, entries: int) -> None:
    session.add(
        AgentRun(
            host_id=host.id,
            started_at=_NOW - timedelta(minutes=10),
            finished_at=_NOW,
            outcome="ok",
            entries_seen=entries,
            rows_changed=0,
            pushed=0,
            scopes_total=1,
            scopes_failed=0,
        )
    )
    await session.flush()


async def _lease(session: AsyncSession, *, host_id: int, scope: ScopeFilter | None = None):
    return await scan_coordinator.request_lease(
        session, host_id=host_id, settings=_SETTINGS, now=_NOW
    )


# --- heaviness ---------------------------------------------------------------------------


async def test_heaviness(session: AsyncSession) -> None:
    no_run = await _host(session, "fresh")
    heavy = await _host(session, "heavy")
    light = await _host(session, "light")
    await _run(session, heavy, 600_000)
    await _run(session, light, 1_000)
    assert await scan_coordinator.host_is_heavy(session, no_run.id, _SETTINGS) is True  # unproven
    assert await scan_coordinator.host_is_heavy(session, heavy.id, _SETTINGS) is True
    assert await scan_coordinator.host_is_heavy(session, light.id, _SETTINGS) is False


# --- grant / defer serialization ---------------------------------------------------------


async def test_light_scan_always_granted_even_with_active_heavy(session: AsyncSession) -> None:
    heavy = await _host(session, "heavy")
    light = await _host(session, "light")
    await _run(session, heavy, 600_000)
    await _run(session, light, 1_000)
    assert (await _lease(session, host_id=heavy.id)).granted is True  # heavy holds the lease
    decision = await _lease(session, host_id=light.id)
    assert decision.granted is True  # a light scan is never gated


async def test_heavy_scans_are_serialized_then_freed(session: AsyncSession) -> None:
    a = await _host(session, "host-a")
    b = await _host(session, "host-b")
    await _run(session, a, 600_000)
    await _run(session, b, 700_000)

    assert (await _lease(session, host_id=a.id)).granted is True
    deferred = await _lease(session, host_id=b.id)
    assert deferred.granted is False
    assert deferred.status == "deferred"
    assert deferred.blocking_host == "host-a"
    assert deferred.retry_after_seconds == _SETTINGS.scan_coordinator_retry_after_seconds
    assert "host-a" in (deferred.reason or "")

    # A's run-report releases its lease → B can now run.
    released = await scan_coordinator.release_lease(session, a.id, now=_NOW)
    assert released == 1
    assert (await _lease(session, host_id=b.id)).granted is True


async def test_rerequest_supersedes_own_lease(session: AsyncSession) -> None:
    a = await _host(session, "host-a")
    await _run(session, a, 600_000)
    assert (await _lease(session, host_id=a.id)).granted is True
    # A asks again (e.g. a retry): it supersedes its own lease, not blocked by itself.
    assert (await _lease(session, host_id=a.id)).granted is True
    active = (await session.execute(_active_for(a.id))).scalars().all()
    assert len(active) == 1  # exactly one active lease, not two


async def test_stale_lease_expires_and_unblocks(session: AsyncSession) -> None:
    a = await _host(session, "host-a")
    b = await _host(session, "host-b")
    await _run(session, b, 600_000)
    # A holds a heavy lease that expired an hour ago (a crashed agent).
    session.add(
        ScanLease(
            host_id=a.id, is_heavy=True, status=LEASE_ACTIVE, expires_at=_NOW - timedelta(hours=1)
        )
    )
    await session.flush()
    # B's heavy request should expire A's stale lease and be granted.
    assert (await _lease(session, host_id=b.id)).granted is True


# --- advisory read surface ---------------------------------------------------------------


async def test_recent_advisories_and_scope(session: AsyncSession) -> None:
    a = await _host(session, "host-a")
    b = await _host(session, "host-b")
    await _run(session, a, 600_000)
    await _run(session, b, 600_000)
    await _lease(session, host_id=a.id)  # granted
    await _lease(session, host_id=b.id)  # deferred → advisory

    rows = await scan_coordinator.recent_advisories(session)
    deferred = [r for r in rows if r.status == "deferred"]
    assert len(deferred) == 1
    assert deferred[0].host_name == "host-b"
    assert deferred[0].blocking_host == "host-a"

    # Scope to host-a only: host-b's advisory is hidden.
    scoped = ScopeFilter(is_global=False, host_ids=frozenset({a.id}))
    only_a = await scan_coordinator.recent_advisories(session, scope=scoped)
    assert all(r.host_name == "host-a" for r in only_a)


def _active_for(host_id: int):
    from sqlalchemy import select

    return select(ScanLease).where(
        ScanLease.host_id == host_id, ScanLease.status == LEASE_ACTIVE
    )
