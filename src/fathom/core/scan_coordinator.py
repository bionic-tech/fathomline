"""Scan concurrency coordinator (ADR-036) — defer a heavy scan while another is running.

Concurrent *heavy* scans (big reconcile/finalize passes) saturate the core's Postgres and cause
ingest failures. This coordinator gives each agent a pre-run **lease**: a light scan is always
granted; a heavy scan is granted only if fewer than ``max_concurrent_heavy`` heavy leases are
active, else it is **deferred** with an advisory (why + which host is blocking + when to retry).
"Heavy" is derived from the host's last :class:`AgentRun` (entries seen). A lease is released when
the agent reports its run; a TTL auto-expires a dead agent's lease so the fleet never wedges.

Read-only with respect to the catalogue: it only coordinates *when* a scan runs, never what it sees.
The whole feature is inert unless ``scan_coordinator_enabled`` is set (the endpoint grants-all when
off), so it is safe to deploy ahead of enabling.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from fathom.auth.scope import ScopeFilter
from fathom.core.agent_runs import latest_run_by_host
from fathom.core.catalogue.models import Host
from fathom.core.catalogue.scan_lease_meta import (
    LEASE_ACTIVE,
    LEASE_DEFERRED,
    LEASE_EXPIRED,
    LEASE_RELEASED,
    ScanLease,
)
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.core.scan_coordinator")


@dataclass(slots=True)
class LeaseDecision:
    """The coordinator's verdict for one scan-lease request."""

    granted: bool
    status: str  # "active" (granted) | "deferred"
    reason: str | None = None
    retry_after_seconds: int | None = None
    blocking_host: str | None = None


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(tz=UTC)


async def host_is_heavy(session: AsyncSession, host_id: int, settings: Settings) -> bool:
    """Whether ``host_id``'s scan is "heavy" — last run saw >= the threshold (no run ⇒ heavy)."""
    latest = await latest_run_by_host(session, [host_id])
    run = latest.get(host_id)
    if run is None:
        return True  # unproven host → coordinate conservatively
    return run.entries_seen >= settings.scan_coordinator_heavy_entries


async def _expire_stale(session: AsyncSession, now: datetime) -> None:
    """Flip any active lease past its TTL to ``expired`` (the crash safety net)."""
    await session.execute(
        update(ScanLease)
        .where(ScanLease.status == LEASE_ACTIVE, ScanLease.expires_at <= now)
        .values(status=LEASE_EXPIRED)
    )


async def release_lease(session: AsyncSession, host_id: int, *, now: datetime | None = None) -> int:
    """Release this host's active lease(s) on run-report. Returns the number released."""
    moment = _now(now)
    result = cast(
        CursorResult[object],
        await session.execute(
            update(ScanLease)
            .where(ScanLease.host_id == host_id, ScanLease.status == LEASE_ACTIVE)
            .values(status=LEASE_RELEASED, released_at=moment)
        ),
    )
    await session.flush()
    return int(result.rowcount or 0)


async def request_lease(
    session: AsyncSession, *, host_id: int, settings: Settings, now: datetime | None = None
) -> LeaseDecision:
    """Grant or defer a scan lease for ``host_id`` (the coordinator's core decision).

    A light scan is always granted. A heavy scan is granted only if fewer than
    ``max_concurrent_heavy`` *other* heavy leases are active; otherwise it is deferred with an
    advisory. A re-request from a host that already holds a lease supersedes its own old lease (a
    fresh run replaces the stale one) before counting others.
    """
    moment = _now(now)
    await _expire_stale(session, moment)
    # A new run from this host supersedes its own prior active lease (idempotent re-request).
    await release_lease(session, host_id, now=moment)

    heavy = await host_is_heavy(session, host_id, settings)
    if not heavy:
        await _grant(session, host_id, is_heavy=False, settings=settings, now=moment)
        return LeaseDecision(granted=True, status=LEASE_ACTIVE)

    # Count OTHER active heavy leases.
    active_heavy = (
        (
            await session.execute(
                select(ScanLease.host_id).where(
                    ScanLease.status == LEASE_ACTIVE, ScanLease.is_heavy.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )
    if len(active_heavy) < settings.scan_coordinator_max_concurrent_heavy:
        await _grant(session, host_id, is_heavy=True, settings=settings, now=moment)
        return LeaseDecision(granted=True, status=LEASE_ACTIVE)

    # Defer: record the advisory (why + blocking host + retry-after).
    blocking_host_id = active_heavy[0]
    blocking_name = await session.get(Host, blocking_host_id)
    blocking = blocking_name.name if blocking_name is not None else f"host {blocking_host_id}"
    retry_after = settings.scan_coordinator_retry_after_seconds
    reason = f"a heavy scan on {blocking} is in progress; deferring to avoid overloading the core"
    session.add(
        ScanLease(
            host_id=host_id,
            is_heavy=True,
            status=LEASE_DEFERRED,
            reason=reason,
            blocking_host_id=blocking_host_id,
            retry_after_seconds=retry_after,
        )
    )
    await session.flush()
    _log.info(
        "scan lease deferred",
        extra={"host_id": host_id, "blocking_host_id": blocking_host_id},
    )
    return LeaseDecision(
        granted=False,
        status=LEASE_DEFERRED,
        reason=reason,
        retry_after_seconds=retry_after,
        blocking_host=blocking,
    )


async def _grant(
    session: AsyncSession, host_id: int, *, is_heavy: bool, settings: Settings, now: datetime
) -> None:
    session.add(
        ScanLease(
            host_id=host_id,
            is_heavy=is_heavy,
            status=LEASE_ACTIVE,
            expires_at=now + timedelta(seconds=settings.scan_coordinator_lease_ttl_seconds),
        )
    )
    await session.flush()


@dataclass(slots=True)
class AdvisoryRow:
    """One coordinator event for the read surface (why a scan was deferred / lease state)."""

    host_name: str
    status: str
    is_heavy: bool
    reason: str | None
    blocking_host: str | None
    retry_after_seconds: int | None
    granted_at: datetime


async def recent_advisories(
    session: AsyncSession, *, scope: ScopeFilter | None = None, limit: int = 50
) -> list[AdvisoryRow]:
    """Recent coordinator events (newest first), scope-filtered by host — the 'why/when' surface.

    Joins the requesting host's name and (for a deferral) the blocking host's name. Scope is
    server-authoritative: a non-global principal sees only events for hosts it can reach.
    """
    blocker = aliased(Host)
    stmt = (
        select(
            Host.name.label("host_name"),
            ScanLease.status,
            ScanLease.is_heavy,
            ScanLease.reason,
            blocker.name.label("blocking_host"),
            ScanLease.retry_after_seconds,
            ScanLease.granted_at,
        )
        .join(Host, Host.id == ScanLease.host_id)
        .outerjoin(blocker, blocker.id == ScanLease.blocking_host_id)
        .order_by(ScanLease.granted_at.desc(), ScanLease.id.desc())
        .limit(limit)
    )
    if scope is not None:
        stmt = scope.apply(stmt, host_col=ScanLease.host_id)
    rows = (await session.execute(stmt)).all()
    return [
        AdvisoryRow(
            host_name=r.host_name,
            status=r.status,
            is_heavy=r.is_heavy,
            reason=r.reason,
            blocking_host=r.blocking_host,
            retry_after_seconds=r.retry_after_seconds,
            granted_at=r.granted_at,
        )
        for r in rows
    ]
