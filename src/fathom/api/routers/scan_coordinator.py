"""Scan coordinator router (ADR-036) — the agent lease endpoint + the operator advisory surface.

``POST /api/v1/agents/scan-lease`` is agent-facing (mTLS, same boundary as ingest): the agent calls
it just before a scan and the core GRANTS or DEFERS based on active heavy scans. When the feature is
off (``scan_coordinator_enabled`` False) it grants unconditionally, so an agent that always asks is
inert until the operator turns it on.

``GET /api/v1/scan-coordinator/advisories`` is the operator read surface (``VIEW_METADATA`` +
scope): recent grant/defer events — *why* a scan was deferred and *when* to retry — since the
notifications subsystem (ADR-031) is not built yet. Read-only throughout.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select

from fathom.api.auth_deps import require
from fathom.api.deps import FingerprintDep, SessionDep, SettingsDep
from fathom.api.schemas import ScanAdvisoryOut, ScanLeaseOut
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import scan_coordinator
from fathom.core.catalogue.models import Host
from fathom.logging import get_logger

_log = get_logger("fathom.api.routers.scan_coordinator")

router = APIRouter(prefix="/api/v1", tags=["scan-coordinator"])

ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


@router.post("/agents/scan-lease", response_model=ScanLeaseOut, status_code=status.HTTP_200_OK)
async def request_scan_lease(
    session: SessionDep, settings: SettingsDep, fingerprint: FingerprintDep
) -> ScanLeaseOut:
    """Agent-facing (mTLS): GRANT or DEFER this host's scan. Grants-all when the feature is off."""
    if not settings.scan_coordinator_enabled:
        # Inert by default: an agent that always asks is unaffected until the operator enables it.
        return ScanLeaseOut(granted=True, status="active")
    host = (
        await session.execute(select(Host).where(Host.cert_fingerprint == fingerprint))
    ).scalar_one_or_none()
    if host is None:
        # Authenticated by the boundary but no host row yet (never ingested) → nothing to gate.
        return ScanLeaseOut(granted=True, status="active")
    decision = await scan_coordinator.request_lease(
        session, host_id=host.id, settings=settings
    )
    return ScanLeaseOut(
        granted=decision.granted,
        status=decision.status,
        reason=decision.reason,
        retry_after_seconds=decision.retry_after_seconds,
        blocking_host=decision.blocking_host,
    )


@router.get("/scan-coordinator/advisories", response_model=list[ScanAdvisoryOut])
async def list_scan_advisories(
    session: SessionDep,
    scope: ViewScopeDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ScanAdvisoryOut]:
    """Operator (VIEW_METADATA + scope): recent grant/defer events — why deferred, when to retry."""
    rows = await scan_coordinator.recent_advisories(session, scope=scope, limit=limit)
    return [
        ScanAdvisoryOut(
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
