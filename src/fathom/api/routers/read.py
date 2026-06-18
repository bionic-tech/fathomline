"""Read router — drill-down, volumes, and history (ADD 01, ADD 13 §4).

A separate route group from the agent/write surfaces, with read-only DB access. Every route
requires the ``VIEW_METADATA`` capability (deny-by-default) and applies the returned,
server-authoritative :class:`ScopeFilter` so a principal only ever sees in-scope
hosts/volumes — and a drill-down/history request against an out-of-scope volume is rejected
403 (ADD 13 §4). The agent mTLS ingest surface is unaffected: human auth deps attach here
only (ADD 03 §3).
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from fathom.api.auth_deps import require
from fathom.api.deps import SessionDep
from fathom.api.schemas import (
    ChangeOut,
    HistoryPointOut,
    SearchResultOut,
    TreeChildOut,
    VolumeOut,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import query

router = APIRouter(prefix="/api/v1", tags=["read"])

# Resolve the VIEW_METADATA capability + scope once; reused by every read route.
ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


@router.get("/volumes", response_model=list[VolumeOut])
async def get_volumes(session: SessionDep, scope: ViewScopeDep) -> list[VolumeOut]:
    """List in-scope volumes with usage and storage topology."""
    volumes = await query.list_volumes(session, scope=scope)
    return [VolumeOut.model_validate(v) for v in volumes]


@router.get("/tree", response_model=list[TreeChildOut])
async def get_tree(
    session: SessionDep,
    scope: ViewScopeDep,
    volume_id: int = Query(..., ge=1),
    path: str = Query(..., min_length=1),
) -> list[TreeChildOut]:
    """Return the immediate children of ``path`` with aggregated subtree sizes (scope-checked)."""
    try:
        children = await query.list_children(session, volume_id=volume_id, path=path, scope=scope)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return [TreeChildOut(**asdict(c)) for c in children]


@router.get("/history", response_model=list[HistoryPointOut])
async def get_history(
    session: SessionDep,
    scope: ViewScopeDep,
    volume_id: int = Query(..., ge=1),
    path: str = Query(..., min_length=1),
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[HistoryPointOut]:
    """Return time-series size samples for an in-scope subtree."""
    try:
        points = await query.get_history(
            session, volume_id=volume_id, path=path, since=since, until=until, scope=scope
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return [HistoryPointOut.model_validate(p) for p in points]


@router.get("/changes", response_model=list[ChangeOut])
async def get_changes(
    session: SessionDep,
    scope: ViewScopeDep,
    volume_id: int = Query(..., ge=1),
    path: str | None = Query(default=None, min_length=1),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[ChangeOut]:
    """Return the churn feed ('what changed') for an in-scope subtree/window (scope-checked).

    Gated by ``VIEW_METADATA`` like the rest of the read surface; the volume is scope-checked
    before any churn row is read so an out-of-scope volume is rejected 403 (incremental subsystem).
    """
    try:
        rows = await query.get_changes(
            session,
            volume_id=volume_id,
            path=path,
            since=since,
            until=until,
            limit=limit,
            scope=scope,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return [ChangeOut.model_validate(r) for r in rows]


@router.get("/search", response_model=list[SearchResultOut])
async def search(
    session: SessionDep,
    scope: ViewScopeDep,
    q: str = Query(..., min_length=1, max_length=255),
    volume_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[SearchResultOut]:
    """Find live entries by name across in-scope volumes (biggest first); jump-to in the explorer.

    Gated by ``VIEW_METADATA`` and scope-filtered server-side (ADD 13 §4). When ``volume_id`` is
    given it is scope-checked first (out-of-scope → 403), so a search is never silently empty for an
    authorisation reason.
    """
    if volume_id is not None:
        volume = await query.get_volume_in_scope(session, volume_id, scope)
        if volume is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")
    results = await query.search_entries(
        session, q=q, scope=scope, volume_id=volume_id, limit=limit
    )
    return [SearchResultOut(**asdict(r)) for r in results]
