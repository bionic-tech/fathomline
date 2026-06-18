"""Reconcile router — cross-host divergence detection (ADR-024; read-only).

``POST /api/v1/reconcile`` compares a **definitive** ``(volume, path)`` against a **comparison**
``(volume, path)``, matching files by their path relative to each root and classifying each
(identical / content-same-but-dates-differ / diverged / size-match-unhashed / missing-each-side).
Read-only: it reads the catalogue and returns a verdict; it proposes and moves nothing. Gated by
``VIEW_METADATA`` + the server-authoritative scope on **both** volumes, with both roots normalised
and confined to their volume mountpoint (reusing the ADR-021 root-anchor validation).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from fathom.api.auth_deps import require
from fathom.api.deps import SessionDep
from fathom.api.routers.organize import _require_root_in_volume
from fathom.api.schemas import ReconcileItemOut, ReconcileOut, ReconcileRequest
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import query
from fathom.core.reconcile import ReconcileService

router = APIRouter(prefix="/api/v1", tags=["reconcile"])

ReconcileScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


@router.post("/reconcile", response_model=ReconcileOut)
async def reconcile(
    body: ReconcileRequest,
    session: SessionDep,
    scope: ReconcileScopeDep,
) -> ReconcileOut:
    """Classify files under two roots by their shared relative path (read-only; ADR-024)."""
    # Both volumes must be in scope, and each root absolute + normalised + within its mountpoint.
    def_vol = await query.get_volume_in_scope(session, body.definitive_volume_id, scope)
    cmp_vol = await query.get_volume_in_scope(session, body.comparison_volume_id, scope)
    if def_vol is None or cmp_vol is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")
    def_root = _require_root_in_volume(body.definitive_path, def_vol)
    cmp_root = _require_root_in_volume(body.comparison_path, cmp_vol)

    result = await ReconcileService(session).compare(
        definitive_volume_id=body.definitive_volume_id,
        definitive_root=def_root,
        comparison_volume_id=body.comparison_volume_id,
        comparison_root=cmp_root,
        scope=scope,
    )
    return ReconcileOut(
        definitive_volume_id=result.definitive_volume_id,
        definitive_root=result.definitive_root,
        comparison_volume_id=result.comparison_volume_id,
        comparison_root=result.comparison_root,
        counts=result.counts,
        considered=result.considered,
        truncated=result.truncated,
        items=[ReconcileItemOut(**asdict(it)) for it in result.items],
    )
