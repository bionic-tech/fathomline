"""Chart read router — treemap / top-N / growth series (ADD 09 §4, frontend ADD §4/§10).

The data surface behind the UI viewer's ECharts treemap, sunburst, bar/pie 'biggest
offenders' and growth-over-time line. A separate route group from the agent/write surfaces
(read != write boundary, ADD 03 §3): every route requires the ``VIEW_METADATA`` capability
(deny-by-default) and applies the server-authoritative :class:`ScopeFilter`, so a principal
only ever sees in-scope volumes and a request against an out-of-scope volume is rejected 403
(ADD 13 §4). The agent mTLS ingest surface is unaffected — human auth deps attach here only.

Node counts are **hard-capped server-side** from settings (frontend ADD §10): a client can
never request an unbounded treemap/top-N/series, so the browser cannot be handed a node set
large enough to OOM (spec risk). The agent mTLS ingest path keeps its own boundary
(``FingerprintDep``) and is never reached from here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status

from fathom.api.auth_deps import require
from fathom.api.deps import SessionDep, SettingsDep
from fathom.api.schemas import (
    GrowthPointOut,
    GrowthSeriesOut,
    TopNItemOut,
    TreemapNodeOut,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import query_charts

router = APIRouter(prefix="/api/v1", tags=["charts"])

# Resolve VIEW_METADATA + the request's scope once; reused by every chart route (ADD 13 §4).
ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


@router.get("/treemap", response_model=list[TreemapNodeOut])
async def get_treemap(
    session: SessionDep,
    settings: SettingsDep,
    scope: ViewScopeDep,
    volume_id: int = Query(..., ge=1),
    path: str = Query(..., min_length=1),
    depth: int = Query(default=1, ge=1, le=4),
    limit: int = Query(default=100, ge=1),
) -> list[TreemapNodeOut]:
    """Return the largest children of ``path`` (capped) for the ECharts treemap/sunburst."""
    # Clamp the client-requested limit to the server-side hard cap (never larger).
    capped = min(limit, settings.treemap_max_nodes)
    try:
        nodes = await query_charts.treemap_children(
            session,
            volume_id=volume_id,
            path=path,
            depth=depth,
            limit=capped,
            scope=scope,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return [TreemapNodeOut.model_validate(n) for n in nodes]


@router.get("/top-n", response_model=list[TopNItemOut])
async def get_top_n(
    session: SessionDep,
    settings: SettingsDep,
    scope: ViewScopeDep,
    volume_id: int = Query(..., ge=1),
    path: str = Query(..., min_length=1),
    n: int = Query(default=20, ge=1),
    by: Literal["on_disk", "logical"] = Query(default="on_disk"),
    kind: Literal["dir", "file", "any"] = Query(default="any"),
) -> list[TopNItemOut]:
    """Return the N largest immediate children of ``path`` (capped) — the 'biggest offenders'."""
    capped = min(n, settings.top_n_max)
    try:
        items = await query_charts.top_n_subtrees(
            session,
            volume_id=volume_id,
            path=path,
            n=capped,
            by=by,
            kind=kind,
            scope=scope,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return [TopNItemOut.model_validate(i) for i in items]


@router.get("/history/series", response_model=GrowthSeriesOut)
async def get_history_series(
    session: SessionDep,
    settings: SettingsDep,
    scope: ViewScopeDep,
    volume_id: int = Query(..., ge=1),
    path: str = Query(..., min_length=1),
    since: datetime | None = None,
    until: datetime | None = None,
    buckets: int = Query(default=200, ge=2),
) -> GrowthSeriesOut:
    """Return a server-downsampled growth-over-time series for an in-scope subtree (ADD §10)."""
    capped = min(buckets, settings.growth_max_buckets)
    try:
        series = await query_charts.growth_series(
            session,
            volume_id=volume_id,
            path=path,
            since=since,
            until=until,
            buckets=capped,
            scope=scope,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return GrowthSeriesOut(
        volume_id=series.volume_id,
        path=series.path,
        points=[GrowthPointOut.model_validate(p) for p in series.points],
    )
