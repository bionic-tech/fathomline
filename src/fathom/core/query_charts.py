"""Chart read-queries for the UI viewer (ADD 09 §4, frontend ADD §10).

The viewer's treemap/sunburst/bar/line charts cannot ingest a 50M-node tree (frontend ADD
§10 risk), so every query here is **capped server-side**: ``treemap_children`` returns at most
one/few levels and a hard node limit; ``top_n_subtrees`` returns the N largest children; and
``growth_series`` is **downsampled server-side** into a bounded number of buckets. The caps
are passed in by the router from settings — the browser never asks for an unbounded result.

All subtree sizes come from ``subtree_rollup`` (instant drill-down totals, ADD 09 §8); files
without a rollup fall back to their own entry size. Path prefixes are matched with the shared
``escape_like`` so ``%``/``_`` in real paths stay literal (AR-0015) — the same parameterised,
escaped ``LIKE`` the rest of the read layer uses, so the new chart surface adds no injection
vector (spec risk: hand-built treemap/top-N queries).

Scope is server-authoritative (ADD 13 §4): the volume is scope-checked up front via the
:class:`~fathom.auth.scope.ScopeFilter`, so a request against an out-of-scope volume is
rejected ``403`` and never returns rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.catalogue.models import FsEntryRow, SizeHistory, SubtreeRollup, Volume
from fathom.core.query import escape_like

if TYPE_CHECKING:
    from fathom.auth.scope import ScopeFilter

_LIKE_ESCAPE = "\\"

SizeBasis = Literal["on_disk", "logical"]
TopNKind = Literal["dir", "file", "any"]


@dataclass(slots=True)
class TreemapNode:
    """A single sized node for the ECharts treemap/sunburst (one drill level)."""

    path: str
    name: str
    is_dir: bool
    subtree_size_logical: int
    subtree_size_on_disk: int
    file_count: int


@dataclass(slots=True)
class TopNItem:
    """A single 'biggest offender' row for the bar chart / top-N list."""

    path: str
    name: str
    is_dir: bool
    size_logical: int
    size_on_disk: int
    file_count: int


@dataclass(slots=True)
class GrowthPoint:
    """One downsampled point on the growth-over-time series."""

    ts: datetime
    total_size_logical: int
    total_size_on_disk: int
    file_count: int


@dataclass(slots=True)
class GrowthSeries:
    """A server-downsampled growth series for one subtree (frontend ADD §10)."""

    volume_id: int
    path: str
    points: list[GrowthPoint]


def _depth_within(mount: str, path: str) -> int:
    rel = path[len(mount) :].strip("/")
    return 0 if not rel else rel.count("/") + 1


async def _scoped_volume(
    session: AsyncSession, *, volume_id: int, scope: ScopeFilter | None
) -> Volume:
    """Load + scope-check a volume; raise ``ValueError`` if unknown, ``403`` if out of scope.

    The scope check threads ``volume.kind`` so a ``kind == 'system'`` volume is 403'd for a
    non-system grant (AR-011): a host-scoped principal cannot chart/drill a system volume it
    does not explicitly own at the volume level.
    """
    volume = await session.get(Volume, volume_id)
    if volume is None:
        raise ValueError(f"unknown volume_id {volume_id}")
    if scope is not None:
        scope.check_target(host_id=volume.host_id, volume_id=volume.id, volume_kind=volume.kind)
    return volume


async def treemap_children(
    session: AsyncSession,
    *,
    volume_id: int,
    path: str,
    depth: int,
    limit: int,
    scope: ScopeFilter | None = None,
) -> list[TreemapNode]:
    """Return up to ``limit`` immediate children of ``path``, largest-on-disk first.

    ``depth`` is accepted for the lazy drill-down contract (the frontend re-requests deeper
    levels on click; one level per call keeps the node count bounded, frontend ADD §10) and
    is clamped to ``>= 1`` by the caller. The returned nodes are sorted by on-disk subtree
    size descending and truncated to ``limit`` so the ECharts treemap/sunburst can never be
    handed an unbounded node set (spec risk: browser OOM).
    """
    volume = await _scoped_volume(session, volume_id=volume_id, scope=scope)
    mount = volume.mountpoint
    child_depth = _depth_within(mount, path) + 1
    like = escape_like(path.rstrip("/")) + "/%"

    rows = (
        await session.execute(
            select(FsEntryRow, SubtreeRollup)
            .outerjoin(
                SubtreeRollup,
                (SubtreeRollup.volume_id == FsEntryRow.volume_id)
                & (SubtreeRollup.path == FsEntryRow.path),
            )
            .where(
                FsEntryRow.volume_id == volume_id,
                FsEntryRow.depth == child_depth,
                FsEntryRow.path.like(like, escape=_LIKE_ESCAPE),
                # Current-state chart: a soft-deleted (present=False) entry is kept for churn but
                # must never appear as a live treemap node (incremental: presence markers).
                FsEntryRow.present.is_(True),
            )
        )
    ).all()

    nodes: list[TreemapNode] = []
    for entry, rollup in rows:
        if rollup is not None:
            subtree_logical = rollup.total_size_logical
            subtree_on_disk = rollup.total_size_on_disk
            file_count = rollup.file_count
        else:
            subtree_logical = entry.size_logical
            subtree_on_disk = entry.size_on_disk
            file_count = 0 if entry.is_dir else 1
        nodes.append(
            TreemapNode(
                path=entry.path,
                name=entry.name,
                is_dir=entry.is_dir,
                subtree_size_logical=subtree_logical,
                subtree_size_on_disk=subtree_on_disk,
                file_count=file_count,
            )
        )
    # Hard node cap (server-side): biggest on-disk first, then truncate.
    nodes.sort(key=lambda n: n.subtree_size_on_disk, reverse=True)
    return nodes[:limit]


async def top_n_subtrees(
    session: AsyncSession,
    *,
    volume_id: int,
    path: str,
    n: int,
    by: SizeBasis,
    kind: TopNKind,
    scope: ScopeFilter | None = None,
) -> list[TopNItem]:
    """Return the ``n`` largest immediate children of ``path`` (the 'biggest offenders').

    ``by`` selects the ordering basis (``on_disk`` | ``logical``); ``kind`` filters to
    directories, files, or any. The cap ``n`` is supplied by the router from settings so a
    client can never request an unbounded list.
    """
    volume = await _scoped_volume(session, volume_id=volume_id, scope=scope)
    mount = volume.mountpoint
    child_depth = _depth_within(mount, path) + 1
    like = escape_like(path.rstrip("/")) + "/%"

    # Order on the *effective* size — the rollup total when present, else the entry's own size
    # (the same fallback applied when building the row) — so ``ORDER BY ... LIMIT n`` can be
    # pushed into SQL and the database never hands back the full child rowset for a directory
    # with millions of children (spec risk: unbounded top-N fetch then slice in Python).
    if by == "on_disk":
        size_col = func.coalesce(SubtreeRollup.total_size_on_disk, FsEntryRow.size_on_disk)
    else:
        size_col = func.coalesce(SubtreeRollup.total_size_logical, FsEntryRow.size_logical)

    stmt = (
        select(FsEntryRow, SubtreeRollup)
        .outerjoin(
            SubtreeRollup,
            (SubtreeRollup.volume_id == FsEntryRow.volume_id)
            & (SubtreeRollup.path == FsEntryRow.path),
        )
        .where(
            FsEntryRow.volume_id == volume_id,
            FsEntryRow.depth == child_depth,
            FsEntryRow.path.like(like, escape=_LIKE_ESCAPE),
            # Live entries only: a removed file never appears in the 'biggest offenders' current
            # view (incremental: present/removed_at markers).
            FsEntryRow.present.is_(True),
        )
    )
    if kind == "dir":
        stmt = stmt.where(FsEntryRow.is_dir.is_(True))
    elif kind == "file":
        stmt = stmt.where(FsEntryRow.is_dir.is_(False))
    # Biggest first; ``path`` ASC is a deterministic secondary key so equal-size rows order
    # stably across calls (otherwise the tie order is whatever the engine returns). ``LIMIT n``
    # caps the rowset in the database, not in Python.
    stmt = stmt.order_by(size_col.desc(), FsEntryRow.path.asc()).limit(n)

    items: list[TopNItem] = []
    for entry, rollup in (await session.execute(stmt)).all():
        if rollup is not None:
            size_logical = rollup.total_size_logical
            size_on_disk = rollup.total_size_on_disk
            file_count = rollup.file_count
        else:
            size_logical = entry.size_logical
            size_on_disk = entry.size_on_disk
            file_count = 0 if entry.is_dir else 1
        items.append(
            TopNItem(
                path=entry.path,
                name=entry.name,
                is_dir=entry.is_dir,
                size_logical=size_logical,
                size_on_disk=size_on_disk,
                file_count=file_count,
            )
        )
    return items


def _downsample(points: list[GrowthPoint], buckets: int) -> list[GrowthPoint]:
    """Reduce ``points`` to at most ``buckets`` by last-in-window sampling (ADD §10).

    Samples are partitioned into ``buckets`` equal time slices and the **last** sample in each
    slice is kept (a monotone size series is best represented by its latest value per window).
    Empty slices contribute nothing, so the output length is ``<= buckets``.
    """
    if buckets <= 0 or len(points) <= buckets:
        return points
    first = points[0].ts.timestamp()
    last = points[-1].ts.timestamp()
    span = last - first
    if span <= 0:
        return [points[-1]]
    chosen: dict[int, GrowthPoint] = {}
    for point in points:
        idx = int((point.ts.timestamp() - first) / span * buckets)
        if idx >= buckets:
            idx = buckets - 1
        chosen[idx] = point  # keep the last sample seen in this slice
    return [chosen[i] for i in sorted(chosen)]


async def growth_series(
    session: AsyncSession,
    *,
    volume_id: int,
    path: str,
    since: datetime | None = None,
    until: datetime | None = None,
    buckets: int,
    scope: ScopeFilter | None = None,
) -> GrowthSeries:
    """Return a server-downsampled growth series for ``path`` over an optional window.

    Reads ``size_history`` rows (append-only, ADD 09 §2) for the subtree, scope-checks the
    volume, then downsamples to ``<= buckets`` points. An empty window yields an empty series
    (handled gracefully — no error, frontend renders an "insufficient history" state).
    """
    await _scoped_volume(session, volume_id=volume_id, scope=scope)
    stmt = select(SizeHistory).where(SizeHistory.volume_id == volume_id, SizeHistory.path == path)
    if since is not None:
        stmt = stmt.where(SizeHistory.ts >= since)
    if until is not None:
        stmt = stmt.where(SizeHistory.ts <= until)
    rows = (await session.execute(stmt.order_by(SizeHistory.ts))).scalars().all()
    points = [
        GrowthPoint(
            ts=row.ts,
            total_size_logical=row.total_size_logical,
            total_size_on_disk=row.total_size_on_disk,
            file_count=row.file_count,
        )
        for row in rows
    ]
    return GrowthSeries(volume_id=volume_id, path=path, points=_downsample(points, buckets))
