"""Concierge catalogue queries (ADR-035) — the scope-enforcing "tools" the concierge can run.

These are thin, read-only query functions the ``ConciergeService`` dispatches to after the model
picks a tool. Every function applies the server-authoritative ``ScopeFilter`` itself (host/volume +
the ``Volume.kind`` system-volume gate, AR-011) — the model never shapes a query and never sees an
out-of-scope row. They reuse the read
layer's conventions (``escape_like`` for ``LIKE`` safety, the ``present`` flag) and add the few
shapes the concierge needs that the existing read API does not expose.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.embedding_meta import FsEntryEmbedding
from fathom.core.catalogue.models import ChangeLog, FsEntryRow, Host, SizeHistory, Snapshot, Volume
from fathom.core.query import escape_like

_LIKE_ESCAPE = "\\"


# --- "I can't find this file" — last-seen / deleted lookup --------------------------------


@dataclass(slots=True)
class LastSeenHit:
    """A file matched by name/path, INCLUDING soft-deleted ones (answers 'when did it vanish')."""

    entry_id: int
    host_id: int
    volume_id: int
    path: str
    name: str
    present: bool
    removed_at: datetime | None
    last_seen_snapshot_id: int | None
    last_seen_at: datetime | None  # Snapshot.finished of the run that last catalogued it
    size_logical: int
    mtime: float


async def find_last_seen(
    session: AsyncSession,
    *,
    name_or_fragment: str,
    scope: ScopeFilter | None = None,
    volume_id: int | None = None,
    include_present: bool = True,
    limit: int = 25,
) -> list[LastSeenHit]:
    """Find entries by name/path fragment, **including soft-deleted ones** (``present=False``).

    Unlike :func:`fathom.core.query.search_entries` (which filters ``present=True``), this keeps
    deleted rows so "I can't find this file" can be answered with *when it was last seen / deleted*.
    LEFT JOINs ``Snapshot`` on ``last_seen_snapshot_id`` for the last-catalogued time. The fragment
    is ``ILIKE``-escaped (AR-0015) and matched against name OR path. Scope + the ``Volume.kind``
    system gate are applied via the ``Volume`` join. Ordered deleted-most-recently first (the
    headline answer), then largest. ``include_present=False`` restricts to deleted entries only.
    """
    like = f"%{escape_like(name_or_fragment)}%"
    stmt = (
        select(
            FsEntryRow.id,
            FsEntryRow.host_id,
            FsEntryRow.volume_id,
            FsEntryRow.path,
            FsEntryRow.name,
            FsEntryRow.present,
            FsEntryRow.removed_at,
            FsEntryRow.last_seen_snapshot_id,
            FsEntryRow.size_logical,
            FsEntryRow.mtime,
            Snapshot.finished.label("last_seen_at"),
        )
        .join(Volume, Volume.id == FsEntryRow.volume_id)
        .outerjoin(Snapshot, Snapshot.id == FsEntryRow.last_seen_snapshot_id)
        .where(
            FsEntryRow.name.ilike(like, escape=_LIKE_ESCAPE)
            | FsEntryRow.path.ilike(like, escape=_LIKE_ESCAPE)
        )
        # Deleted first (removed_at not-null sorts before null), most-recent deletion first, then
        # biggest. Ordering by ``is_(None)`` avoids a non-portable NULLS LAST clause.
        .order_by(
            FsEntryRow.removed_at.is_(None),
            FsEntryRow.removed_at.desc(),
            FsEntryRow.size_on_disk.desc(),
        )
        .limit(limit)
    )
    if not include_present:
        stmt = stmt.where(FsEntryRow.present.is_(False))
    if volume_id is not None:
        stmt = stmt.where(FsEntryRow.volume_id == volume_id)
    if scope is not None:
        stmt = scope.apply(
            stmt,
            host_col=FsEntryRow.host_id,
            volume_col=FsEntryRow.volume_id,
            kind_col=Volume.kind,
        )
    rows = (await session.execute(stmt)).all()
    return [
        LastSeenHit(
            entry_id=r.id,
            host_id=r.host_id,
            volume_id=r.volume_id,
            path=r.path,
            name=r.name,
            present=r.present,
            removed_at=r.removed_at,
            last_seen_snapshot_id=r.last_seen_snapshot_id,
            last_seen_at=r.last_seen_at,
            size_logical=r.size_logical,
            mtime=r.mtime,
        )
        for r in rows
    ]


# --- "which non-OS folders changed most" — hot folders from the churn feed ----------------


@dataclass(slots=True)
class HotFolder:
    """A frequently-changed (non-OS) folder, ranked from the change feed."""

    volume_id: int
    host_id: int
    path: str
    change_count: int
    net_size_delta: int
    last_change: datetime


# Cap how many change_log rows a single hot-folders scan reads (bounds latency; the aggregation is
# done in Python because deriving the Nth-level ancestor of a path is not portable across dialects).
_HOT_SCAN_CAP = 5000


async def hot_folders(
    session: AsyncSession,
    *,
    since: datetime,
    scope: ScopeFilter | None = None,
    volume_id: int | None = None,
    parent_depth: int = 1,
    limit: int = 20,
) -> list[HotFolder]:
    """Rank the most-churned **non-OS** folders from ``change_log`` over a window.

    Joins ``change_log`` → ``volume`` and **hard-filters ``Volume.kind != 'system'``** (the
    OS-folder exclusion the user asked for), on top of the scope's own system gate. Each changed
    path is rolled up to its ``parent_depth``-level ancestor folder (relative to the volume
    mountpoint); folders are ranked by change count. The scan is bounded by the newest rows.
    """
    stmt = (
        select(
            ChangeLog.path,
            ChangeLog.size_delta,
            ChangeLog.ts,
            ChangeLog.volume_id,
            Volume.host_id,
            Volume.mountpoint,
        )
        .join(Volume, Volume.id == ChangeLog.volume_id)
        .where(ChangeLog.ts >= since, Volume.kind != "system")
        .order_by(ChangeLog.ts.desc())
        .limit(_HOT_SCAN_CAP)
    )
    if volume_id is not None:
        stmt = stmt.where(ChangeLog.volume_id == volume_id)
    if scope is not None:
        stmt = scope.apply(
            stmt,
            host_col=Volume.host_id,
            volume_col=ChangeLog.volume_id,
            kind_col=Volume.kind,
        )
    rows = (await session.execute(stmt)).all()

    agg: dict[tuple[int, str], HotFolder] = {}
    for r in rows:
        folder = _ancestor_folder(r.mountpoint, r.path, parent_depth)
        key = (r.volume_id, folder)
        cur = agg.get(key)
        if cur is None:
            agg[key] = HotFolder(
                volume_id=r.volume_id,
                host_id=r.host_id,
                path=folder,
                change_count=1,
                net_size_delta=r.size_delta,
                last_change=r.ts,
            )
        else:
            cur.change_count += 1
            cur.net_size_delta += r.size_delta
            if r.ts > cur.last_change:
                cur.last_change = r.ts
    ranked = sorted(agg.values(), key=lambda h: (h.change_count, h.last_change), reverse=True)
    return ranked[:limit]


def _ancestor_folder(mountpoint: str, path: str, parent_depth: int) -> str:
    """Return the ``parent_depth``-level ancestor folder of ``path`` under ``mountpoint``.

    e.g. mountpoint=/mnt/data, path=/mnt/data/media/films/x.mkv, parent_depth=1 → /mnt/data/media.
    A path at or above the requested depth collapses to its own directory / the mountpoint.
    """
    base = mountpoint.rstrip("/")
    if not path.startswith(base + "/"):
        return posixpath.dirname(path) or base
    rel_parts = path[len(base) + 1 :].split("/")
    # Drop the leaf (the changed file/dir itself) is implicit: we keep the first ``parent_depth``
    # directory components. If the path is shallower, fall back to its parent directory.
    keep = rel_parts[:parent_depth]
    if not keep:
        return base
    return base + "/" + "/".join(keep)


# --- "how full is the fleet / what disk types" — per-host storage roll-up -----------------


@dataclass(slots=True)
class VolumeSummary:
    """One volume's capacity + storage type, for the fleet roll-up."""

    volume_id: int
    mountpoint: str
    display_name: str | None
    fs_type: str
    transport: str
    raid_role: str | None
    pool: str | None
    dataset: str | None
    kind: str
    total: int
    used: int
    free: int


@dataclass(slots=True)
class HostStorage:
    """A host's total disk space + the volumes (with types/formats) that make it up."""

    host_id: int
    host_name: str
    total: int
    used: int
    free: int
    volumes: list[VolumeSummary] = field(default_factory=list)


async def fleet_storage(
    session: AsyncSession,
    *,
    scope: ScopeFilter | None = None,
    host_id: int | None = None,
) -> list[HostStorage]:
    """Per-host roll-up of disk space + disk types/formats across in-scope volumes.

    The "knows the whole fleet's disk space and disk types from memory" answer. Joins ``volume`` →
    ``host`` for the host name, applies scope + the ``Volume.kind`` system gate, and groups in
    Python (small result set — one row per volume). Hosts are ordered by free space ascending so the
    fullest host surfaces first.
    """
    stmt = (
        select(Volume, Host.name.label("host_name"))
        .join(Host, Host.id == Volume.host_id)
        .order_by(Volume.host_id, Volume.id)
    )
    if host_id is not None:
        stmt = stmt.where(Volume.host_id == host_id)
    if scope is not None:
        stmt = scope.apply(
            stmt, host_col=Volume.host_id, volume_col=Volume.id, kind_col=Volume.kind
        )
    rows = (await session.execute(stmt)).all()

    by_host: dict[int, HostStorage] = {}
    for volume, host_name in rows:
        host = by_host.get(volume.host_id)
        if host is None:
            host = HostStorage(host_id=volume.host_id, host_name=host_name, total=0, used=0, free=0)
            by_host[volume.host_id] = host
        host.total += volume.total
        host.used += volume.used
        host.free += volume.free
        host.volumes.append(
            VolumeSummary(
                volume_id=volume.id,
                mountpoint=volume.mountpoint,
                display_name=volume.display_name,
                fs_type=volume.fs_type,
                transport=volume.transport,
                raid_role=volume.raid_role,
                pool=volume.pool,
                dataset=volume.dataset,
                kind=volume.kind,
                total=volume.total,
                used=volume.used,
                free=volume.free,
            )
        )
    return sorted(by_host.values(), key=lambda h: h.free)


# --- "what's actually scanned" — catalogue coverage per host/volume ----------------------


@dataclass(slots=True)
class VolumeCoverage:
    """One scanned volume: its mountpoint (a collected path), type, file count and last scan."""

    volume_id: int
    mountpoint: str
    kind: str
    fs_type: str
    entry_count: int
    last_scan: datetime | None


@dataclass(slots=True)
class HostCoverage:
    """A host and the volumes (collected paths) the catalogue holds for it."""

    host_id: int
    host_name: str
    volumes: list[VolumeCoverage] = field(default_factory=list)


async def scanned_paths(
    session: AsyncSession,
    *,
    scope: ScopeFilter | None = None,
    host_id: int | None = None,
) -> list[HostCoverage]:
    """What the catalogue actually contains: per host, the scanned volumes (collected paths) with
    their indexed-file count and last scan time.

    Answers "what paths are collected on X", "which hosts/volumes do you know", "is X being scanned"
    — and lets a "no results" answer distinguish *nothing here* from *that host isn't scanned*. The
    in-scope volume set is resolved first (same scope + ``Volume.kind`` system gate as every other
    tool), then the present-entry count and latest finished :class:`Snapshot` are looked up for
    those volume ids only — so counts can never include an out-of-scope or system volume.
    """
    vol_stmt = (
        select(Volume, Host.name.label("host_name"))
        .join(Host, Host.id == Volume.host_id)
        .order_by(Volume.host_id, Volume.id)
    )
    if host_id is not None:
        vol_stmt = vol_stmt.where(Volume.host_id == host_id)
    if scope is not None:
        vol_stmt = scope.apply(
            vol_stmt, host_col=Volume.host_id, volume_col=Volume.id, kind_col=Volume.kind
        )
    vol_rows = (await session.execute(vol_stmt)).all()
    vol_ids = [v.id for v, _ in vol_rows]

    counts: dict[int, int] = {}
    last_scans: dict[int, datetime | None] = {}
    if vol_ids:
        count_rows = (
            await session.execute(
                select(FsEntryRow.volume_id, func.count(FsEntryRow.id))
                .where(FsEntryRow.volume_id.in_(vol_ids), FsEntryRow.present.is_(True))
                .group_by(FsEntryRow.volume_id)
            )
        ).all()
        counts = {vid: int(n) for vid, n in count_rows}
        scan_rows = (
            await session.execute(
                select(Snapshot.volume_id, func.max(Snapshot.finished))
                .where(Snapshot.volume_id.in_(vol_ids))
                .group_by(Snapshot.volume_id)
            )
        ).all()
        last_scans = {vid: ts for vid, ts in scan_rows}

    by_host: dict[int, HostCoverage] = {}
    for volume, host_name in vol_rows:
        host = by_host.get(volume.host_id)
        if host is None:
            host = HostCoverage(host_id=volume.host_id, host_name=host_name)
            by_host[volume.host_id] = host
        host.volumes.append(
            VolumeCoverage(
                volume_id=volume.id,
                mountpoint=volume.mountpoint,
                kind=volume.kind,
                fs_type=volume.fs_type,
                entry_count=counts.get(volume.id, 0),
                last_scan=last_scans.get(volume.id),
            )
        )
    return list(by_host.values())


# --- "when will it fill up" — linear growth forecast -------------------------------------


@dataclass(slots=True)
class GrowthForecast:
    """A simple linear growth projection for a subtree (days-to-full)."""

    volume_id: int
    path: str
    current_size: int
    daily_growth_bytes: float
    days_to_full: float | None  # None when flat/shrinking or free space unknown


async def growth_forecast(
    session: AsyncSession,
    *,
    volume_id: int,
    path: str,
    scope: ScopeFilter | None = None,
    lookback_days: int = 30,
    now: datetime | None = None,
) -> GrowthForecast | None:
    """Linear least-squares forecast from ``size_history`` + ``Volume.free`` → days-to-full.

    Scope-checks the volume (403 if out of scope). Returns ``None`` when the volume is unknown or
    there are fewer than two history points to fit. ``now`` is injectable for deterministic tests.
    """
    volume = await session.get(Volume, volume_id)
    if volume is None:
        return None
    if scope is not None:
        scope.check_target(host_id=volume.host_id, volume_id=volume.id, volume_kind=volume.kind)

    since = None
    if now is not None and lookback_days > 0:
        since = datetime.fromtimestamp(now.timestamp() - lookback_days * 86400, tz=now.tzinfo)
    stmt = select(SizeHistory.ts, SizeHistory.total_size_on_disk).where(
        SizeHistory.volume_id == volume_id, SizeHistory.path == path
    )
    if since is not None:
        stmt = stmt.where(SizeHistory.ts >= since)
    points = (await session.execute(stmt.order_by(SizeHistory.ts))).all()
    if len(points) < 2:
        return None

    # Least-squares slope of size vs. time (seconds), converted to bytes/day.
    t0 = points[0].ts.timestamp()
    xs = [p.ts.timestamp() - t0 for p in points]
    ys = [float(p.total_size_on_disk) for p in points]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom == 0:
        slope = 0.0
    else:
        cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
        slope = cov / denom
    daily = slope * 86400.0
    current = int(ys[-1])
    days_to_full: float | None = None
    if daily > 0 and volume.free > 0:
        days_to_full = volume.free / daily
    return GrowthForecast(
        volume_id=volume_id,
        path=path,
        current_size=current,
        daily_growth_bytes=daily,
        days_to_full=days_to_full,
    )


# --- "find the file about X" — semantic (pgvector) search (Phase 2; PostgreSQL-only) -----


@dataclass(slots=True)
class SemanticHit:
    """One semantic-search hit (nearest path-name embedding to the query)."""

    entry_id: int
    host_id: int
    volume_id: int
    path: str
    name: str
    distance: float


async def semantic_search(
    session: AsyncSession,
    *,
    query_embedding: list[float],
    scope: ScopeFilter | None = None,
    volume_id: int | None = None,
    limit: int = 20,
) -> list[SemanticHit]:
    """Nearest path-name embeddings to ``query_embedding`` by cosine distance (PostgreSQL/pgvector).

    Joins ``fs_entry_embedding`` → ``fs_entry`` (business key) → ``volume`` and applies the SAME
    scope + ``Volume.kind`` gate as every other read, so the vector search can never surface an
    out-of-scope or system-volume path. Present entries only. Uses pgvector's ``<=>`` cosine
    distance; a pgvector-enabled Postgres + the embedding pipeline must be live for this to return
    rows — on SQLite the operator is unavailable, so the concierge degrades to substring find.
    """
    distance = FsEntryEmbedding.embedding.cosine_distance(query_embedding)
    stmt = (
        select(
            FsEntryRow.id,
            FsEntryRow.host_id,
            FsEntryRow.volume_id,
            FsEntryRow.path,
            FsEntryRow.name,
            distance.label("distance"),
        )
        .join(
            FsEntryRow,
            (FsEntryRow.id == FsEntryEmbedding.entry_id)
            & (FsEntryRow.host_id == FsEntryEmbedding.host_id)
            & (FsEntryRow.volume_id == FsEntryEmbedding.volume_id),
        )
        .join(Volume, Volume.id == FsEntryRow.volume_id)
        .where(FsEntryRow.present.is_(True))
        .order_by(distance)
        .limit(limit)
    )
    if volume_id is not None:
        stmt = stmt.where(FsEntryRow.volume_id == volume_id)
    if scope is not None:
        stmt = scope.apply(
            stmt, host_col=FsEntryRow.host_id, volume_col=FsEntryRow.volume_id, kind_col=Volume.kind
        )
    rows = (await session.execute(stmt)).all()
    return [
        SemanticHit(
            entry_id=r.id,
            host_id=r.host_id,
            volume_id=r.volume_id,
            path=r.path,
            name=r.name,
            distance=float(r.distance),
        )
        for r in rows
    ]
