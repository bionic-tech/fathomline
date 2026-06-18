"""Read-side queries for the catalogue (ADD 09 §4).

All subtree drill-down uses the materialised ``path`` with a ``LIKE`` prefix; the prefix is
escaped to neutralise ``%``/``_`` wildcards in real paths (AR-0015). Aggregated sizes come
from ``subtree_rollup`` (for directories) and fall back to the entry's own size for files.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from fathom.core.catalogue.models import (
    ChangeLog,
    DupGroup,
    DupMember,
    FsEntryRow,
    SizeHistory,
    SubtreeRollup,
    Volume,
)

if TYPE_CHECKING:
    from fathom.auth.scope import ScopeFilter

_LIKE_ESCAPE = "\\"


def escape_like(prefix: str) -> str:
    """Escape LIKE metacharacters so a literal path prefix matches literally (AR-0015)."""
    return (
        prefix.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
        .replace("%", _LIKE_ESCAPE + "%")
        .replace("_", _LIKE_ESCAPE + "_")
    )


def _depth_within(mount: str, path: str) -> int:
    rel = path[len(mount) :].strip("/")
    return 0 if not rel else rel.count("/") + 1


@dataclass(slots=True)
class TreeChild:
    """A single child node with its aggregated subtree totals and per-entry metadata."""

    # The catalogue row id — the surrogate the preview route (and any per-entry action) keys on,
    # so the UI never has to round-trip a path back to an entry (ADR-014 preview).
    entry_id: int
    path: str
    name: str
    is_dir: bool
    is_symlink: bool
    size_logical: int
    size_on_disk: int
    subtree_size_logical: int
    subtree_size_on_disk: int
    file_count: int
    # Per-entry metadata the scanner already captured (ADD 09 §2) — surfaced so the explorer's
    # detail pane can show owner / modified-time / inode / the open ``flags`` vocabulary
    # (sparse/reflink/compressed/ads/…) and the content hash when a full-bit pass has run.
    mtime: float
    uid: int
    gid: int
    inode: int
    flags: dict[str, bool]
    content_hash: str | None


async def list_volumes(
    session: AsyncSession, *, scope: ScopeFilter | None = None
) -> Sequence[Volume]:
    """Return catalogued volumes (usage + topology), scope-filtered when ``scope`` is given.

    The scope predicate is server-authoritative (ADD 13 §4): a non-global principal sees only
    in-scope hosts/volumes. ``Volume.host_id``/``Volume.id`` are the constrained columns, and
    ``Volume.kind`` drives the system-volume gate (AR-011): a non-global principal sees a
    ``kind == 'system'`` volume only when a volume-scoped grant names it explicitly.
    """
    stmt = select(Volume).order_by(Volume.id)
    if scope is not None:
        stmt = scope.apply(
            stmt, host_col=Volume.host_id, volume_col=Volume.id, kind_col=Volume.kind
        )
    return (await session.execute(stmt)).scalars().all()


def _check_volume_in_scope(volume: Volume, scope: ScopeFilter | None) -> None:
    """Raise 403 via ScopeFilter when ``volume`` is out of scope (ADD 13 §4).

    Passes ``volume.kind`` so a system volume is 403'd for a non-system grant (AR-011): a
    host-scoped principal cannot drill/inspect a ``kind == 'system'`` volume it does not
    explicitly own at the volume level.
    """
    if scope is not None:
        scope.check_target(host_id=volume.host_id, volume_id=volume.id, volume_kind=volume.kind)


async def get_volume_in_scope(
    session: AsyncSession, volume_id: int, scope: ScopeFilter | None
) -> Volume | None:
    """Return ``volume_id`` if it exists, raising 403 (via scope) when out of scope; None if absent.

    A small reusable guard for routes that take a ``volume_id`` and must 403 an out-of-scope volume
    rather than silently return nothing (ADD 13 §4).
    """
    volume = await session.get(Volume, volume_id)
    if volume is None:
        return None
    _check_volume_in_scope(volume, scope)
    return volume


async def list_children(
    session: AsyncSession,
    *,
    volume_id: int,
    path: str,
    scope: ScopeFilter | None = None,
) -> list[TreeChild]:
    """Return the immediate children of ``path`` within ``volume_id`` with subtree sizes."""
    volume = await session.get(Volume, volume_id)
    if volume is None:
        raise ValueError(f"unknown volume_id {volume_id}")
    _check_volume_in_scope(volume, scope)
    mount = volume.mountpoint
    parent_depth = _depth_within(mount, path)
    child_depth = parent_depth + 1
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
                # Current-state drill-down shows only live entries: a soft-deleted (present=False)
                # entry is kept for history/churn but must never inflate a current tree/size
                # (incremental: present/removed_at markers).
                FsEntryRow.present.is_(True),
            )
            .order_by(FsEntryRow.name)
        )
    ).all()

    children: list[TreeChild] = []
    for entry, rollup in rows:
        if rollup is not None:
            subtree_logical = rollup.total_size_logical
            subtree_on_disk = rollup.total_size_on_disk
            file_count = rollup.file_count
        else:
            subtree_logical = entry.size_logical
            subtree_on_disk = entry.size_on_disk
            file_count = 0 if entry.is_dir else 1
        children.append(
            TreeChild(
                entry_id=entry.id,
                path=entry.path,
                name=entry.name,
                is_dir=entry.is_dir,
                is_symlink=entry.is_symlink,
                size_logical=entry.size_logical,
                size_on_disk=entry.size_on_disk,
                subtree_size_logical=subtree_logical,
                subtree_size_on_disk=subtree_on_disk,
                file_count=file_count,
                mtime=entry.mtime,
                uid=entry.uid,
                gid=entry.gid,
                inode=entry.inode,
                flags=entry.flags or {},
                content_hash=entry.full_hash,
            )
        )
    return children


@dataclass(slots=True)
class SearchResult:
    """One estate-search hit — enough to render it and jump to it in the explorer."""

    path: str
    name: str
    is_dir: bool
    size_logical: int
    size_on_disk: int
    host_id: int
    volume_id: int


async def search_entries(
    session: AsyncSession,
    *,
    q: str,
    scope: ScopeFilter | None = None,
    volume_id: int | None = None,
    limit: int = 100,
) -> list[SearchResult]:
    """Find live entries whose **name** contains ``q`` (case-insensitive), biggest first.

    Estate-wide find-a-file: searches in-scope volumes (or one ``volume_id``), live entries only,
    ordered by on-disk size so the largest matches surface first, bounded by ``limit``. The term is
    LIKE-escaped (AR-0015) so ``%``/``_`` in a query match literally. Scope is server-authoritative
    (ADD 13 §4) and the ``Volume.kind`` system-volume gate (AR-011) is applied via the join. Name
    (not full-path) match keeps it index-friendlier; a substring search still seq-scans at estate
    scale, so a deployment that needs sub-second find over 50M rows adds a pg_trgm index — the query
    shape is unchanged.
    """
    like = f"%{escape_like(q)}%"
    stmt = (
        select(
            FsEntryRow.path,
            FsEntryRow.name,
            FsEntryRow.is_dir,
            FsEntryRow.size_logical,
            FsEntryRow.size_on_disk,
            FsEntryRow.host_id,
            FsEntryRow.volume_id,
        )
        .join(Volume, Volume.id == FsEntryRow.volume_id)
        .where(
            FsEntryRow.present.is_(True),
            FsEntryRow.name.ilike(like, escape=_LIKE_ESCAPE),
        )
        .order_by(FsEntryRow.size_on_disk.desc())
        .limit(limit)
    )
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
        SearchResult(
            path=r.path,
            name=r.name,
            is_dir=r.is_dir,
            size_logical=r.size_logical,
            size_on_disk=r.size_on_disk,
            host_id=r.host_id,
            volume_id=r.volume_id,
        )
        for r in rows
    ]


async def get_history(
    session: AsyncSession,
    *,
    volume_id: int,
    path: str,
    since: datetime | None = None,
    until: datetime | None = None,
    scope: ScopeFilter | None = None,
) -> Sequence[SizeHistory]:
    """Return size-history points for ``path`` over an optional time window (scope-checked)."""
    if scope is not None:
        volume = await session.get(Volume, volume_id)
        if volume is None:
            raise ValueError(f"unknown volume_id {volume_id}")
        _check_volume_in_scope(volume, scope)
    stmt = select(SizeHistory).where(SizeHistory.volume_id == volume_id, SizeHistory.path == path)
    if since is not None:
        stmt = stmt.where(SizeHistory.ts >= since)
    if until is not None:
        stmt = stmt.where(SizeHistory.ts <= until)
    return (await session.execute(stmt.order_by(SizeHistory.ts))).scalars().all()


async def get_changes(
    session: AsyncSession,
    *,
    volume_id: int,
    path: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 200,
    scope: ScopeFilter | None = None,
) -> Sequence[ChangeLog]:
    """Return churn rows for a subtree over a window (the 'what changed' feed, ADD 09 §4).

    Scope-checked (the volume must be in scope) before any row is read. ``path`` (when given)
    narrows to that subtree via an escaped ``LIKE`` prefix — the same wildcard-neutralising escape
    the tree drill-down uses (AR-0015). Newest first, bounded by ``limit``. Read-only: this only
    reads the append-only ``change_log`` the incremental reconciliation populates.
    """
    if scope is not None:
        volume = await session.get(Volume, volume_id)
        if volume is None:
            raise ValueError(f"unknown volume_id {volume_id}")
        _check_volume_in_scope(volume, scope)
    stmt = select(ChangeLog).where(ChangeLog.volume_id == volume_id)
    if path is not None:
        like = escape_like(path.rstrip("/")) + "/%"
        stmt = stmt.where((ChangeLog.path == path) | ChangeLog.path.like(like, escape=_LIKE_ESCAPE))
    if since is not None:
        stmt = stmt.where(ChangeLog.ts >= since)
    if until is not None:
        stmt = stmt.where(ChangeLog.ts <= until)
    stmt = stmt.order_by(ChangeLog.ts.desc(), ChangeLog.id.desc()).limit(limit)
    return (await session.execute(stmt)).scalars().all()


# --- duplicates (fullbit-dedup; ADD 09 §4, read-only, scope-filtered) --------------------


def _member_scope_predicate(scope: ScopeFilter) -> ColumnElement[bool]:
    """An EXISTS predicate: a group is visible iff it has a member in an in-scope host/volume.

    Built only from the server-authoritative :class:`ScopeFilter` (ADD 13 §4); an out-of-scope
    principal never sees a group whose every copy is out of scope, and the detail view filters
    members the same way so an out-of-scope path is never leaked (security_constraints).
    """
    member = select(DupMember.id).where(DupMember.group_id == DupGroup.id)
    member = scope.apply(member, host_col=DupMember.host_id, volume_col=DupMember.volume_id)
    return exists(member)


async def list_duplicate_groups(
    session: AsyncSession,
    *,
    scope: ScopeFilter | None = None,
    volume_id: int | None = None,
    cursor: int | None = None,
    limit: int = 50,
) -> tuple[list[DupGroup], int | None]:
    """Return a keyset page of duplicate groups and the next cursor (ADD 09 §4, API §2).

    Ordered by ascending ``id`` for a stable keyset (no offset pagination at 50M rows). ``cursor``
    is the last ``id`` of the previous page. ``volume_id`` narrows to groups with a member on that
    volume. ``scope`` (when given) hides any group with no in-scope member.
    """
    stmt = select(DupGroup).order_by(DupGroup.id)
    if cursor is not None:
        stmt = stmt.where(DupGroup.id > cursor)
    if volume_id is not None:
        stmt = stmt.where(
            exists(
                select(DupMember.id).where(
                    DupMember.group_id == DupGroup.id, DupMember.volume_id == volume_id
                )
            )
        )
    if scope is not None and not scope.is_global:
        stmt = stmt.where(_member_scope_predicate(scope))
    # Fetch one extra row to decide whether a next page exists (keyset).
    rows = (await session.execute(stmt.limit(limit + 1))).scalars().all()
    groups = list(rows[:limit])
    next_cursor = groups[-1].id if len(rows) > limit else None
    return groups, next_cursor


async def duplicate_summary(
    session: AsyncSession,
    *,
    scope: ScopeFilter | None = None,
    volume_id: int | None = None,
) -> tuple[int, int]:
    """Return ``(group_count, total_reclaimable_bytes)`` over the in-scope duplicate groups.

    The estate-wide headline for the dashboard ("reclaimable space"): a single aggregate over
    ``dup_group`` rather than summing a page client-side (which would understate it). Scope and
    ``volume_id`` filter exactly as the listing does, so the number reflects only what the
    principal may see / the selected volume.
    """
    stmt = select(
        func.count(DupGroup.id),
        func.coalesce(func.sum(DupGroup.reclaimable_bytes), 0),
    )
    if volume_id is not None:
        stmt = stmt.where(
            exists(
                select(DupMember.id).where(
                    DupMember.group_id == DupGroup.id, DupMember.volume_id == volume_id
                )
            )
        )
    if scope is not None and not scope.is_global:
        stmt = stmt.where(_member_scope_predicate(scope))
    count, total = (await session.execute(stmt)).one()
    return int(count), int(total)


async def get_duplicate_group(
    session: AsyncSession,
    group_id: int,
    *,
    scope: ScopeFilter | None = None,
) -> tuple[DupGroup, list[DupMember]] | None:
    """Return one group with its in-scope members, or ``None`` if not visible (scope-filtered).

    A group with no in-scope member returns ``None`` (404 at the router) — it must not leak its
    existence. Members are filtered to in-scope hosts/volumes so an out-of-scope path is never
    returned even within a partially-in-scope group (security_constraints).
    """
    group = await session.get(DupGroup, group_id)
    if group is None:
        return None
    member_stmt = select(DupMember).where(DupMember.group_id == group_id)
    if scope is not None and not scope.is_global:
        member_stmt = scope.apply(
            member_stmt, host_col=DupMember.host_id, volume_col=DupMember.volume_id
        )
    members = list((await session.execute(member_stmt.order_by(DupMember.id))).scalars().all())
    if not members:
        return None  # no in-scope member → not visible to this principal
    return group, members
