"""Notification Center service (ADR-031) — emit + read the in-app "bell" store.

The producer side is :func:`emit` (one call per event, with optional coalescing); the consumer
side is the scope-filtered list / unread-count / mark-read used by the bell API. Read-only with
respect to the estate. Outbound Email/Chat channels reuse this same store in a later wave; Phase 1
is the in-app channel only.

Scope: a notification with ``host_id IS NULL`` is estate-wide (visible to anyone who can view);
otherwise it is gated to its host (a non-global principal sees it only if that host is in scope).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from sqlalchemy import CursorResult, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.notification_meta import CATEGORIES, SEVERITIES, Notification
from fathom.logging import get_logger

_log = get_logger("fathom.core.notifications")


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(tz=UTC)


def _visible(scope: ScopeFilter | None) -> ColumnElement[bool] | None:
    """A WHERE predicate limiting notifications to those a principal may see, or None for all.

    Estate-wide rows (``host_id IS NULL``) are always visible; host-scoped rows need the host in
    scope. A non-global principal with no in-scope hosts therefore sees only estate-wide rows
    (fail-closed for host-specific ones).
    """
    if scope is None or scope.is_global:
        return None
    preds: list[ColumnElement[bool]] = [Notification.host_id.is_(None)]
    if scope.host_ids:
        preds.append(Notification.host_id.in_(scope.host_ids))
    return or_(*preds)


async def emit(
    session: AsyncSession,
    *,
    category: str,
    title: str,
    source: str,
    body: str = "",
    severity: str = "info",
    host_id: int | None = None,
    volume_id: int | None = None,
    dedup_key: str | None = None,
    now: datetime | None = None,
) -> Notification:
    """Raise one notification into the bell store; coalesce on ``dedup_key`` if given.

    Validates ``category``/``severity`` against the vocabularies (a typo is a bug, not a silent
    mis-file). When ``dedup_key`` matches an existing **unread** row, that row is refreshed (title/
    body/severity/timestamp) and bumped to the top instead of stacking a duplicate — so a producer
    can re-emit "disk 95% full" each tick without flooding the panel.
    """
    if category not in CATEGORIES:
        raise ValueError(f"unknown notification category {category!r}")
    if severity not in SEVERITIES:
        raise ValueError(f"unknown notification severity {severity!r}")
    moment = _now(now)
    if dedup_key is not None:
        existing = (
            await session.execute(
                select(Notification).where(
                    Notification.dedup_key == dedup_key, Notification.read_at.is_(None)
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.title = title
            existing.body = body
            existing.severity = severity
            existing.created_at = moment  # bump to top
            await session.flush()
            return existing
    note = Notification(
        category=category,
        severity=severity,
        title=title,
        body=body,
        source=source,
        host_id=host_id,
        volume_id=volume_id,
        dedup_key=dedup_key,
        created_at=moment,
    )
    session.add(note)
    await session.flush()
    _log.info("notification emitted", extra={"category": category, "source": source})
    return note


async def list_notifications(
    session: AsyncSession,
    *,
    scope: ScopeFilter | None = None,
    unread_only: bool = False,
    category: str | None = None,
    limit: int = 50,
) -> list[Notification]:
    """Return notifications visible to the principal, newest first, optionally filtered."""
    stmt = select(Notification).order_by(Notification.created_at.desc(), Notification.id.desc())
    visible = _visible(scope)
    if visible is not None:
        stmt = stmt.where(visible)
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    if category is not None:
        stmt = stmt.where(Notification.category == category)
    return list((await session.execute(stmt.limit(limit))).scalars().all())


async def unread_count(session: AsyncSession, *, scope: ScopeFilter | None = None) -> int:
    """Count unread notifications visible to the principal (the bell badge)."""
    stmt = select(func.count(Notification.id)).where(Notification.read_at.is_(None))
    visible = _visible(scope)
    if visible is not None:
        stmt = stmt.where(visible)
    return int((await session.execute(stmt)).scalar_one())


async def mark_read(
    session: AsyncSession,
    *,
    ids: list[int],
    scope: ScopeFilter | None = None,
    now: datetime | None = None,
) -> int:
    """Mark the given (in-scope, currently-unread) notifications read; return how many changed."""
    if not ids:
        return 0
    stmt = (
        update(Notification)
        .where(Notification.id.in_(ids), Notification.read_at.is_(None))
        .values(read_at=_now(now))
    )
    visible = _visible(scope)
    if visible is not None:
        stmt = stmt.where(visible)
    result = cast(CursorResult[object], await session.execute(stmt))
    await session.flush()
    return int(result.rowcount or 0)


async def mark_all_read(
    session: AsyncSession, *, scope: ScopeFilter | None = None, now: datetime | None = None
) -> int:
    """Mark every in-scope unread notification read; return how many changed."""
    stmt = update(Notification).where(Notification.read_at.is_(None)).values(read_at=_now(now))
    visible = _visible(scope)
    if visible is not None:
        stmt = stmt.where(visible)
    result = cast(CursorResult[object], await session.execute(stmt))
    await session.flush()
    return int(result.rowcount or 0)
