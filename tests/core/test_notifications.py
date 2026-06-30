"""Notification Center service tests (ADR-031) — emit/coalesce, list/filter, unread, mark-read.

The security-relevant bits: estate-wide notifications (no host) are visible to anyone who can view,
host-scoped ones only to a principal whose scope covers that host; mark-read only touches the
principal's own visible, unread rows; and a producer can re-emit a dedup_key without flooding.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.auth.scope import ScopeFilter
from fathom.core import notifications
from fathom.core.catalogue.models import Base
from fathom.core.catalogue.notification_meta import (
    CATEGORY_PROBLEM,
    CATEGORY_RECOMMENDATION,
)


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _emit(session: AsyncSession, **kw: object) -> object:
    kw.setdefault("category", CATEGORY_PROBLEM)
    kw.setdefault("title", "t")
    kw.setdefault("source", "test")
    return await notifications.emit(session, **kw)  # type: ignore[arg-type]


async def test_emit_validates_vocab(session: AsyncSession) -> None:
    with pytest.raises(ValueError, match="category"):
        await notifications.emit(session, category="bogus", title="t", source="s")
    with pytest.raises(ValueError, match="severity"):
        await notifications.emit(
            session, category=CATEGORY_PROBLEM, title="t", source="s", severity="loud"
        )


async def test_emit_list_and_unread(session: AsyncSession) -> None:
    await _emit(session, title="first")
    await _emit(session, title="second", category=CATEGORY_RECOMMENDATION)
    rows = await notifications.list_notifications(session)
    assert [r.title for r in rows] == ["second", "first"]  # newest first
    assert await notifications.unread_count(session) == 2


async def test_dedup_coalesces_then_new_after_read(session: AsyncSession) -> None:
    await _emit(session, title="disk 90%", dedup_key="cap:h1:v1")
    await _emit(session, title="disk 95%", dedup_key="cap:h1:v1")  # same key, still unread
    rows = await notifications.list_notifications(session)
    assert len(rows) == 1
    assert rows[0].title == "disk 95%"  # coalesced + refreshed
    # Once read, the same key starts a fresh notification.
    await notifications.mark_all_read(session)
    await _emit(session, title="disk 97%", dedup_key="cap:h1:v1")
    assert await notifications.unread_count(session) == 1


async def test_dedup_refreshes_same_row_not_stacked(session: AsyncSession) -> None:
    # Re-emitting a still-unread dedup_key updates the SAME row in place (id stable, fields +
    # timestamp refreshed) rather than stacking a second row — asserted via the emit return value,
    # the core helper. (EC-notifications-11)
    t1 = datetime(2026, 6, 27, 12, 0, tzinfo=UTC)
    t2 = datetime(2026, 6, 27, 12, 5, tzinfo=UTC)
    first = await _emit(
        session, title="disk 90%", severity="info", dedup_key="cap:h1:v1", now=t1
    )
    second = await _emit(
        session, title="disk 95%", severity="warning", dedup_key="cap:h1:v1", now=t2
    )
    assert second.id == first.id  # type: ignore[attr-defined]  # same row, not a new one
    assert second.title == "disk 95%"  # type: ignore[attr-defined]  # refreshed
    assert second.severity == "warning"  # type: ignore[attr-defined]
    assert second.created_at == t2  # type: ignore[attr-defined]  # bumped to the top
    assert await notifications.unread_count(session) == 1
    assert len(await notifications.list_notifications(session)) == 1


async def test_filters_unread_and_category(session: AsyncSession) -> None:
    a = await _emit(session, title="prob", category=CATEGORY_PROBLEM)
    await _emit(session, title="rec", category=CATEGORY_RECOMMENDATION)
    await notifications.mark_read(session, ids=[a.id])  # type: ignore[attr-defined]
    unread = await notifications.list_notifications(session, unread_only=True)
    assert [r.title for r in unread] == ["rec"]
    probs = await notifications.list_notifications(session, category=CATEGORY_PROBLEM)
    assert [r.title for r in probs] == ["prob"]


async def test_mark_read_counts(session: AsyncSession) -> None:
    a = await _emit(session)
    b = await _emit(session)
    marked = await notifications.mark_read(session, ids=[a.id, b.id])  # type: ignore[attr-defined]
    assert marked == 2
    assert await notifications.unread_count(session) == 0
    # Re-marking already-read ones changes nothing.
    assert await notifications.mark_read(session, ids=[a.id]) == 0  # type: ignore[attr-defined]


async def test_scope_visibility(session: AsyncSession) -> None:
    await _emit(session, title="estate", host_id=None)  # estate-wide
    await _emit(session, title="host-1", host_id=1)
    await _emit(session, title="host-2", host_id=2)
    scope = ScopeFilter(is_global=False, host_ids=frozenset({1}))
    rows = await notifications.list_notifications(session, scope=scope)
    titles = {r.title for r in rows}
    assert titles == {"estate", "host-1"}  # host-2 hidden
    assert await notifications.unread_count(session, scope=scope) == 2
    # mark-read is scoped too: it can't touch host-2's notification.
    assert await notifications.mark_all_read(session, scope=scope) == 2
    assert await notifications.unread_count(session) == 1  # host-2 still unread (global view)
