"""Notification Center route tests (ADR-031) — the gate, listing, badge, mark-read, and scope.

The bell routes are read-class (VIEW_METADATA + scope) and default-OFF behind notifications_enabled.
These assert the gate, the list + unread badge, mark-read flipping state, auth, and that a
host-scoped principal sees estate-wide + in-scope notifications but not another host's.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.auth.principal import Role
from fathom.core import db, notifications
from fathom.core.catalogue.notification_meta import CATEGORY_PROBLEM
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal


@pytest.fixture
async def notif_client(tmp_path: object) -> AsyncIterator[httpx.AsyncClient]:
    """A client whose app has the Notification Center enabled (the default app keeps it OFF)."""
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/cat.db",  # type: ignore[attr-defined]
        auto_create_schema=True,
        session_cookie_secure=False,
        notifications_enabled=True,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def _seed(**kw: object) -> None:
    kw.setdefault("category", CATEGORY_PROBLEM)
    kw.setdefault("title", "t")
    kw.setdefault("source", "test")
    async with db.session_scope() as session:
        await notifications.emit(session, **kw)  # type: ignore[arg-type]


async def test_disabled_by_default(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/notifications", headers=auth)
    assert resp.status_code == 403  # notifications_enabled=False on the default app


async def test_requires_auth(notif_client: httpx.AsyncClient) -> None:
    assert (await notif_client.get("/api/v1/notifications")).status_code == 401


async def test_list_and_unread_badge(notif_client: httpx.AsyncClient) -> None:
    await _seed(title="alpha")
    await _seed(title="beta")
    auth = await seed_principal()
    resp = await notif_client.get("/api/v1/notifications", headers=auth)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [i["title"] for i in body["items"]] == ["beta", "alpha"]  # newest first
    assert body["unread_count"] == 2
    badge = await notif_client.get("/api/v1/notifications/unread-count", headers=auth)
    assert badge.json()["unread_count"] == 2


async def test_mark_read_flow(notif_client: httpx.AsyncClient) -> None:
    await _seed(title="one")
    await _seed(title="two")
    auth = await seed_principal()
    items = (await notif_client.get("/api/v1/notifications", headers=auth)).json()["items"]
    first_id = items[0]["id"]
    r = await notif_client.post(
        "/api/v1/notifications/mark-read", json={"ids": [first_id]}, headers=auth
    )
    assert r.json()["marked"] == 1
    assert (
        await notif_client.get("/api/v1/notifications/unread-count", headers=auth)
    ).json()["unread_count"] == 1
    r2 = await notif_client.post("/api/v1/notifications/mark-all-read", headers=auth)
    assert r2.json()["marked"] == 1
    assert (
        await notif_client.get("/api/v1/notifications/unread-count", headers=auth)
    ).json()["unread_count"] == 0


async def test_scope_filters_host_notifications(notif_client: httpx.AsyncClient) -> None:
    await _seed(title="estate", host_id=None)
    await _seed(title="host-7", host_id=7)
    await _seed(title="host-9", host_id=9)
    scoped = await seed_principal(username="scoped", scope_kind="host", host_id=7)
    body = (await notif_client.get("/api/v1/notifications", headers=scoped)).json()
    titles = {i["title"] for i in body["items"]}
    assert titles == {"estate", "host-7"}  # host-9 never leaks
    assert body["unread_count"] == 2


async def test_list_caps_at_requested_limit_newest_first(
    notif_client: httpx.AsyncClient,
) -> None:
    # Seed well past a page (60 rows); a request caps at the requested limit, newest-first, while
    # the unread badge counts every unread row (not just the page). (EC-notifications-10)
    async with db.session_scope() as session:
        for i in range(60):
            await notifications.emit(
                session, category=CATEGORY_PROBLEM, title=f"n{i:02d}", source="test"
            )
    auth = await seed_principal()
    body = (await notif_client.get("/api/v1/notifications?limit=25", headers=auth)).json()
    assert len(body["items"]) == 25  # capped at the requested limit
    assert body["items"][0]["title"] == "n59"  # newest first (the last-seeded row)
    ids = [i["id"] for i in body["items"]]
    assert ids == sorted(ids, reverse=True)  # strictly newest-first by id
    assert body["unread_count"] == 60  # the badge counts all unread, not just the page
    # No explicit limit → the default page cap (50) still applies.
    default = await notif_client.get("/api/v1/notifications", headers=auth)
    assert len(default.json()["items"]) == 50


async def test_limit_out_of_bounds_is_422(notif_client: httpx.AsyncClient) -> None:
    # limit is constrained 1..200 (Query ge=1, le=200) → either bound violated is a 422.
    # (EC-notifications-10)
    auth = await seed_principal()
    lo = await notif_client.get("/api/v1/notifications?limit=0", headers=auth)
    assert lo.status_code == 422
    hi = await notif_client.get("/api/v1/notifications?limit=201", headers=auth)
    assert hi.status_code == 422


async def test_mark_read_too_many_ids_is_422(notif_client: httpx.AsyncClient) -> None:
    # MarkReadRequest.ids caps at 1000 (Field max_length) → 1001 ids is a body-validation 422.
    # (EC-notifications-5)
    auth = await seed_principal()
    resp = await notif_client.post(
        "/api/v1/notifications/mark-read", json={"ids": list(range(1001))}, headers=auth
    )
    assert resp.status_code == 422


async def test_unknown_category_filter_is_422(notif_client: httpx.AsyncClient) -> None:
    # A category outside the vocabulary is rejected by the route (422 "unknown category"), not
    # silently treated as "match nothing". (EC-notifications-5)
    auth = await seed_principal()
    resp = await notif_client.get("/api/v1/notifications?category=bogus", headers=auth)
    assert resp.status_code == 422
    assert resp.json()["detail"] == "unknown category"


async def test_test_endpoint_does_not_require_step_up_mfa(api_client: httpx.AsyncClient) -> None:
    # The connectivity test is admin-only (MANAGE_SETTINGS) but DELIBERATELY not step-up-MFA gated
    # (an admin verifies channels before arming the master gate) and not gated on
    # notifications_enabled — so it succeeds for an admin with no fresh MFA. (UC-notifications-8)
    admin = await seed_principal(role=Role.ADMIN, mfa_fresh=False)
    resp = await api_client.post("/api/v1/notifications/test", headers=admin)
    assert resp.status_code == 200  # no fresh MFA challenge
    assert resp.json()["results"] == []  # the default app has no channels enabled
