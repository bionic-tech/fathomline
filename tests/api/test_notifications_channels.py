"""Notification channel API tests (ADR-039) — the admin connectivity-test endpoint, end to end.

Drives the full live path: an admin configures a channel through the runtime settings store
(ADR-038) — including the webhook secret — then POSTs the connectivity test, and a fake transport
on ``app.state`` records the send. Also covers RBAC (admin-only) and the "no channels" case.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal


@dataclass
class FakeTransport:
    posts: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    emails: list[dict[str, Any]] = field(default_factory=list)

    async def post_json(self, url: str, payload: dict[str, Any], *, timeout_seconds: float) -> None:
        self.posts.append((url, payload))

    async def send_email(self, **kw: Any) -> None:
        self.emails.append(kw)


@pytest.fixture
async def app_client(
    settings: Settings,
) -> AsyncIterator[tuple[httpx.AsyncClient, FakeTransport]]:
    await db.dispose_engine()
    app = create_app(settings)
    transport = FakeTransport()
    async with LifespanManager(app):
        app.state.notify_transport = transport  # injected so no real network is touched
        asgi = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=asgi, base_url="http://test") as client:
            yield client, transport
    await db.dispose_engine()


async def test_test_endpoint_requires_admin(
    app_client: tuple[httpx.AsyncClient, FakeTransport],
) -> None:
    client, _ = app_client
    assert (await client.post("/api/v1/notifications/test")).status_code == 401
    operator = await seed_principal(role=Role.OPERATOR)
    assert (await client.post("/api/v1/notifications/test", headers=operator)).status_code == 403


async def test_test_endpoint_no_channels_is_empty(
    app_client: tuple[httpx.AsyncClient, FakeTransport],
) -> None:
    client, _ = app_client
    admin = await seed_principal(role=Role.ADMIN)
    resp = await client.post("/api/v1/notifications/test", headers=admin)
    assert resp.status_code == 200
    assert resp.json()["results"] == []


async def test_configure_chat_then_test_sends(
    app_client: tuple[httpx.AsyncClient, FakeTransport],
) -> None:
    client, transport = app_client
    admin = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    # Configure the Discord chat channel live through the settings store, secret included.
    for key, value in [
        ("notify_chat_enabled", True),
        ("notify_chat_kind", "discord"),
        ("notify_chat_webhook_ref", "DISCORD_HOOK"),
    ]:
        r = await client.put(f"/api/v1/settings/{key}", json={"value": value}, headers=admin)
        assert r.status_code == 200, (key, r.text)
    r = await client.put(
        "/api/v1/settings/secrets",
        json={"ref": "DISCORD_HOOK", "value": "https://discord.example/webhook"},
        headers=admin,
    )
    assert r.status_code == 200
    # Run the connectivity test — the fake transport records the webhook POST.
    resp = await client.post("/api/v1/notifications/test", headers=admin)
    assert resp.status_code == 200
    results = {r["channel"]: r for r in resp.json()["results"]}
    assert results["chat:discord"]["ok"] is True
    assert transport.posts and transport.posts[0][0] == "https://discord.example/webhook"
    assert "content" in transport.posts[0][1]
