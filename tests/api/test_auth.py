"""Auth-router integration beyond the local MFA happy path (ADD 13, ADD 03 §2).

A session-less federated principal (forward-auth) can confirm a TOTP enrollment — ``mfa_enrolled``
flips true — but, having no Fathom session row to stamp, never gains step-up freshness: ``/auth/me``
reports ``mfa_fresh`` false and any step-up-gated write stays denied (EC-mfa-11 / EC-mfa-23 /
EC-auth-29). The forward provider only trusts identity headers from the configured trusted-proxy
source, so the fixture pins the loopback CIDR the test transport reports.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pyotp
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.settings import Settings


def _secret(uri: str) -> str:
    return parse_qs(urlparse(uri).query)["secret"][0]


@pytest.fixture
async def forward_client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    """An ASGI client whose requests are trusted as forward-auth (trusted CIDR = loopback).

    The test transport reports client 127.0.0.1, so a 127.0.0.1/32 trusted-proxy CIDR lets a
    ``Remote-User`` header assert a federated (session-less) principal end to end.
    """
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'fwd.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        trusted_forward_proxy_cidrs=("127.0.0.1/32",),
    )
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def test_forward_principal_authenticates(forward_client: httpx.AsyncClient) -> None:
    # Sanity: the loopback-trusted Remote-User header yields a forward-sourced principal with no
    # session-backed step-up.
    me = await forward_client.get("/api/v1/auth/me", headers={"Remote-User": "fwduser"})
    assert me.status_code == 200
    body = me.json()
    assert body["source"] == "forward"
    assert body["subject"] == "fwduser"
    assert body["mfa_enrolled"] is False
    assert body["mfa_fresh"] is False


async def test_session_less_verify_confirms_enrollment_but_no_step_up(
    forward_client: httpx.AsyncClient,
) -> None:
    fwd = {"Remote-User": "fwdverify"}
    enroll = await forward_client.post("/api/v1/auth/mfa/enroll", headers=fwd)
    assert enroll.status_code == 200
    secret = _secret(enroll.json()["provisioning_uri"])

    verify = await forward_client.post(
        "/api/v1/auth/mfa/verify", headers=fwd, json={"code": pyotp.TOTP(secret).now()}
    )
    assert verify.status_code == 204  # a valid code confirms the enrollment...

    me = await forward_client.get("/api/v1/auth/me", headers=fwd)
    body = me.json()
    assert body["mfa_enrolled"] is True  # ...so the second factor is now registered,
    # ...but with no session row to stamp, mfa_authenticated_at stays unset and step-up is never
    # fresh — the exact freshness oracle require_step_up_mfa consults to gate destructive writes.
    assert body["mfa_fresh"] is False
