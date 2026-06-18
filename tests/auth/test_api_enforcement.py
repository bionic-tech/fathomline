"""End-to-end API enforcement: deny-by-default, admin management, boundary isolation."""

from __future__ import annotations

import httpx

from fathom.auth.principal import Role
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


async def test_agent_ingest_boundary_unaffected_by_human_auth(
    api_client: httpx.AsyncClient,
) -> None:
    # The agent mTLS ingest route authenticates by fingerprint only — no human session, and a
    # human bearer must neither help nor be required (separate boundary, ADD 03 §3 / AR-0012).
    no_cert = await api_client.post("/api/v1/agents/ingest", json=batch())
    assert no_cert.status_code == 401  # still fingerprint-gated
    with_cert = await api_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    assert with_cert.status_code == 200  # fingerprint alone suffices; no human auth attached


async def test_admin_can_manage_users(api_client: httpx.AsyncClient) -> None:
    admin = await seed_principal(username="root", role=Role.ADMIN)
    created = await api_client.post(
        "/api/v1/users",
        json={"username": "newbie", "password": "longenoughpass"},
        headers=admin,
    )
    assert created.status_code == 201
    user_id = created.json()["id"]
    grant = await api_client.post(
        f"/api/v1/users/{user_id}/assignments",
        json={"role": "viewer", "scope_kind": "global"},
        headers=admin,
    )
    assert grant.status_code == 201
    listing = await api_client.get("/api/v1/users", headers=admin)
    assert listing.status_code == 200
    assert any(u["subject"] == "newbie" for u in listing.json())


async def test_viewer_cannot_manage_users_403(api_client: httpx.AsyncClient) -> None:
    viewer = await seed_principal(username="lookey", role=Role.VIEWER)
    resp = await api_client.post(
        "/api/v1/users",
        json={"username": "x", "password": "longenoughpass"},
        headers=viewer,
    )
    assert resp.status_code == 403  # deny-by-default: no MANAGE_USERS


async def test_auditor_cannot_manage_users_403(api_client: httpx.AsyncClient) -> None:
    auditor = await seed_principal(username="reviewer", role=Role.AUDITOR)
    resp = await api_client.post(
        "/api/v1/users",
        json={"username": "y", "password": "longenoughpass"},
        headers=auditor,
    )
    assert resp.status_code == 403


async def test_unknown_assignment_role_422(api_client: httpx.AsyncClient) -> None:
    admin = await seed_principal(username="root2", role=Role.ADMIN)
    created = await api_client.post(
        "/api/v1/users",
        json={"username": "tgt", "password": "longenoughpass"},
        headers=admin,
    )
    user_id = created.json()["id"]
    resp = await api_client.post(
        f"/api/v1/users/{user_id}/assignments",
        json={"role": "superuser", "scope_kind": "global"},
        headers=admin,
    )
    assert resp.status_code == 422


async def test_assignment_revoke(api_client: httpx.AsyncClient) -> None:
    admin = await seed_principal(username="root3", role=Role.ADMIN)
    created = await api_client.post(
        "/api/v1/users",
        json={"username": "tgt2", "password": "longenoughpass"},
        headers=admin,
    )
    user_id = created.json()["id"]
    grant = await api_client.post(
        f"/api/v1/users/{user_id}/assignments",
        json={"role": "viewer", "scope_kind": "global"},
        headers=admin,
    )
    assignment_id = grant.json()["id"]
    revoke = await api_client.request(
        "DELETE",
        f"/api/v1/users/{user_id}/assignments/{assignment_id}",
        headers=admin,
    )
    assert revoke.status_code == 204
