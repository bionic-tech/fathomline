"""End-to-end API enforcement: deny-by-default, admin management, boundary isolation."""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

from fathom.api.auth_deps import require
from fathom.auth.models import RoleAssignment, User
from fathom.auth.principal import Capability, Grant, Principal, Role
from fathom.auth.scope import ScopeFilter
from fathom.auth.store import grants_for_user
from fathom.core import db
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


def _principal(grants: tuple[Grant, ...]) -> Principal:
    return Principal(subject="p", source="local", user_id=1, grants=grants)


# --- require() dependency: capability + non-empty scope (EC-auth-6) -----------------------


async def test_require_empty_scope_403() -> None:
    """Capability held (viewer→view_metadata) but a host grant names no host → empty scope → 403."""
    principal = _principal((Grant(role=Role.VIEWER, scope_kind="host", host_id=None),))
    assert principal.has_capability(Capability.VIEW_METADATA) is True
    with pytest.raises(HTTPException) as exc:
        await require(Capability.VIEW_METADATA)(principal)
    assert exc.value.status_code == 403
    assert exc.value.detail == "no scope for capability"


async def test_require_insufficient_capability_403() -> None:
    # The other 403 branch: the role does not confer the capability at all.
    principal = _principal((Grant(role=Role.VIEWER, scope_kind="global"),))
    with pytest.raises(HTTPException) as exc:
        await require(Capability.MANAGE_USERS)(principal)
    assert exc.value.status_code == 403
    assert exc.value.detail == "insufficient capability"


async def test_require_returns_scope_on_success() -> None:
    principal = _principal((Grant(role=Role.ADMIN, scope_kind="global"),))
    scope = await require(Capability.MANAGE_USERS)(principal)
    assert isinstance(scope, ScopeFilter)
    assert scope.is_global is True


# --- grant resolution: identical grants collapse, distinct ones don't (EC-auth-19) -------


async def test_duplicate_identical_grants_collapsed(api_client: httpx.AsyncClient) -> None:
    async with db.session_scope() as session:
        user = User(subject="dup-dan", source="local", is_active=True)
        session.add(user)
        await session.flush()
        for _ in range(2):  # two byte-identical admin/global rows
            session.add(
                RoleAssignment(
                    user_id=user.id, role="admin", scope_kind="global", granted_by="test"
                )
            )
        user_id = user.id
    async with db.session_scope() as session:
        grants = await grants_for_user(session, user_id=user_id)
    assert len(grants) == 1
    assert grants[0].role == Role.ADMIN
    assert grants[0].scope_kind == "global"


async def test_distinct_grants_not_collapsed(api_client: httpx.AsyncClient) -> None:
    async with db.session_scope() as session:
        user = User(subject="multi-mia", source="local", is_active=True)
        session.add(user)
        await session.flush()
        session.add(
            RoleAssignment(user_id=user.id, role="viewer", scope_kind="global", granted_by="test")
        )
        session.add(
            RoleAssignment(user_id=user.id, role="operator", scope_kind="global", granted_by="test")
        )
        user_id = user.id
    async with db.session_scope() as session:
        grants = await grants_for_user(session, user_id=user_id)
    assert len(grants) == 2
    assert {g.role for g in grants} == {Role.VIEWER, Role.OPERATOR}


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
