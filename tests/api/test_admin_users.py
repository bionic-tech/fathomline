"""Admin user/assignment route tests (ADD 13) — the lockout guard + durable audit.

Covers two spec-vs-code fixes (docs/spec/rbac-users.md, GAPS.md divergences):
- EC-rbac-24: revoking the LAST global-admin grant is refused (409) — no self-lockout.
- EC-rbac-25: user-admin mutations are appended to the durable hash-chained audit (the sink was a
  no-op, so grants/revokes vanished). A create now persists an audit row.
"""

from __future__ import annotations

import httpx
from sqlalchemy import func, select

from fathom.auth.models import RoleAssignment
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.remediation.models import RemediationAuditRow
from tests.api.conftest import seed_principal


async def _global_admin_assignment() -> tuple[int, int]:
    """Return (user_id, assignment_id) of a global-admin grant (seed_principal makes one)."""
    async with db.session_scope() as s:
        a = (
            await s.execute(
                select(RoleAssignment)
                .where(RoleAssignment.role == "admin", RoleAssignment.scope_kind == "global")
                .order_by(RoleAssignment.id)
            )
        ).scalars().first()
        assert a is not None
        return a.user_id, a.id


async def test_cannot_revoke_last_global_admin(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")  # one admin/global grant
    uid, aid = await _global_admin_assignment()
    resp = await api_client.delete(f"/api/v1/users/{uid}/assignments/{aid}", headers=auth)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"] == "cannot revoke the last global admin"


async def test_revoke_admin_succeeds_when_another_exists(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    uid1, aid1 = await _global_admin_assignment()
    # Grant a SECOND global admin via the API, then the first becomes safely revocable.
    created = await api_client.post(
        "/api/v1/users",
        json={"username": "admin2", "password": "password123"},
        headers=auth,
    )
    uid2 = created.json()["id"]
    grant = await api_client.post(
        f"/api/v1/users/{uid2}/assignments",
        json={"role": "admin", "scope_kind": "global"},
        headers=auth,
    )
    assert grant.status_code == 201, grant.text
    resp = await api_client.delete(f"/api/v1/users/{uid1}/assignments/{aid1}", headers=auth)
    assert resp.status_code == 204, resp.text


async def test_user_admin_actions_are_audited(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    async with db.session_scope() as s:
        before = (
            await s.execute(select(func.count()).select_from(RemediationAuditRow))
        ).scalar_one()
    await api_client.post(
        "/api/v1/users",
        json={"username": "bob", "password": "password123"},
        headers=auth,
    )
    async with db.session_scope() as s:
        after = (
            await s.execute(select(func.count()).select_from(RemediationAuditRow))
        ).scalar_one()
        actions = set(
            (await s.execute(select(RemediationAuditRow.action))).scalars().all()
        )
    assert after > before  # the audit sink persists now (was a no-op)
    assert "users.create" in actions


# --- EC-rbac-3: GET /users/{id}/assignments (the missing read counterpart) -------------------


async def test_list_assignments_returns_user_grants(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    created = await api_client.post(
        "/api/v1/users",
        json={"username": "carol", "password": "password123"},
        headers=auth,
    )
    uid = created.json()["id"]
    for role in ("viewer", "operator"):
        grant = await api_client.post(
            f"/api/v1/users/{uid}/assignments",
            json={"role": role, "scope_kind": "global"},
            headers=auth,
        )
        assert grant.status_code == 201, grant.text
    resp = await api_client.get(f"/api/v1/users/{uid}/assignments", headers=auth)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [a["role"] for a in body] == ["viewer", "operator"]  # ordered by id
    first = body[0]
    assert first["user_id"] == uid
    assert first["scope_kind"] == "global"
    assert first["host_id"] is None and first["volume_id"] is None
    assert "id" in first


async def test_list_assignments_unknown_user_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    resp = await api_client.get("/api/v1/users/999999/assignments", headers=auth)
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown user"


async def test_list_assignments_requires_auth_401(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.get("/api/v1/users/1/assignments")
    assert resp.status_code == 401, resp.text
    assert resp.headers["WWW-Authenticate"] == "Bearer"


async def test_list_assignments_requires_capability_403(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="viewer1", role=Role.VIEWER)  # no MANAGE_USERS
    # The MANAGE_USERS gate denies before the route body runs, so the user_id need not exist.
    resp = await api_client.get("/api/v1/users/1/assignments", headers=auth)
    assert resp.status_code == 403, resp.text


# --- EC-rbac-8: grant to an unknown user is 404 ----------------------------------------------


async def test_grant_unknown_user_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    resp = await api_client.post(
        "/api/v1/users/999999/assignments",
        json={"role": "viewer", "scope_kind": "global"},  # valid body → reaches the user lookup
        headers=auth,
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown user"


# --- EC-rbac-9: revoke a missing / cross-user assignment is 404 ------------------------------


async def test_revoke_missing_assignment_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    uid, _aid = await _global_admin_assignment()
    resp = await api_client.delete(f"/api/v1/users/{uid}/assignments/999999", headers=auth)
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown assignment"


async def test_revoke_cross_user_assignment_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    admin_uid, _aid = await _global_admin_assignment()
    created = await api_client.post(
        "/api/v1/users",
        json={"username": "carol", "password": "password123"},
        headers=auth,
    )
    carol_uid = created.json()["id"]
    grant = await api_client.post(
        f"/api/v1/users/{carol_uid}/assignments",
        json={"role": "viewer", "scope_kind": "global"},
        headers=auth,
    )
    carol_aid = grant.json()["id"]
    # Carol's assignment under the WRONG user_id (the admin's) → user_id mismatch → 404.
    resp = await api_client.delete(
        f"/api/v1/users/{admin_uid}/assignments/{carol_aid}", headers=auth
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown assignment"


# --- EC-rbac-11/12/13: scope validation is 422 ----------------------------------------------


async def test_grant_unknown_scope_kind_422(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    uid, _aid = await _global_admin_assignment()
    resp = await api_client.post(
        f"/api/v1/users/{uid}/assignments",
        json={"role": "viewer", "scope_kind": "galaxy"},
        headers=auth,
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "unknown scope_kind"


async def test_grant_host_scope_missing_host_id_422(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    uid, _aid = await _global_admin_assignment()
    resp = await api_client.post(
        f"/api/v1/users/{uid}/assignments",
        json={"role": "viewer", "scope_kind": "host"},
        headers=auth,
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "host scope needs host_id"


async def test_grant_volume_scope_missing_volume_id_422(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    uid, _aid = await _global_admin_assignment()
    resp = await api_client.post(
        f"/api/v1/users/{uid}/assignments",
        json={"role": "viewer", "scope_kind": "volume"},
        headers=auth,
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "volume scope needs volume_id"


# --- EC-rbac-15: a duplicate local user is 409 ----------------------------------------------


async def test_create_duplicate_local_user_409(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="admin1")
    body = {"username": "dave", "password": "password123"}
    first = await api_client.post("/api/v1/users", json=body, headers=auth)
    assert first.status_code == 201, first.text
    second = await api_client.post("/api/v1/users", json=body, headers=auth)
    assert second.status_code == 409, second.text
    assert second.json()["detail"] == "user exists"


# --- EC-rbac-6: unauthenticated user routes are 401 + WWW-Authenticate: Bearer ---------------


async def test_list_users_unauthenticated_401(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.get("/api/v1/users")
    assert resp.status_code == 401, resp.text
    assert resp.headers["WWW-Authenticate"] == "Bearer"


async def test_create_user_unauthenticated_401(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post(
        "/api/v1/users", json={"username": "x", "password": "password123"}
    )
    assert resp.status_code == 401, resp.text
    assert resp.headers["WWW-Authenticate"] == "Bearer"


# --- EC-rbac-26: create records a real before-state; rejection paths emit no audit row -------


async def test_create_audit_records_before_state(api_client: httpx.AsyncClient) -> None:
    """A create persists a 'granted' audit row whose before_state is the real prior state.

    For a creation the prior state is empty (the user did not exist), so before_state is {}.
    """
    auth = await seed_principal(username="admin1")
    await api_client.post(
        "/api/v1/users",
        json={"username": "erin", "password": "password123"},
        headers=auth,
    )
    async with db.session_scope() as s:
        row = (
            await s.execute(
                select(RemediationAuditRow)
                .where(RemediationAuditRow.action == "users.create")
                .where(RemediationAuditRow.target == "erin")
            )
        ).scalar_one()
    assert row.result == "granted"
    assert row.before_state == {}


async def test_rejection_paths_emit_no_denied_audit(api_client: httpx.AsyncClient) -> None:
    """Documents CURRENT behaviour (EC-rbac-26): rejection paths do NOT write an audit row.

    The router only audits on the success path; a 409/404/422 raises before ``_audit`` and the
    request transaction is rolled back, so no row — and in particular no result='denied' row — is
    persisted. This is asserted (not aspirational) per the gap brief; denied-path auditing is left
    unimplemented to avoid over-engineering the audit surface.
    """
    auth = await seed_principal(username="admin1")
    await api_client.post(
        "/api/v1/users",
        json={"username": "frank", "password": "password123"},
        headers=auth,
    )
    async with db.session_scope() as s:
        before = (
            await s.execute(select(func.count()).select_from(RemediationAuditRow))
        ).scalar_one()
    # Three rejection paths: duplicate (409), unknown-user grant (404), bad scope (422).
    dup = await api_client.post(
        "/api/v1/users", json={"username": "frank", "password": "password123"}, headers=auth
    )
    assert dup.status_code == 409
    bad_user = await api_client.post(
        "/api/v1/users/999999/assignments",
        json={"role": "viewer", "scope_kind": "global"},
        headers=auth,
    )
    assert bad_user.status_code == 404
    bad_scope = await api_client.post(
        "/api/v1/users/1/assignments",
        json={"role": "viewer", "scope_kind": "galaxy"},
        headers=auth,
    )
    assert bad_scope.status_code == 422
    async with db.session_scope() as s:
        after = (
            await s.execute(select(func.count()).select_from(RemediationAuditRow))
        ).scalar_one()
        denied = (
            await s.execute(
                select(func.count())
                .select_from(RemediationAuditRow)
                .where(RemediationAuditRow.result == "denied")
            )
        ).scalar_one()
    assert after == before  # no audit row written on any rejection path
    assert denied == 0  # current behaviour: no 'denied' audit rows exist
