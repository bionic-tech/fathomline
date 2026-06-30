"""Auth-event audit durability (EC-auth-27 divergence fix).

``routers/auth._audit`` was a no-op lambda, so login / MFA events were never queryable. It now
appends to the durable hash-chained store. These tests lock that contract — including that a
*denied* login persists despite the request rolling back on the 401 (a failed auth attempt is
exactly what the security audit must retain).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pyotp
from sqlalchemy import select

from fathom.core import db
from fathom.core.audit import verify_chain
from fathom.core.audit_store import persisted_records
from fathom.core.remediation.models import RemediationAuditRow
from tests.api.conftest import seed_principal

_PASSWORD = "correct horse battery staple"  # the password seed_principal sets


async def _audit_pairs() -> set[tuple[str, str]]:
    """Return the set of (action, result) audit rows currently persisted."""
    async with db.session_scope() as s:
        rows = (
            await s.execute(select(RemediationAuditRow.action, RemediationAuditRow.result))
        ).all()
    return {(action, result) for action, result in rows}


async def test_successful_login_is_audited(api_client: httpx.AsyncClient) -> None:
    await seed_principal(username="loginok")
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "loginok", "password": _PASSWORD}
    )
    assert resp.status_code == 204, resp.text
    assert ("auth.login", "granted") in await _audit_pairs()


async def test_denied_login_is_audited_despite_rollback(api_client: httpx.AsyncClient) -> None:
    await seed_principal(username="loginbad")
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "loginbad", "password": "wrong-password"}
    )
    assert resp.status_code == 401, resp.text
    # The request rolled back on the 401, but the denied event was committed independently.
    assert ("auth.login", "denied") in await _audit_pairs()


async def test_unknown_user_login_is_audited(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "ghost", "password": _PASSWORD}
    )
    assert resp.status_code == 401, resp.text
    assert ("auth.login", "denied") in await _audit_pairs()


async def test_mfa_enroll_and_verify_are_audited(api_client: httpx.AsyncClient) -> None:
    hdr = await seed_principal(username="mfaaudit")
    enroll = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    secret = parse_qs(urlparse(enroll.json()["provisioning_uri"]).query)["secret"][0]
    # A bad code first (denied, committed before the 401), then a good one (granted).
    await api_client.post("/api/v1/auth/mfa/verify", headers=hdr, json={"code": "000000"})
    good = await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(secret).now()}
    )
    assert good.status_code == 204, good.text
    pairs = await _audit_pairs()
    assert ("auth.mfa.enroll", "pending") in pairs
    assert ("auth.mfa.verify", "denied") in pairs
    assert ("auth.mfa.verify", "granted") in pairs


async def test_audit_chain_stays_unbroken_across_events(api_client: httpx.AsyncClient) -> None:
    """Each event re-links onto the persisted head — the chain must verify end to end."""
    await seed_principal(username="chainuser")
    await api_client.post(
        "/api/v1/auth/login", json={"username": "chainuser", "password": _PASSWORD}
    )
    await api_client.post(
        "/api/v1/auth/login", json={"username": "chainuser", "password": "nope"}
    )
    async with db.session_scope() as s:
        records = await persisted_records(s)
    assert len(records) >= 2
    assert verify_chain(records)
