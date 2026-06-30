"""TOTP MFA enrolment + verify (ADD 13 §4).

Enrol → confirm with a real TOTP code → ``/auth/me`` reports ``mfa_enrolled``. Re-enrolment replaces
the prior secret so ``verify`` always checks the just-issued one (no stale duplicate row).
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlparse

import httpx
import pyotp
from sqlalchemy import select

from fathom.auth.models import MfaEnrollment, User
from fathom.core import db
from tests.api.conftest import seed_principal


def _secret(uri: str) -> str:
    return parse_qs(urlparse(uri).query)["secret"][0]


async def test_mfa_enroll_then_verify_marks_enrolled(api_client: httpx.AsyncClient) -> None:
    hdr = await seed_principal(username="mfauser")

    me = await api_client.get("/api/v1/auth/me", headers=hdr)
    assert me.status_code == 200
    assert me.json()["mfa_enrolled"] is False

    enroll = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    assert enroll.status_code == 200
    secret = _secret(enroll.json()["provisioning_uri"])

    code = pyotp.TOTP(secret).now()
    verify = await api_client.post("/api/v1/auth/mfa/verify", headers=hdr, json={"code": code})
    assert verify.status_code == 204

    me2 = await api_client.get("/api/v1/auth/me", headers=hdr)
    assert me2.json()["mfa_enrolled"] is True


async def test_reenroll_replaces_prior_secret(api_client: httpx.AsyncClient) -> None:
    hdr = await seed_principal(username="reuser")
    first = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    secret1 = _secret(first.json()["provisioning_uri"])
    await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(secret1).now()}
    )

    # Re-enrol issues a fresh secret; the old one must stop working, the new one must verify.
    second = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    secret2 = _secret(second.json()["provisioning_uri"])
    assert secret2 != secret1

    bad = await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(secret1).now()}
    )
    assert bad.status_code == 401  # prior secret replaced — no stale duplicate matches
    good = await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(secret2).now()}
    )
    assert good.status_code == 204


async def test_enroll_unauthenticated_is_401_bearer(api_client: httpx.AsyncClient) -> None:
    # Deny-by-default: an anonymous caller cannot begin enrollment (EC-mfa-4).
    resp = await api_client.post("/api/v1/auth/mfa/enroll")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


async def test_verify_unauthenticated_is_401_bearer(api_client: httpx.AsyncClient) -> None:
    # A well-formed body isolates the failure to the missing principal, not body validation.
    resp = await api_client.post("/api/v1/auth/mfa/verify", json={"code": "123456"})
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


async def test_verify_code_too_short_is_422(api_client: httpx.AsyncClient) -> None:
    # min_length=6 on MfaVerifyRequest.code rejects "12" before the route body runs (EC-mfa-3).
    hdr = await seed_principal(username="shortcode")
    resp = await api_client.post("/api/v1/auth/mfa/verify", headers=hdr, json={"code": "12"})
    assert resp.status_code == 422


async def test_verify_nondigit_code_is_401(api_client: httpx.AsyncClient) -> None:
    # "abcdef" passes the length check but trips verify_totp's isdigit guard → 401 (EC-mfa-3).
    hdr = await seed_principal(username="nondigit")
    enroll = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    assert enroll.status_code == 200  # an enrollment exists, so the 401 is from the digit guard
    resp = await api_client.post("/api/v1/auth/mfa/verify", headers=hdr, json={"code": "abcdef"})
    assert resp.status_code == 401


async def test_concurrent_enroll_yields_single_enrollment(api_client: httpx.AsyncClient) -> None:
    # Two parallel enrolls race the delete-then-insert; under a serialized writer the last
    # writer wins and exactly one row survives — never a stale duplicate (EC-mfa-9). There is
    # no DB UniqueConstraint backing this (see report follow-up); this locks current behaviour.
    hdr = await seed_principal(username="raceuser")
    first, second = await asyncio.gather(
        api_client.post("/api/v1/auth/mfa/enroll", headers=hdr),
        api_client.post("/api/v1/auth/mfa/enroll", headers=hdr),
    )
    assert first.status_code == 200
    assert second.status_code == 200

    async with db.session_scope() as s:
        user_id = await s.scalar(select(User.id).where(User.subject == "raceuser"))
        rows = (
            (await s.execute(select(MfaEnrollment).where(MfaEnrollment.user_id == user_id)))
            .scalars()
            .all()
        )
    assert len(rows) == 1  # single enrollment row, not one per request
    # secret_ref now holds a settings-store REFERENCE, not the raw base32 secret (P0b hardening).
    assert rows[0].secret_ref.startswith("mfa:")

    # The surviving enrollment's secret is one of the two issued; that one verifies and the other
    # (replaced) one does not — exactly one of the two codes is accepted.
    secret1 = _secret(first.json()["provisioning_uri"])
    secret2 = _secret(second.json()["provisioning_uri"])
    statuses = [
        (
            await api_client.post(
                "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(s).now()}
            )
        ).status_code
        for s in (secret1, secret2)
    ]
    assert statuses.count(204) == 1  # the surviving secret verifies
    assert statuses.count(401) == 1  # the replaced secret does not


async def test_reenroll_clears_mfa_enrolled_until_reconfirmed(
    api_client: httpx.AsyncClient,
) -> None:
    # Re-enrolling drops the confirmed row for a fresh, unconfirmed one, so /auth/me reports
    # mfa_enrolled=false in the window before the new secret is reconfirmed
    # (EC-mfa-17 / EC-auth-31).
    hdr = await seed_principal(username="reenrollwindow")
    first = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    secret1 = _secret(first.json()["provisioning_uri"])
    await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(secret1).now()}
    )
    assert (await api_client.get("/api/v1/auth/me", headers=hdr)).json()["mfa_enrolled"] is True

    second = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    secret2 = _secret(second.json()["provisioning_uri"])
    mid = await api_client.get("/api/v1/auth/me", headers=hdr)
    assert mid.json()["mfa_enrolled"] is False  # re-enrolled, not yet reconfirmed

    await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(secret2).now()}
    )
    assert (await api_client.get("/api/v1/auth/me", headers=hdr)).json()["mfa_enrolled"] is True


async def test_enroll_stores_secret_encrypted_not_in_db(api_client: httpx.AsyncClient) -> None:
    # P0b hardening (ADR-010): a NEW enrollment must persist only a REFERENCE in secret_ref — the
    # raw base32 secret never lands in the DB. The secret resolves through the encrypted settings
    # store (so verify still works), and the stored column is neither the secret nor a TOTP-usable
    # value.
    hdr = await seed_principal(username="encuser")
    enroll = await api_client.post("/api/v1/auth/mfa/enroll", headers=hdr)
    assert enroll.status_code == 200
    secret = _secret(enroll.json()["provisioning_uri"])

    async with db.session_scope() as s:
        user_id = await s.scalar(select(User.id).where(User.subject == "encuser"))
        row = (
            await s.execute(select(MfaEnrollment).where(MfaEnrollment.user_id == user_id))
        ).scalar_one()
    # The DB holds a reference, NOT the raw secret (the ADR-010 invariant being restored). The
    # stored ref is not even valid base32, so it could never be used as a TOTP secret directly.
    assert row.secret_ref != secret
    assert row.secret_ref.startswith("mfa:")

    # The encrypted, store-backed secret still verifies — hardening did not break enrollment.
    good = await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(secret).now()}
    )
    assert good.status_code == 204


async def test_legacy_raw_secret_ref_still_verifies(api_client: httpx.AsyncClient) -> None:
    # BACKWARD COMPAT: an enrollment written before the hardening holds the RAW base32 secret in
    # secret_ref (the live nas-1 enrollment). It must keep verifying via the fallback — no bulk
    # migration, no lockout — until the user re-enrolls (which then stores it encrypted).
    hdr = await seed_principal(username="legacyuser")
    raw_secret = pyotp.random_base32()
    async with db.session_scope() as s:
        user_id = await s.scalar(select(User.id).where(User.subject == "legacyuser"))
        s.add(MfaEnrollment(user_id=user_id, type="totp", secret_ref=raw_secret))

    # The raw secret_ref does not resolve in the store, so verify treats it as the secret directly.
    good = await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": pyotp.TOTP(raw_secret).now()}
    )
    assert good.status_code == 204
    bad = await api_client.post(
        "/api/v1/auth/mfa/verify", headers=hdr, json={"code": "000000"}
    )
    assert bad.status_code == 401
