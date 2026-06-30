"""Provider-chain, local-auth and OIDC SSRF/id_token tests (ADD 03 §2, ADR-009)."""

from __future__ import annotations

import contextlib
import socket
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import httpx
import jwt
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy import update

from fathom.api.app import create_app
from fathom.auth import passwords
from fathom.auth.models import User
from fathom.auth.passwords import hash_password
from fathom.auth.principal import Role
from fathom.auth.providers import oidc
from fathom.auth.providers.local import SESSION_COOKIE, extract_session_token
from fathom.auth.providers.oidc import (
    ALLOWED_ALGS,
    OidcError,
    assert_url_allowed,
    build_jwks_client,
    fetch_discovery_document,
    validate_id_token,
)
from fathom.auth.sessions import create_session
from fathom.core import db
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal

# --- local provider / password ----------------------------------------------------------


def test_argon2_roundtrip() -> None:
    h = passwords.hash_password("s3cret-pass")
    assert passwords.verify_password("s3cret-pass", h) is True
    assert passwords.verify_password("wrong", h) is False


def test_verify_rejects_garbage_hash() -> None:
    assert passwords.verify_password("x", "not-a-hash") is False


async def test_login_flow_and_me(api_client: httpx.AsyncClient) -> None:
    # seed a local user (password fixed in the helper) and confirm /me reflects the principal.
    auth = await seed_principal(username="alice", mfa_fresh=False)
    resp = await api_client.get("/api/v1/auth/me", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert body["subject"] == "alice"
    assert body["source"] == "local"
    assert body["mfa_fresh"] is False


async def test_login_wrong_password_401(api_client: httpx.AsyncClient) -> None:
    await seed_principal(username="bob")
    resp = await api_client.post("/api/v1/auth/login", json={"username": "bob", "password": "nope"})
    assert resp.status_code == 401


async def test_login_unknown_user_401(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "ghost", "password": "whatever"}
    )
    assert resp.status_code == 401


async def test_login_then_logout_revokes(api_client: httpx.AsyncClient) -> None:
    await seed_principal(username="carol")
    login = await api_client.post(
        "/api/v1/auth/login",
        json={"username": "carol", "password": "correct horse battery staple"},
    )
    assert login.status_code == 204
    # The cookie is now on the client; /me works.
    me = await api_client.get("/api/v1/auth/me")
    assert me.status_code == 200
    out = await api_client.post("/api/v1/auth/logout")
    assert out.status_code == 204
    # After logout the (revoked) session is rejected → 401.
    me2 = await api_client.get("/api/v1/auth/me")
    assert me2.status_code == 401


async def test_no_credentials_401(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.get("/api/v1/auth/me")
    assert resp.status_code == 401


# --- session lifecycle 401s (EC-auth-3 / EC-auth-5) --------------------------------------


async def test_expired_session_me_401(api_client: httpx.AsyncClient) -> None:
    """A live token whose session row has a past ``expires_at`` is rejected (EC-auth-3)."""
    async with db.session_scope() as session:
        user = User(
            subject="exp-erin",
            source="local",
            display_name="exp-erin",
            password_hash=hash_password("pw"),
            is_active=True,
        )
        session.add(user)
        await session.flush()
        row, raw = await create_session(session, user_id=user.id, ttl_seconds=3600)
        # Backdate absolute expiry: lookup_session must treat this as expired (fail-closed).
        row.expires_at = datetime.now(tz=UTC) - timedelta(seconds=60)
    resp = await api_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 401


async def test_inactive_user_me_401(api_client: httpx.AsyncClient) -> None:
    """Deactivating the user invalidates an otherwise-live session immediately (EC-auth-5)."""
    auth = await seed_principal(username="inactive-ivan", role=Role.VIEWER)
    ok = await api_client.get("/api/v1/auth/me", headers=auth)
    assert ok.status_code == 200  # session is live before deactivation
    async with db.session_scope() as session:
        await session.execute(
            update(User).where(User.subject == "inactive-ivan").values(is_active=False)
        )
    resp = await api_client.get("/api/v1/auth/me", headers=auth)
    assert resp.status_code == 401


# --- login / MFA input validation (422 before DB access) — EC-auth-12 --------------------


async def test_login_empty_username_422(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "", "password": "whatever-pw"}
    )
    assert resp.status_code == 422  # username min_length=1


async def test_login_oversized_password_422(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "p" * 2048}
    )
    assert resp.status_code == 422  # password max_length=1024 → ~2KB rejected


async def test_mfa_verify_malformed_code_422(api_client: httpx.AsyncClient) -> None:
    # Authenticated so the principal dependency resolves; the body still fails validation → 422.
    auth = await seed_principal(username="mfa-mona", role=Role.VIEWER)
    too_short = await api_client.post(
        "/api/v1/auth/mfa/verify", json={"code": "123"}, headers=auth
    )
    assert too_short.status_code == 422  # code min_length=6
    too_long = await api_client.post(
        "/api/v1/auth/mfa/verify", json={"code": "123456789"}, headers=auth
    )
    assert too_long.status_code == 422  # code max_length=8


# --- session cookie flags (EC-auth-21) ---------------------------------------------------


@contextlib.asynccontextmanager
async def _client_with_settings(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    """A throwaway ASGI client over an app built from ``settings`` (mirrors api_client)."""
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def test_login_cookie_flags_secure(settings: Settings) -> None:
    """The login Set-Cookie carries HttpOnly, SameSite=Strict and Secure (secure=True)."""
    secure = settings.model_copy(update={"session_cookie_secure": True})
    async with _client_with_settings(secure) as client:
        await seed_principal(username="cookie-carl", role=Role.VIEWER)
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "cookie-carl", "password": "correct horse battery staple"},
        )
        assert resp.status_code == 204
        set_cookie = resp.headers.get("set-cookie", "").lower()
        assert SESSION_COOKIE in set_cookie
        assert "httponly" in set_cookie
        assert "samesite=strict" in set_cookie
        assert "secure" in set_cookie


# --- extract_session_token edge cases (EC-auth-30) ---------------------------------------


def _fake_request(
    *, cookies: dict[str, str] | None = None, headers: dict[str, str] | None = None
) -> MagicMock:
    req = MagicMock()
    req.cookies = cookies or {}
    req.headers = headers or {}
    return req


def test_extract_token_bare_bearer_is_none() -> None:
    # "Bearer " with an empty/whitespace token strips to "" → None.
    assert extract_session_token(_fake_request(headers={"Authorization": "Bearer "})) is None


def test_extract_token_empty_cookie_is_none() -> None:
    # An empty cookie is falsy and must not shadow a (missing) header → None.
    assert extract_session_token(_fake_request(cookies={SESSION_COOKIE: ""})) is None


def test_extract_token_non_bearer_scheme_is_none() -> None:
    assert extract_session_token(_fake_request(headers={"Authorization": "Basic abc123"})) is None


def test_extract_token_positive_cookie_and_bearer() -> None:
    assert (
        extract_session_token(_fake_request(cookies={SESSION_COOKIE: "cookie-tok"})) == "cookie-tok"
    )
    assert (
        extract_session_token(_fake_request(headers={"Authorization": "Bearer hdr-tok"}))
        == "hdr-tok"
    )


# --- OIDC 503 contract while the interactive flow is unwired (EC-auth-15) -----------------


async def test_oidc_unset_returns_503_not_configured(api_client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/auth/oidc/login", "/api/v1/auth/oidc/callback"):
        resp = await api_client.get(path)
        assert resp.status_code == 503
        assert resp.json()["detail"] == "OIDC not configured"


async def test_oidc_configured_but_unwired_returns_503(settings: Settings) -> None:
    configured = settings.model_copy(
        update={"oidc_issuer": "https://idp.example.test", "oidc_client_id": "fathom"}
    )
    async with _client_with_settings(configured) as client:
        for path in ("/api/v1/auth/oidc/login", "/api/v1/auth/oidc/callback"):
            resp = await client.get(path)
            assert resp.status_code == 503
            assert resp.json()["detail"] == "OIDC interactive flow not yet enabled"


# --- OIDC SSRF guard + alg allow-list ----------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/.well-known/openid-configuration",
        "http://authentik.example/.well-known/openid-configuration",  # not https
        "https://127.0.0.1/oidc",
        "https://10.0.0.5/oidc",
        "https://[::1]/oidc",
    ],
)
def test_ssrf_guard_blocks(url: str) -> None:
    with pytest.raises(OidcError):
        assert_url_allowed(url)


def test_oidc_alg_allowlist_excludes_none() -> None:
    assert "none" not in ALLOWED_ALGS
    assert "HS256" not in ALLOWED_ALGS
    assert "RS256" in ALLOWED_ALGS


# --- id_token alg-confusion: none / HS256-forged must be rejected (EC-auth-17) ------------


def _id_token_claims() -> dict[str, Any]:
    return {
        "sub": "user-1",
        "iss": "https://idp.example.test",
        "aud": "fathom",
        "exp": datetime.now(tz=UTC) + timedelta(hours=1),
    }


def _fake_jwks_client(key: object) -> SimpleNamespace:
    """A stand-in PyJWKClient whose signing key is whatever the forger would supply."""
    return SimpleNamespace(get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=key))


def test_id_token_alg_none_rejected() -> None:
    # An unsigned (alg=none) token: even with a returned key, the allow-list rejects it.
    token = jwt.encode(_id_token_claims(), key="", algorithm="none")
    with pytest.raises(OidcError):
        validate_id_token(
            token,
            jwks_client=_fake_jwks_client("any-key"),  # type: ignore[arg-type]
            issuer="https://idp.example.test",
            audience="fathom",
        )


def test_id_token_hs256_forged_rejected() -> None:
    # A token signed HS256 with the (public) key material is rejected: HS* is not in the allow-list.
    secret = "x" * 40  # >=32 bytes to avoid PyJWT's insecure-key-length warning
    token = jwt.encode(_id_token_claims(), secret, algorithm="HS256")
    with pytest.raises(OidcError):
        validate_id_token(
            token,
            jwks_client=_fake_jwks_client(secret),  # type: ignore[arg-type]
            issuer="https://idp.example.test",
            audience="fathom",
        )


# --- OIDC TOCTOU / DNS-rebinding: the fetch must pin the once-validated address ----------


def _addrinfo(ip: str, port: int) -> list[Any]:
    """One IPv4 getaddrinfo answer tuple resolving to ``ip``."""
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


def test_jwks_fetch_rejects_rebind_to_metadata_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host that flips to the cloud-metadata IP at *fetch* time is rejected.

    This is the TOCTOU / DNS-rebinding case: the host validates public at ``build_jwks_client``
    time, then re-answers 169.254.169.254 when ``fetch_data`` runs. Because the fetch resolves
    again through the *guarded* ``_resolve_allowed`` (and would re-check the connected peer),
    there is no second, unguarded resolution and the connection is never opened.
    """
    answers = iter([_addrinfo("93.184.216.34", 443), _addrinfo("169.254.169.254", 443)])

    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return next(answers)

    def explode_create_connection(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("connect attempted to a blocked address — pinning failed")

    monkeypatch.setattr(oidc.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(oidc.socket, "create_connection", explode_create_connection)

    # Build succeeds against the public answer; the rebind only lands on the second resolution.
    client = build_jwks_client("https://idp.example.test/jwks")
    with pytest.raises(OidcError):
        client.fetch_data()


def test_discovery_fetch_rejects_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery against a host resolving to a private range is rejected, no connect made."""

    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return _addrinfo("10.0.0.5", port)

    def explode_create_connection(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("connect attempted to a private address — pinning failed")

    monkeypatch.setattr(oidc.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(oidc.socket, "create_connection", explode_create_connection)

    with pytest.raises(OidcError):
        fetch_discovery_document("https://idp.example.test")


def test_jwks_fetch_pins_validated_ip_then_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the resolved address is public, the connection targets that *pinned* IP.

    We stub the TLS connection out and capture the address actually dialled, proving the fetch
    connects to the once-resolved IP (not a re-resolution) and preserves the SNI host header.
    """
    resolved_ip = "93.184.216.34"
    dialled: dict[str, Any] = {}

    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return _addrinfo(resolved_ip, port)

    class FakeResponse:
        status = 200

        def read(self) -> bytes:
            return b'{"keys": []}'

    def fake_request(self: Any, method: str, target: str, headers: dict[str, str]) -> None:
        dialled["pinned_ip"] = self._pinned_ip
        dialled["host_header"] = headers["Host"]
        dialled["target"] = target

    monkeypatch.setattr(oidc.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(oidc._PinnedHTTPSConnection, "request", fake_request)
    monkeypatch.setattr(oidc._PinnedHTTPSConnection, "getresponse", lambda self: FakeResponse())
    monkeypatch.setattr(oidc._PinnedHTTPSConnection, "close", lambda self: None)

    client = build_jwks_client("https://idp.example.test/realm/jwks")
    jwk_set = client.fetch_data()

    assert jwk_set == {"keys": []}
    assert dialled["pinned_ip"] == resolved_ip
    assert dialled["host_header"] == "idp.example.test"
    assert dialled["target"] == "/realm/jwks"
