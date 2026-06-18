"""Provider-chain, local-auth and OIDC SSRF/id_token tests (ADD 03 §2, ADR-009)."""

from __future__ import annotations

import socket
from typing import Any

import httpx
import pytest

from fathom.auth import passwords
from fathom.auth.providers import oidc
from fathom.auth.providers.oidc import (
    ALLOWED_ALGS,
    OidcError,
    assert_url_allowed,
    build_jwks_client,
    fetch_discovery_document,
)
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
