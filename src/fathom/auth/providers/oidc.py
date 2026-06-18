"""App-native OIDC against authentik — authorization-code + PKCE (ADD 03 §2.1, ADR-009).

The third link in the chain. Login builds an authorization-code + PKCE redirect; the callback
exchanges the code, validates the id_token (issuer / audience / signature / explicit alg
allow-list to defeat alg-confusion), maps group claims to roles via the local IdentityBinding
table (ADD 13 §7) and mints a server-side session.

SSRF guard (ADD 03 §2.1/§6): every outbound discovery / token / JWKS URL is checked to
resolve to a public address; cloud metadata endpoints (169.254.169.254 and friends) and all
private / loopback / link-local ranges are **always hard-blocked**, mirroring the adapter
SSRF policy. id_token validation never trusts ``none`` and never accepts an alg the server
did not pin.

The naive guard ("resolve, check, then hand the URL to a library that resolves again") is
TOCTOU- / DNS-rebinding-able: :class:`jwt.PyJWKClient` (and a plain ``urlopen`` discovery
fetch) re-resolve the host independently, so a name that answered public during the check can
answer ``169.254.169.254`` at fetch time. We close that gap by resolving the host **once**,
validating that pinned address with :func:`_is_blocked_ip`, and then connecting **to the
pinned IP** while preserving SNI / ``Host`` (TLS still validates the certificate against the
real hostname). The connection's actually-connected peer address is re-checked on connect, so
there is no second, unguarded resolution. ``oidc_issuer`` is operator config, so this is
defence-in-depth — kept bounded and on top of the existing public-address check.

This module provides the verification primitives (pure, easily tested); the HTTP exchange is
intentionally thin and is exercised at the integration layer.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import jwt
from jwt import InvalidTokenError, PyJWKClient

# Always-blocked metadata addresses (ADD 03 §6), regardless of range classification.
_BLOCKED_METADATA_IPS: frozenset[str] = frozenset(
    {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}
)
# Explicit signing-algorithm allow-list — never ``none``, never HS* with a public client.
ALLOWED_ALGS: tuple[str, ...] = ("RS256", "ES256")


class OidcError(Exception):
    """Raised when an OIDC flow or its SSRF/id_token validation fails (fail-closed)."""


def _is_blocked_ip(ip: str) -> bool:
    if ip in _BLOCKED_METADATA_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable → block (fail-closed)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _resolve_allowed(url: str) -> tuple[str, int, list[str]]:
    """Resolve ``url`` **once**, validate every answer, and return the pinned candidates.

    Returns ``(host, port, candidate_ips)`` where every IP in ``candidate_ips`` has passed
    :func:`_is_blocked_ip`. Raising here (https-only, resolvable, public) is the single point
    of DNS resolution for the SSRF guard; callers connect to one of the returned pinned IPs so
    no second, unguarded resolution can reintroduce a private / metadata address.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise OidcError(f"OIDC URL must be https: {url!r}")
    host = parsed.hostname
    if host is None:
        raise OidcError(f"OIDC URL has no host: {url!r}")
    port = parsed.port or 443
    # A literal IP host is checked directly; a hostname is resolved and every answer checked.
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise OidcError(f"cannot resolve OIDC host {host!r}") from exc
        candidates = [str(info[4][0]) for info in infos]
    if not candidates:
        raise OidcError(f"no addresses for OIDC host {host!r}")
    for ip in candidates:
        if _is_blocked_ip(ip):
            raise OidcError(f"OIDC host {host!r} resolves to blocked address {ip}")
    return host, port, candidates


def assert_url_allowed(url: str) -> None:
    """Raise :class:`OidcError` unless ``url`` is https and resolves to a public address.

    Blocks cloud metadata endpoints and all private / loopback / link-local ranges (SSRF
    guard, ADD 03 §2.1/§6). DNS is resolved here so a public hostname that maps to a private
    address is still rejected (DNS-rebinding defence). For an actual fetch, prefer
    :func:`fetch_discovery_document` / :func:`build_jwks_client`, which additionally **pin** the
    validated address so the fetch cannot re-resolve to a blocked one (TOCTOU defence).
    """
    _resolve_allowed(url)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a **pre-validated** IP while keeping SNI / cert host.

    The TCP connection targets ``pinned_ip`` (already passed :func:`_is_blocked_ip`), but TLS
    still presents and verifies the original ``host`` (SNI + certificate hostname), so a
    rebinding answer cannot redirect us to a metadata endpoint without also breaking TLS. As a
    belt-and-braces check the *actually-connected* peer address is re-validated on connect, so
    even a stray resolution path is caught.
    """

    def __init__(self, host: str, pinned_ip: str, *, port: int, timeout: float) -> None:
        ctx = ssl.create_default_context()
        # ``server_hostname`` is forced to the real host below; cert verification stays on.
        super().__init__(host, port=port, timeout=timeout, context=ctx)
        self._pinned_ip = pinned_ip
        self._ssl_ctx = ctx

    def connect(self) -> None:  # pragma: no cover - exercised via the fetch helpers
        sock = socket.create_connection((self._pinned_ip, self.port), timeout=self.timeout)
        peer = sock.getpeername()[0]
        if _is_blocked_ip(str(peer)):
            sock.close()
            raise OidcError(f"OIDC connection reached blocked address {peer}")
        self.sock = self._ssl_ctx.wrap_socket(sock, server_hostname=self.host)


def _fetch_pinned(url: str, *, timeout: float = 10.0) -> bytes:
    """GET ``url`` over a connection pinned to a once-resolved, validated IP (SSRF-safe)."""
    host, port, candidates = _resolve_allowed(url)
    parsed = urlparse(url)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    last_exc: Exception | None = None
    for pinned_ip in candidates:
        conn = _PinnedHTTPSConnection(host, pinned_ip, port=port, timeout=timeout)
        headers = {"Host": host, "Accept": "application/json"}
        try:
            conn.request("GET", request_target, headers=headers)
            resp = conn.getresponse()
            if resp.status != 200:
                raise OidcError(f"OIDC fetch of {url!r} returned HTTP {resp.status}")
            return resp.read()
        except OidcError:
            raise
        except OSError as exc:  # connection / TLS error against this candidate
            last_exc = exc
            continue
        finally:
            conn.close()
    raise OidcError(f"OIDC fetch of {url!r} failed for all resolved addresses") from last_exc


def fetch_discovery_document(issuer: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch ``<issuer>/.well-known/openid-configuration`` SSRF-safely and parse it.

    The discovery URL is resolved + validated **once** and the fetch is pinned to that
    address, so neither this request nor the host's later reuse can be steered to a private /
    metadata endpoint between check and connect.
    """
    discovery_url = urljoin(issuer.rstrip("/") + "/", ".well-known/openid-configuration")
    raw = _fetch_pinned(discovery_url, timeout=timeout)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OidcError(f"OIDC discovery document is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise OidcError("OIDC discovery document is not a JSON object")
    return doc


class _PinnedPyJWKClient(PyJWKClient):
    """:class:`PyJWKClient` whose JWKS fetch is pinned to a once-validated IP (SSRF-safe).

    Upstream ``fetch_data`` re-resolves ``self.uri`` via ``urllib`` at fetch time; we override
    it to reuse :func:`_fetch_pinned`, which resolves once, validates, and connects to the
    pinned address — closing the TOCTOU / rebinding window while keeping PyJWT's caching and
    signing-key extraction.
    """

    def fetch_data(self) -> Any:
        raw = _fetch_pinned(self.uri)
        jwk_set = json.loads(raw)
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        return jwk_set


def build_jwks_client(jwks_uri: str) -> PyJWKClient:
    """Return a JWKS client that pins its fetch to a once-validated, public address.

    ``jwks_uri`` is validated up front (https + public, fail-closed) and every subsequent JWKS
    fetch re-validates the resolved address against :func:`_is_blocked_ip` before connecting.
    """
    assert_url_allowed(jwks_uri)
    return _PinnedPyJWKClient(jwks_uri)


@dataclass(frozen=True, slots=True)
class OidcClaims:
    """The validated subject + groups extracted from an id_token."""

    subject: str
    groups: tuple[str, ...]
    amr: tuple[str, ...]
    acr: str | None


def validate_id_token(
    id_token: str,
    *,
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
    groups_claim: str = "groups",
    leeway: int = 30,
) -> OidcClaims:
    """Validate an id_token (sig/iss/aud/alg) and extract subject + groups (fail-closed).

    Uses an explicit ``algorithms`` allow-list (never ``none``) and requires ``exp``/``iss``/
    ``aud`` to be present and correct, defeating alg-confusion and audience-substitution.
    """
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        payload: dict[str, object] = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=list(ALLOWED_ALGS),
            issuer=issuer,
            audience=audience,
            leeway=leeway,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except InvalidTokenError as exc:
        raise OidcError(f"id_token validation failed: {exc}") from exc

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        raise OidcError("id_token missing subject")
    raw_groups = payload.get(groups_claim, [])
    groups = (
        tuple(g for g in raw_groups if isinstance(g, str)) if isinstance(raw_groups, list) else ()
    )
    raw_amr = payload.get("amr", [])
    amr = tuple(a for a in raw_amr if isinstance(a, str)) if isinstance(raw_amr, list) else ()
    acr = payload.get("acr")
    return OidcClaims(
        subject=sub,
        groups=groups,
        amr=amr,
        acr=acr if isinstance(acr, str) else None,
    )
