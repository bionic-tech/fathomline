"""Adapter configuration models and the SSRF endpoint policy (ADD 04, sec-arch §6, ADR-010).

Two concerns live here, both Pydantic v2, ``extra="forbid"``, fail-fast (code-quality #10):

1. :class:`AdapterConfig` — the *shape* of an adapter connection: platform class, endpoint,
   pinned API version, ``verify_ssl`` (default ``True``), and an **api_key_ref** that is a
   *reference* to a secret (env/Docker-secret/OpenBao name), **never the key material**
   (ADR-010, STRIDE I-2). The secret is resolved at runtime via a ``secret_provider`` seam.

2. The SSRF endpoint policy (sec-arch §6, owner ruling). The generic OIDC SSRF guard blocks
   *all* private/loopback/link-local ranges, but TrueNAS and other NAS appliances live
   precisely at localhost/private addresses, so a blanket block would forbid the intended
   use. Resolution (owner-confirmed): adapter endpoints are validated against an explicit,
   operator-confirmed **allowlist of hosts**; cloud-metadata addresses
   (169.254.169.254 and friends) stay **hard-blocked even when allowlisted** — there is no
   legitimate adapter reason to reach a metadata service.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fathom.adapters.discovery import PlatformClass

# Cloud/link-local metadata addresses — ALWAYS hard-blocked for adapter endpoints, even if a
# host is on the operator allowlist (owner ruling; mirrors the OIDC guard's metadata set).
_BLOCKED_METADATA_IPS: frozenset[str] = frozenset(
    {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}
)

# Schemes an adapter endpoint may use. ``wss`` is the production TrueNAS transport; ``ws`` and
# the ``unix``/local-socket form are only valid for the on-box loopback path under a lab/local
# profile. Plaintext ``ws`` to a remote host is rejected unless ``lab_insecure`` is set.
_SECURE_SCHEMES: frozenset[str] = frozenset({"wss", "unix"})
_ALL_SCHEMES: frozenset[str] = frozenset({"wss", "ws", "unix"})


class SsrfError(ValueError):
    """Raised when an adapter endpoint is rejected by the SSRF allowlist policy (fail-closed)."""


def _endpoint_host(endpoint: str) -> str | None:
    """Return the host portion of an adapter endpoint, or ``None`` for a local socket."""
    parsed = urlparse(endpoint)
    if parsed.scheme == "unix":
        return None  # on-box local socket has no network host
    return parsed.hostname


def _is_metadata_ip(host: str) -> bool:
    """True if ``host`` is a literal cloud-metadata address (always blocked)."""
    if host in _BLOCKED_METADATA_IPS:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # a hostname; metadata services are reached by literal IP
    return str(addr) in _BLOCKED_METADATA_IPS


def assert_endpoint_allowed(endpoint: str, allowlist: frozenset[str]) -> None:
    """Validate an adapter ``endpoint`` against the operator-confirmed ``allowlist``.

    Policy (sec-arch §6, owner ruling):

    * cloud-metadata addresses are hard-blocked **unconditionally** — there is no adapter
      reason to reach 169.254.169.254 or its peers, allowlisted or not;
    * the on-box ``unix`` local socket is always permitted (no network host to forge);
    * every other endpoint host must appear verbatim in the operator-confirmed allowlist —
      private NAS IPs are *expected* here, which is exactly why the generic private-IP block
      is replaced by an explicit allowlist rather than an address-range rule.

    Raises:
        SsrfError: If the endpoint is malformed, targets a metadata address, or its host is
            not on the allowlist.
    """
    host = _endpoint_host(endpoint)
    if host is None:
        return  # local socket — no host to validate
    if _is_metadata_ip(host):
        raise SsrfError(f"adapter endpoint host {host!r} is a hard-blocked metadata address")
    if host not in allowlist:
        raise SsrfError(
            f"adapter endpoint host {host!r} is not on the operator-confirmed allowlist"
        )


class AdapterConfig(BaseModel):
    """A single host's adapter connection settings (config shape only; secrets by reference).

    The API key is **never** a field value — ``api_key_ref`` names the secret so it can be
    resolved at runtime from env/Docker-secrets/OpenBao (ADR-010). ``verify_ssl`` defaults to
    ``True`` and ``lab_insecure`` to ``False``; flipping ``lab_insecure`` is the *only* way to
    permit a plaintext/unverified transport and is validated to be loud and deliberate
    (sec-arch §6, code-quality #6, STRIDE S-4).
    """

    model_config = ConfigDict(extra="forbid")

    platform: PlatformClass
    # ws://localhost | wss://<nas>/api/current | unix:///var/run/middlewared.sock (on-box).
    endpoint: str = Field(min_length=1)
    # Pinned middleware API version to negotiate (TrueNAS REST is removed in 26 — ADD 04).
    api_version: str = "v25.10"
    verify_ssl: bool = True
    # Secret *reference* (env var / Docker-secret name / OpenBao path), NOT the key (ADR-010).
    # ``None`` for the on-box local-socket root context, which needs no key (ADD 04).
    api_key_ref: str | None = None
    # Loud, explicit lab-only escape hatch for plaintext/unverified transport (default False).
    lab_insecure: bool = False
    # Operator-confirmed host allowlist for the SSRF policy above. Private NAS IPs go here.
    endpoint_allowlist: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("endpoint")
    @classmethod
    def _known_scheme(cls, value: str) -> str:
        scheme = urlparse(value).scheme
        if scheme not in _ALL_SCHEMES:
            raise ValueError(
                f"adapter endpoint scheme must be one of {sorted(_ALL_SCHEMES)}: {value!r}"
            )
        return value

    @model_validator(mode="after")
    def _enforce_secure_and_ssrf(self) -> AdapterConfig:
        scheme = urlparse(self.endpoint).scheme
        # verify_ssl=False or a plaintext ws:// transport is permitted ONLY behind lab_insecure.
        if not self.lab_insecure:
            if not self.verify_ssl:
                raise ValueError(
                    "verify_ssl=False requires lab_insecure=True (insecure transport, sec-arch §6)"
                )
            if scheme not in _SECURE_SCHEMES:
                raise ValueError(
                    f"plaintext endpoint scheme {scheme!r} requires lab_insecure=True "
                    "(verify_ssl/TLS is mandatory outside the lab profile, sec-arch §6)"
                )
        # SSRF allowlist applies regardless of profile — metadata IPs stay hard-blocked.
        assert_endpoint_allowed(self.endpoint, self.endpoint_allowlist)
        return self
