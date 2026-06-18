"""Core-side live-browse runtime provisioning (ADR-034 Phase 2).

Builds the browse signer + per-host pull queue when a browse signing key is configured by reference
(ADR-010). Mirrors :mod:`fathom.api.preview_runtime_dist`. Default-OFF: absent
``browse_signing_key_ref`` this returns ``None`` and the agent poll/result routes stay inert (204)
while the operator browse endpoint 503s.
"""

from __future__ import annotations

from collections.abc import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.core.browse import BrowsePullQueue, BrowseSigner
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.api.browse_runtime")

SecretProvider = Callable[[str], str]


class BrowseRuntimeError(RuntimeError):
    """A configured browse signing key reference is set but invalid (fail loud at startup)."""


def load_browse_signer(
    settings: Settings, *, secret_provider: SecretProvider | None = None
) -> BrowseSigner | None:
    """Load the core's browse signer from the secret backend, or ``None`` when unconfigured."""
    ref = settings.browse_signing_key_ref
    if not ref:
        return None
    from fathom.backends.remote import env_or_docker_secret_provider

    provider = secret_provider or env_or_docker_secret_provider
    material = provider(ref)
    if not material:
        raise BrowseRuntimeError("browse_signing_key_ref did not resolve from the secret backend")
    try:
        private = serialization.load_pem_private_key(material.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise BrowseRuntimeError("browse_signing_key_ref is not a valid PEM private key") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise BrowseRuntimeError("browse_signing_key_ref is not an Ed25519 private key")
    return BrowseSigner(private, key_id=settings.browse_grant_key_id)


def build_browse_runtime(
    settings: Settings, *, secret_provider: SecretProvider | None = None
) -> tuple[BrowseSigner, BrowsePullQueue] | None:
    """Provision (signer, queue) when a browse signing key is configured; else ``None`` (inert)."""
    signer = load_browse_signer(settings, secret_provider=secret_provider)
    if signer is None:
        return None
    queue = BrowsePullQueue()
    _log.info("live browse runtime provisioned", extra={"key_id": signer.key_id})
    return signer, queue
