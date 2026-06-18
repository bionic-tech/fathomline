"""Distributed-preview runtime wiring (ADR-014) — core side of the worker-rendered preview.

Mirrors :mod:`fathom.api.remediation_runtime`: resolves the Ed25519 grant SIGNING key by reference
(ADR-010), builds the per-host :class:`~fathom.preview.pull.PreviewPullQueue` + the
:class:`~fathom.preview.pull.GrantPullFetcher` + an :class:`~fathom.preview.remote_driver.
HttpRenderTransport` to the gVisor worker, and assembles the distributed preview runtime.

Returns ``None`` to preserve default-OFF: preview disabled, or the single-host local-fetch topology
was chosen, or no grant signing key / worker URL is configured. A key reference that is set but
unloadable raises :class:`PreviewProvisioningError` (fail loud at startup — never half-armed).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.logging import get_logger
from fathom.preview.grant import GrantSigner
from fathom.preview.provision import build_distributed_preview_runtime
from fathom.preview.pull import PreviewPullQueue
from fathom.preview.remote_driver import HttpRenderTransport

if TYPE_CHECKING:
    from fathom.api.preview_runtime import PreviewRuntime
    from fathom.core.settings import Settings

_log = get_logger("fathom.api.preview_runtime_dist")

SecretProvider = Callable[[str], str]


class PreviewProvisioningError(RuntimeError):
    """Distributed-preview key material was configured but could not be loaded (fail loud)."""


def load_grant_signer(
    settings: Settings, *, secret_provider: SecretProvider | None = None
) -> GrantSigner | None:
    """Load the core's Ed25519 grant signing key by reference (ADR-010), or ``None`` if unset."""
    ref = settings.preview_grant_signing_key_ref
    if not ref:
        return None
    from fathom.backends.remote import env_or_docker_secret_provider

    provider = secret_provider or env_or_docker_secret_provider
    try:
        material = provider(ref)
    except Exception as exc:  # any resolver failure is fail-loud
        raise PreviewProvisioningError(
            f"preview grant signing key {ref!r} did not resolve from the secret backend"
        ) from exc
    if not material:
        raise PreviewProvisioningError(f"preview grant signing key {ref!r} resolved to empty")
    try:
        private = serialization.load_pem_private_key(material.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise PreviewProvisioningError(
            "preview grant signing key is not a valid PEM private key"
        ) from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise PreviewProvisioningError("preview grant signing key is not an Ed25519 private key")
    return GrantSigner(private, key_id=settings.preview_grant_key_id)


def build_distributed_preview(
    settings: Settings,
    *,
    secret_provider: SecretProvider | None = None,
    render_client: httpx.AsyncClient | None = None,
) -> tuple[PreviewRuntime, PreviewPullQueue] | None:
    """Assemble the distributed preview runtime + its pull queue, or ``None`` to stay default-OFF.

    Returns a runtime ONLY when preview is enabled, the topology is distributed
    (``preview_local_fetch`` is False), and both a grant signing key and a worker URL are
    configured. The returned queue must be set on ``app.state.preview_pull_queue`` so the agent
    poll/serve endpoints feed the same queue the fetcher waits on.
    """
    if not settings.preview_enabled or settings.preview_local_fetch:
        return None
    if not settings.preview_grant_signing_key_ref or not settings.preview_worker_url:
        _log.warning(
            "preview_enabled (distributed) but no grant signing key / worker url — route stays 503"
        )
        return None
    if not settings.ingest_proxy_secret:
        raise PreviewProvisioningError(
            "distributed preview requires ingest_proxy_secret (the core↔worker shared auth)"
        )
    from fathom.backends.remote import env_or_docker_secret_provider

    provider = secret_provider or env_or_docker_secret_provider
    signer = load_grant_signer(settings, secret_provider=provider)
    if signer is None:  # pragma: no cover — guarded by the key-ref check above
        return None
    cache_ref = settings.preview_cache_key_ref
    cache_material = provider(cache_ref) if cache_ref else None
    queue = PreviewPullQueue()
    client = render_client or httpx.AsyncClient(timeout=settings.preview_timeout_seconds + 30.0)
    transport = HttpRenderTransport(
        client=client,
        url=settings.preview_worker_url,
        proxy_secret=settings.ingest_proxy_secret,
    )
    runtime = build_distributed_preview_runtime(
        settings,
        signer=signer,
        render_transport=transport,
        queue=queue,
        cache_key_material=cache_material or None,
    )
    _log.info(
        "distributed preview runtime provisioned",
        extra={"key_id": signer.key_id, "worker_url": settings.preview_worker_url},
    )
    return runtime, queue
