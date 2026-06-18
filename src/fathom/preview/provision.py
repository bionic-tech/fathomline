"""Preview-runtime provisioning from settings (ADR-014; deploy enablement).

Assembles a :class:`~fathom.api.preview_runtime.PreviewRuntime` (cache + sandbox driver + queue
+ service) from :class:`~fathom.core.settings.Settings` plus a caller-supplied
:class:`~fathom.preview.service.FileFetcher` (the signed single-file pull, which needs the secret
backend's Ed25519 grant key + the agent channel). Wiring this is the deliberate, documented
enablement step (mirrors the remediation runtime): until it runs, the preview route is 503
(fail-closed).

The cache-encryption key and the grant signing key come from the secret backend (ADR-010); this
module accepts the already-resolved key material / fetcher and never reads secrets from code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fathom.api.preview_runtime import PreviewRuntime
from fathom.core.settings import Settings
from fathom.preview.cache import EncryptedLruCache
from fathom.preview.sandbox import RunscSandboxDriver, SandboxDriver
from fathom.preview.service import FileFetcher, PreviewService
from fathom.preview.types import ResourceCaps
from fathom.workers.preview import PreviewQueue

if TYPE_CHECKING:
    from fathom.preview.grant import GrantSigner
    from fathom.preview.pull import PreviewPullQueue
    from fathom.preview.remote_driver import RenderTransport


def caps_from_settings(settings: Settings) -> ResourceCaps:
    """Build the per-render :class:`ResourceCaps` from the config-driven limits (D-6 guard)."""
    return ResourceCaps(
        cpu=settings.preview_cpu_limit,
        mem_bytes=settings.preview_mem_bytes,
        time_s=settings.preview_timeout_seconds,
        max_pages=settings.preview_max_pages,
        max_decompressed_bytes=settings.preview_max_decompressed_bytes,
    )


def build_preview_runtime(
    settings: Settings,
    *,
    fetcher: FileFetcher,
    driver: SandboxDriver | None = None,
    cache_key_material: str | None = None,
    max_concurrent: int = 2,
) -> PreviewRuntime:
    """Assemble the preview runtime (cache + sandbox driver + queue + service) from settings.

    ``fetcher`` is the signed single-file pull (caller-built with the secret-backed grant key +
    the agent channel). ``driver`` defaults to a local :class:`RunscSandboxDriver` (single-host /
    on-the-gVisor-host) but a distributed core injects a
    :class:`~fathom.preview.remote_driver.RemoteSandboxDriver` that ships the bytes to the worker —
    the core itself cannot run ``runsc`` (TrueNAS, AR-0002). ``cache_key_material`` is the
    urlsafe-base64 Fernet key resolved from the secret backend (``None`` → ephemeral per-process
    key; dev/test only). The local driver pins the configured runtime and fails closed if it is not
    ``runsc`` (E-7).
    """
    cache = EncryptedLruCache.from_key_material(
        cache_key_material,
        max_entries=settings.preview_cache_max_entries,
        ttl_seconds=settings.preview_cache_ttl_seconds,
    )
    if driver is None:
        driver = RunscSandboxDriver(
            image=settings.preview_sandbox_image,
            runtime=settings.preview_sandbox_runtime,
        )
    service = PreviewService(
        cache=cache,
        driver=driver,
        fetcher=fetcher,
        caps=caps_from_settings(settings),
        max_input_bytes=settings.preview_max_input_bytes,
        cache_ttl_seconds=settings.preview_cache_ttl_seconds,
    )
    return PreviewRuntime(service=service, queue=PreviewQueue(max_concurrent=max_concurrent))


def build_distributed_preview_runtime(
    settings: Settings,
    *,
    signer: GrantSigner,
    render_transport: RenderTransport,
    queue: PreviewPullQueue,
    cache_key_material: str | None = None,
    max_concurrent: int = 2,
) -> PreviewRuntime:
    """Assemble the preview runtime for a **distributed** deployment (ADR-014).

    The core mints + signs file grants (``signer``), pulls each file from its owning agent over the
    shared ``queue`` (a :class:`~fathom.preview.pull.GrantPullFetcher`), and ships the bytes to the
    gVisor worker for the render via ``render_transport`` (a
    :class:`~fathom.preview.remote_driver.RemoteSandboxDriver`) — the core never runs ``runsc``
    itself (TrueNAS, AR-0002). The same ``queue`` must be set on ``app.state.preview_pull_queue`` so
    the agent poll/serve endpoints feed it. The grant TTL doubles as the pull dispatch window (a
    timed-out pull is also an expired grant).
    """
    from fathom.preview.pull import GrantPullFetcher
    from fathom.preview.remote_driver import RemoteSandboxDriver

    fetcher = GrantPullFetcher(
        signer=signer, queue=queue, grant_ttl_seconds=settings.preview_grant_ttl_seconds
    )
    return build_preview_runtime(
        settings,
        fetcher=fetcher,
        driver=RemoteSandboxDriver(transport=render_transport),
        cache_key_material=cache_key_material,
        max_concurrent=max_concurrent,
    )


def build_local_preview_runtime(
    settings: Settings,
    *,
    cache_key_material: str | None = None,
    max_concurrent: int = 2,
) -> PreviewRuntime:
    """Assemble the preview runtime for a **single-host** deployment (local-disk file fetch).

    Identical to :func:`build_preview_runtime` except the file delivery is
    :class:`~fathom.preview.local_fetch.LocalFileFetcher` — the data lives on this host, so the
    signed single-file pull over the agent channel is unnecessary; the file is read directly off
    local disk (still O_NOFOLLOW + inode-anchored + bounded). The runsc sandbox is unchanged, so
    the isolation guarantee is identical to the distributed deployment — only the byte source
    differs. The driver still fails closed if the configured runtime is not ``runsc`` (E-7).
    """
    from fathom.preview.local_fetch import LocalFileFetcher

    return build_preview_runtime(
        settings,
        fetcher=LocalFileFetcher(),
        cache_key_material=cache_key_material,
        max_concurrent=max_concurrent,
    )
