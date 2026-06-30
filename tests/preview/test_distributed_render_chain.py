"""Distributed preview render chain end-to-end with a FAKE gVisor sandbox (ADR-014).

Ties the whole distributed pull + remote-render path into ONE ``PreviewService.render`` call,
with no gVisor and no HTTP — the happy path that otherwise needs the runsc sandbox::

    service.render
      → GrantPullFetcher.fetch    (mints a signed grant, enqueues it on the PreviewPullQueue)
      → a fake agent polls the queue, "reads" the granted file, delivers the bytes back
      → RemoteSandboxDriver.run   → fake RenderTransport → render_request (the worker side)
      → a fake sandbox driver returns a canned DERIVED artifact (stands in for RunscSandboxDriver)
      → derived artifact returned + cached.

The individual pieces are unit-tested elsewhere (test_pull: the grant rendezvous;
test_remote_driver: the core↔worker split). This is the missing happy-path that proves they
COMPOSE into a working distributed render without runsc — grant → serve → render → artifact back.
"""

from __future__ import annotations

import asyncio

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.preview.cache import EncryptedLruCache
from fathom.preview.grant import GrantSigner
from fathom.preview.pull import GrantPullFetcher, PreviewPullQueue
from fathom.preview.remote_driver import (
    RemoteSandboxDriver,
    RenderRequest,
    RenderResponse,
    render_request,
)
from fathom.preview.service import PreviewService, ResolvedEntry
from fathom.preview.types import SupportedType
from tests.preview.conftest import DEFAULT_CAPS, RecordingDriver

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64  # PNG magic → IMAGE


def _entry() -> ResolvedEntry:
    return ResolvedEntry(
        entry_id=1,
        host_id=7,
        volume_id=11,
        path="/mnt/pool/photo.jpg",
        inode=42,
        content_hash="d4" * 32,
        host_name="nas-1",  # the agent's poll/grant scope for the distributed pull
    )


async def test_distributed_chain_renders_via_fake_sandbox() -> None:
    """grant → agent serves bytes → worker renders via fake sandbox → DERIVED artifact returned."""
    # The worker-side fake sandbox: a RecordingDriver stands in for RunscSandboxDriver (no gVisor).
    sandbox = RecordingDriver()

    class _Transport:
        """In-process stand-in for the mTLS POST to the worker ``/render`` route (no HTTP)."""

        async def post_render(self, request: RenderRequest) -> RenderResponse:
            return await render_request(request, driver=sandbox)

    queue = PreviewPullQueue()
    signer = GrantSigner(Ed25519PrivateKey.generate(), key_id="preview-v1")
    fetcher = GrantPullFetcher(signer=signer, queue=queue, grant_ttl_seconds=5)
    service = PreviewService(
        cache=EncryptedLruCache.from_key_material(None, max_entries=8, ttl_seconds=1800),
        driver=RemoteSandboxDriver(transport=_Transport()),
        fetcher=fetcher,
        caps=DEFAULT_CAPS,
        max_input_bytes=256 * 1024 * 1024,
        cache_ttl_seconds=1800,
    )

    async def agent() -> None:
        # The owning host long-polls, "reads" exactly the granted file, serves the bytes back.
        polled = await queue.poll("nas-1", timeout_seconds=5)
        assert polled is not None
        signed, _max_bytes = polled
        queue.deliver(grant_id=signed.grant.grant_id, host_id="nas-1", data=_PNG)

    agent_task = asyncio.create_task(agent())
    result, cached_size = await service.render(_entry(), job_id="job-dist-1")
    await agent_task

    assert result.type is SupportedType.IMAGE
    assert result.cache_hit is False
    assert len(result.artifacts) == 1
    derived = result.artifacts[0]
    assert derived.kind == "thumbnail"
    assert derived.media_type == "image/webp"
    # DERIVED bytes from the fake sandbox — never the raw PNG (ADR-014); base64 is lossless.
    assert derived.data == f"derived:image:{len(_PNG)}".encode()
    assert derived.data != _PNG
    # The fake sandbox ran once, on exactly the bytes the agent served over the grant channel.
    assert sandbox.seen == [(len(_PNG), "image")]
    assert cached_size > 0  # the derived artifact was encrypted + cached (its at-rest size)
