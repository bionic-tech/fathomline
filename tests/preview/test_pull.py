"""PreviewPullQueue + GrantPullFetcher — core side of the distributed signed single-file pull.

Unit-level (no DB/app): a fake "agent" coroutine polls the queue and delivers/fails, exercising the
happy path plus the fail-closed correlation rules (cross-host, unknown, double-resolve) and the
TTL timeout that maps to a clean 504.
"""

from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.preview.grant import GrantSigner
from fathom.preview.pull import (
    GrantPullFetcher,
    PreviewPullQueue,
    PullCorrelationError,
)
from fathom.preview.service import ResolvedEntry
from fathom.preview.types import PreviewError


def _signer() -> GrantSigner:
    return GrantSigner(Ed25519PrivateKey.generate(), key_id="preview-v1")


def _entry(*, host_id: int = 7) -> ResolvedEntry:
    return ResolvedEntry(
        entry_id=1,
        host_id=host_id,
        volume_id=11,
        path="C:\\Users\\x\\a.txt",
        inode=42,
        content_hash=None,
    )


async def test_fetch_round_trips_bytes_from_owning_agent() -> None:
    queue = PreviewPullQueue()
    fetcher = GrantPullFetcher(signer=_signer(), queue=queue, grant_ttl_seconds=5)

    async def agent() -> None:
        polled = await queue.poll("7", timeout_seconds=5)
        assert polled is not None
        signed, max_bytes = polled
        assert max_bytes == 1000  # the authoritative server-side cap rides the poll
        queue.deliver(grant_id=signed.grant.grant_id, host_id="7", data=b"hello")

    task = asyncio.create_task(agent())
    raw = await fetcher.fetch(_entry(), max_bytes=1000)
    await task
    assert raw == b"hello"


async def test_grant_carries_entry_identity_and_host_scope() -> None:
    queue = PreviewPullQueue()
    fetcher = GrantPullFetcher(signer=_signer(), queue=queue, grant_ttl_seconds=30)
    captured: dict[str, object] = {}

    async def agent() -> None:
        polled = await queue.poll("7", timeout_seconds=5)
        assert polled is not None
        signed, max_bytes = polled
        captured["grant"] = signed.grant
        captured["max_bytes"] = max_bytes
        queue.deliver(grant_id=signed.grant.grant_id, host_id="7", data=b"z")

    task = asyncio.create_task(agent())
    await fetcher.fetch(_entry(host_id=7), max_bytes=2048)
    await task
    grant = captured["grant"]
    assert grant.host_id == "7"  # type: ignore[attr-defined]
    assert grant.volume_id == 11 and grant.inode == 42 and grant.entry_id == 1  # type: ignore[attr-defined]
    assert captured["max_bytes"] == 2048
    assert grant.expires_at > grant.issued_at  # type: ignore[attr-defined]


async def test_fetch_times_out_as_504_when_no_agent_serves() -> None:
    queue = PreviewPullQueue()
    # ttl 0 → the dispatch window is zero, so the wait gives up immediately (and the grant is also
    # expired, so a late agent would refuse it anyway).
    fetcher = GrantPullFetcher(signer=_signer(), queue=queue, grant_ttl_seconds=0)
    with pytest.raises(PreviewError) as excinfo:
        await fetcher.fetch(_entry(), max_bytes=1000)
    assert excinfo.value.status_code == 504


async def test_agent_failure_surfaces_as_504() -> None:
    queue = PreviewPullQueue()
    fetcher = GrantPullFetcher(signer=_signer(), queue=queue, grant_ttl_seconds=5)

    async def agent() -> None:
        polled = await queue.poll("7", timeout_seconds=5)
        assert polled is not None
        signed, _ = polled
        queue.fail(grant_id=signed.grant.grant_id, host_id="7", reason="file vanished")

    task = asyncio.create_task(agent())
    with pytest.raises(PreviewError) as excinfo:
        await fetcher.fetch(_entry(), max_bytes=1000)
    await task
    assert excinfo.value.status_code == 504


async def test_deliver_from_wrong_host_is_rejected_then_correct_host_completes() -> None:
    queue = PreviewPullQueue()
    fetcher = GrantPullFetcher(signer=_signer(), queue=queue, grant_ttl_seconds=5)

    async def agent() -> None:
        polled = await queue.poll("7", timeout_seconds=5)
        assert polled is not None
        signed, _ = polled
        # A host trying to answer a grant scoped to host "7" is rejected (cross-host spoof).
        with pytest.raises(PullCorrelationError):
            queue.deliver(grant_id=signed.grant.grant_id, host_id="99", data=b"evil")
        queue.deliver(grant_id=signed.grant.grant_id, host_id="7", data=b"ok")

    task = asyncio.create_task(agent())
    raw = await fetcher.fetch(_entry(), max_bytes=1000)
    await task
    assert raw == b"ok"


async def test_deliver_unknown_grant_is_rejected() -> None:
    queue = PreviewPullQueue()
    with pytest.raises(PullCorrelationError):
        queue.deliver(grant_id="never-issued", host_id="7", data=b"x")


async def test_double_deliver_is_rejected() -> None:
    queue = PreviewPullQueue()
    fetcher = GrantPullFetcher(signer=_signer(), queue=queue, grant_ttl_seconds=5)

    async def agent() -> None:
        polled = await queue.poll("7", timeout_seconds=5)
        assert polled is not None
        signed, _ = polled
        queue.deliver(grant_id=signed.grant.grant_id, host_id="7", data=b"first")
        with pytest.raises(PullCorrelationError):  # already resolved
            queue.deliver(grant_id=signed.grant.grant_id, host_id="7", data=b"second")

    task = asyncio.create_task(agent())
    raw = await fetcher.fetch(_entry(), max_bytes=1000)
    await task
    assert raw == b"first"


async def test_poll_returns_none_on_timeout() -> None:
    queue = PreviewPullQueue()
    assert await queue.poll("7", timeout_seconds=0.01) is None


async def test_poll_drops_expired_grant_and_fails_its_waiter() -> None:
    # An already-expired grant sitting in the per-host queue must be drained by poll (not handed to
    # an agent that would only refuse it) and its still-awaiting fetch failed promptly — so the
    # queue can't accumulate dead grants for an offline host (bounded growth).
    from datetime import UTC, datetime, timedelta

    from fathom.preview.grant import FileGrant
    from fathom.preview.pull import PreviewPullError

    queue = PreviewPullQueue()
    now = datetime.now(tz=UTC)
    grant = FileGrant(
        grant_id="expired-1",
        entry_id=1,
        host_id="h1",
        volume_id=1,
        inode=1,
        path="/x",
        nonce="n" * 16,
        issued_at=now - timedelta(seconds=60),
        expires_at=now - timedelta(seconds=1),
    )
    signed = _signer().sign(grant)
    fut = asyncio.get_running_loop().create_future()
    queue._results["expired-1"] = fut  # as enqueue_and_wait would register it
    queue._grant_host["expired-1"] = "h1"
    queue._queue_for("h1").put_nowait((signed, 1000))

    polled = await queue.poll("h1", timeout_seconds=0.2)
    assert polled is None  # expired grant drained, nothing handed to the agent
    assert fut.done() and isinstance(fut.exception(), PreviewPullError)
