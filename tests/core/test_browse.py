"""Signed browse request model + fail-closed verification (ADR-034 Phase 2)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.core.browse import (
    BrowseCorrelationError,
    BrowsePullError,
    BrowsePullQueue,
    BrowseReplayError,
    BrowseRequest,
    BrowseResult,
    BrowseSigner,
    BrowseVerificationError,
    BrowseVerifier,
    verify_browse_request,
)


class _FakeNonceStore:
    """consume() succeeds once per nonce, then fails (a replay) — mirrors the atomic DB store."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    async def consume(self, nonce: str, *, job_id: str) -> bool:
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        return True


def _request(**over: object) -> BrowseRequest:
    now = datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)
    base = {
        "request_id": "br-1",
        "host_id": "nas-1",
        "path": "/scan/data",
        "nonce": "a" * 32,
        "issued_at": now,
        "expires_at": now + timedelta(seconds=60),
    }
    return BrowseRequest.model_validate({**base, **over})


def _signer_verifier(key_id: str = "browse-v1") -> tuple[BrowseSigner, BrowseVerifier]:
    priv = Ed25519PrivateKey.generate()
    signer = BrowseSigner(priv, key_id=key_id)
    verifier = BrowseVerifier(priv.public_key(), key_id=key_id)
    return signer, verifier


def test_canonical_bytes_is_stable_and_covers_fields() -> None:
    r1 = _request()
    r2 = _request()
    assert r1.canonical_bytes() == r2.canonical_bytes()
    # any field change perturbs the signed bytes
    assert _request(path="/scan/other").canonical_bytes() != r1.canonical_bytes()
    assert _request(max_entries=10).canonical_bytes() != r1.canonical_bytes()


async def test_sign_verify_round_trip_consumes_nonce_once() -> None:
    signer, verifier = _signer_verifier()
    store = _FakeNonceStore()
    now = datetime(2026, 6, 16, 12, 0, 30, tzinfo=UTC)
    signed = signer.sign(_request())
    got = await verify_browse_request(
        signed, verifier=verifier, nonce_store=store, expected_host_id="nas-1", now=now
    )
    assert got.path == "/scan/data"
    # replay: same nonce → BrowseReplayError
    with pytest.raises(BrowseReplayError):
        await verify_browse_request(
            signed, verifier=verifier, nonce_store=store, expected_host_id="nas-1", now=now
        )


async def test_verify_rejects_tampered_signature() -> None:
    signer, verifier = _signer_verifier()
    signed = signer.sign(_request())
    tampered = signed.model_copy(update={"request": _request(path="/etc")})
    with pytest.raises(BrowseVerificationError):
        await verify_browse_request(
            tampered,
            verifier=verifier,
            nonce_store=_FakeNonceStore(),
            expected_host_id="nas-1",
        )


async def test_verify_rejects_wrong_key_id() -> None:
    signer, _ = _signer_verifier(key_id="browse-v1")
    other = BrowseVerifier(Ed25519PrivateKey.generate().public_key(), key_id="browse-v1")
    with pytest.raises(BrowseVerificationError):
        await verify_browse_request(
            signer.sign(_request()),
            verifier=other,
            nonce_store=_FakeNonceStore(),
            expected_host_id="nas-1",
        )


async def test_verify_rejects_expired_and_out_of_scope() -> None:
    signer, verifier = _signer_verifier()
    late = datetime(2026, 6, 16, 12, 5, 0, tzinfo=UTC)  # past expires_at
    with pytest.raises(BrowseVerificationError):
        await verify_browse_request(
            signer.sign(_request()),
            verifier=verifier,
            nonce_store=_FakeNonceStore(),
            expected_host_id="nas-1",
            now=late,
        )
    with pytest.raises(BrowseVerificationError):
        await verify_browse_request(
            signer.sign(_request()),
            verifier=verifier,
            nonce_store=_FakeNonceStore(),
            expected_host_id="other-host",  # scope mismatch
        )


# A clock fixed inside the request validity window (issued 12:00:00, expires 12:01:00) so the
# queue's expiry check is deterministic regardless of real wall-clock when the suite runs.
_IN_WINDOW = datetime(2026, 6, 16, 12, 0, 30, tzinfo=UTC)


async def test_queue_round_trip_delivers_result_to_waiter() -> None:
    signer, _ = _signer_verifier()
    queue = BrowsePullQueue(now=lambda: _IN_WINDOW)
    signed = signer.sign(_request())

    async def operator() -> BrowseResult:
        return await queue.enqueue_and_wait(signed, host_id="nas-1", timeout_seconds=5.0)

    task = asyncio.create_task(operator())
    polled = await queue.poll("nas-1", timeout_seconds=2.0)
    assert polled is not None and polled.request.request_id == "br-1"
    result = BrowseResult(request_id="br-1", path="/scan/data")
    queue.deliver(host_id="nas-1", result=result)
    assert (await task).path == "/scan/data"


async def test_queue_refuses_cross_host_delivery() -> None:
    signer, _ = _signer_verifier()
    queue = BrowsePullQueue(now=lambda: _IN_WINDOW)
    task = asyncio.create_task(
        queue.enqueue_and_wait(signer.sign(_request()), host_id="nas-1", timeout_seconds=5.0)
    )
    await queue.poll("nas-1", timeout_seconds=2.0)
    # a different host trying to answer the request scoped to nas-1
    bad = BrowseResult(request_id="br-1", path="/scan/data")
    with pytest.raises(BrowseCorrelationError):
        queue.deliver(host_id="evil-host", result=bad)
    queue.deliver(host_id="nas-1", result=BrowseResult(request_id="br-1", path="/scan/data"))
    await task  # cleanup


async def test_queue_times_out_when_no_agent_answers() -> None:
    signer, _ = _signer_verifier()
    queue = BrowsePullQueue()
    with pytest.raises(BrowsePullError):
        await queue.enqueue_and_wait(signer.sign(_request()), host_id="nas-1", timeout_seconds=0.05)
