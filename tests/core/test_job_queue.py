"""In-memory dispatch JobQueue tests (ADR-025 §1): correlation, claim-once, cross-host, expiry.

The queue is the core side of the agent-initiated channel. These exercise its invariants in
isolation (no HTTP): a dispatch awaits exactly its own result, a host only drains its own queue,
a claimed job is gone, an expired job is never delivered, and a mis-correlated result is refused.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.core.remediation.job import ActionJob, SignedJob
from fathom.core.remediation.job_queue import (
    DispatchTimeoutError,
    JobCorrelationError,
    JobQueue,
    JobResultPayload,
)
from fathom.core.remediation.plan import PlanAction, PlanItem
from fathom.core.remediation.signing import Ed25519Signer, sign_job


def _signed(
    *, host_id: str = "nas-1", nonce: str = "0123456789abcdef0123", ttl: int = 300
) -> SignedJob:
    now = datetime.now(tz=UTC)
    job = ActionJob(
        plan_id="plan-1",
        mode="execute",
        nonce=nonce,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=ttl),
        host_id=host_id,
        keeper_path="/v/keep.bin",
        items=[
            PlanItem(
                entry_id="dup",
                path="/v/dup.bin",
                prior_inode=42,
                prior_size=4096,
                prior_hash="abc",
                action=PlanAction.QUARANTINE,
            )
        ],
    )
    return sign_job(job, Ed25519Signer(Ed25519PrivateKey.generate(), key_id="orchestrator-v1"))


def _result(job_id: str, *, plan_id: str = "plan-1") -> JobResultPayload:
    return JobResultPayload(
        job_id=job_id,
        plan_id=plan_id,
        mode="execute",
        results=[{"entry_id": "dup", "action": "quarantine", "status": "quarantined"}],  # type: ignore[list-item]
    )


async def _poll_act_resolve(queue: JobQueue, *, host_id: str) -> None:
    """Simulate one agent: claim a job for ``host_id`` and post its result back."""
    claimed = await queue.poll(host_id=host_id)
    assert claimed is not None
    queue.resolve(host_id=host_id, payload=_result(claimed.job_id))


async def test_dispatch_awaits_its_own_result() -> None:
    queue = JobQueue()
    agent = asyncio.create_task(_poll_act_resolve(queue, host_id="nas-1"))
    result = await queue.enqueue_and_wait(_signed(), host_id="nas-1", timeout_seconds=5)
    await agent
    assert result.plan_id == "plan-1"
    assert [r.status for r in result.results] == ["quarantined"]


async def test_claim_once_second_poll_blocks_until_timeout() -> None:
    # A claimed job is gone from the queue: a second poll on the same host finds nothing and 204s.
    queue = JobQueue(poll_timeout_seconds=0.2)
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(), host_id="nas-1", timeout_seconds=5)
    )
    first = await queue.poll(host_id="nas-1")
    assert first is not None
    second = await queue.poll(host_id="nas-1")  # nothing left to claim
    assert second is None
    queue.resolve(host_id="nas-1", payload=_result(first.job_id))
    await dispatch


async def test_cross_host_cannot_claim_another_hosts_job() -> None:
    # Host B polling never sees host A's job (structural per-host scoping = no cross-host leakage).
    queue = JobQueue(poll_timeout_seconds=0.2)
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(host_id="nas-1"), host_id="nas-1", timeout_seconds=5)
    )
    other = await queue.poll(host_id="node-1")
    assert other is None  # host B drains only its own (empty) queue
    mine = await queue.poll(host_id="nas-1")
    assert mine is not None
    queue.resolve(host_id="nas-1", payload=_result(mine.job_id))
    await dispatch


async def test_cross_host_result_is_refused() -> None:
    # A result posted under host B for host A's job is rejected — an agent can only return its own.
    queue = JobQueue()
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(host_id="nas-1"), host_id="nas-1", timeout_seconds=5)
    )
    claimed = await queue.poll(host_id="nas-1")
    assert claimed is not None
    with pytest.raises(JobCorrelationError):
        queue.resolve(host_id="node-1", payload=_result(claimed.job_id))
    # The real host can still resolve it (the spoof did not consume the correlation).
    queue.resolve(host_id="nas-1", payload=_result(claimed.job_id))
    await dispatch


async def test_resolve_once_second_result_refused() -> None:
    queue = JobQueue()
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(), host_id="nas-1", timeout_seconds=5)
    )
    claimed = await queue.poll(host_id="nas-1")
    assert claimed is not None
    queue.resolve(host_id="nas-1", payload=_result(claimed.job_id))
    await dispatch
    with pytest.raises(JobCorrelationError):
        queue.resolve(host_id="nas-1", payload=_result(claimed.job_id))


async def test_unknown_job_result_refused() -> None:
    queue = JobQueue()
    with pytest.raises(JobCorrelationError):
        queue.resolve(host_id="nas-1", payload=_result("deadbeef"))


async def test_expired_job_is_dropped_not_delivered() -> None:
    # A job that aged past expiry while queued is dropped on poll (the agent is never handed a job
    # it would only refuse); its awaiting dispatch fails closed.
    queue = JobQueue(poll_timeout_seconds=0.2)
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(ttl=-1), host_id="nas-1", timeout_seconds=5)
    )
    await asyncio.sleep(0)  # let the enqueue run
    claimed = await queue.poll(host_id="nas-1")
    assert claimed is None  # expired → not delivered
    with pytest.raises(DispatchTimeoutError):
        await dispatch


async def test_dispatch_timeout_when_no_agent() -> None:
    queue = JobQueue()
    with pytest.raises(DispatchTimeoutError):
        await queue.enqueue_and_wait(_signed(), host_id="nas-1", timeout_seconds=0.2)


async def test_nonce_and_owner_lookup_cleared_after_dispatch() -> None:
    queue = JobQueue()
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(
            _signed(nonce="aaaabbbbccccdddd0000"), host_id="nas-1", timeout_seconds=5
        )
    )
    claimed = await queue.poll(host_id="nas-1")
    assert claimed is not None
    assert queue.owner_of(claimed.job_id) == "nas-1"
    assert queue.nonce_of(claimed.job_id) == "aaaabbbbccccdddd0000"
    queue.resolve(host_id="nas-1", payload=_result(claimed.job_id))
    await dispatch
    # Correlation state is reaped once the dispatch returns.
    assert queue.owner_of(claimed.job_id) is None
    assert queue.nonce_of(claimed.job_id) is None
