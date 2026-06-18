"""Dispatch-route tests (ADR-025 §1) on the mTLS agent boundary: poll/result + adversarial set.

These drive the two routes over a real ASGI app and a tmp catalogue, exercising the named
adversarial cases the ADR requires before the channel can carry a real job:

* **cross-host job leakage** — host B's poll never returns host A's job;
* **cross-host / spoofed result** — a result posted by the wrong host is refused;
* **replay** — a second result for the same job is rejected on the durable nonce ledger;
* **expiry** — an expired job is dropped, never delivered;
* **tampered job** — out of scope of the route itself (the *agent* verifies the signature; see
  ``tests/core/test_job_signing.py``), but the route never hands a job to a host it is not
  scoped to, so a tampered job for host B cannot even reach host A.

The queue is driven directly (a dispatch task enqueues) so the routes can be tested without the
full orchestrator wiring (that integration lands with step 2).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.catalogue.models import Host
from fathom.core.remediation.job import ActionJob, SignedJob
from fathom.core.remediation.job_queue import JobQueue, JobResultPayload
from fathom.core.remediation.plan import PlanAction, PlanItem
from fathom.core.remediation.signing import Ed25519Signer, sign_job
from fathom.core.settings import Settings

NAS1_FP = {"X-Client-Cert-Fingerprint": "ab:cd:ef:01"}
NODE1_FP = {"X-Client-Cert-Fingerprint": "11:22:33:44"}


@pytest.fixture
async def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        remediation_enabled=True,
    )


async def _seed_hosts() -> None:
    async with db.session_scope() as session:
        session.add(Host(name="nas-1", cert_fingerprint="ab:cd:ef:01"))
        session.add(Host(name="node-1", cert_fingerprint="11:22:33:44"))


def _signed(*, host_id: str, nonce: str = "0123456789abcdef0123", ttl: int = 300) -> SignedJob:
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


def _result_body(job_id: str) -> dict[str, object]:
    return JobResultPayload(
        job_id=job_id,
        plan_id="plan-1",
        mode="execute",
        results=[{"entry_id": "dup", "action": "quarantine", "status": "quarantined"}],  # type: ignore[list-item]
    ).model_dump(mode="json")


@pytest.fixture
async def app_client(settings: Settings) -> AsyncIterator[tuple[httpx.AsyncClient, JobQueue]]:
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        # Replace the default 25s long-poll with a short one so "empty queue" tests don't hang.
        queue = JobQueue(poll_timeout_seconds=0.3)
        app.state.job_queue = queue
        await _seed_hosts()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client, queue
    await db.dispose_engine()


async def test_poll_returns_204_when_no_jobs(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    client, _ = app_client
    resp = await client.post("/api/v1/agents/jobs/poll", headers=NAS1_FP)
    assert resp.status_code == 204


async def test_poll_unknown_fingerprint_refused(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    client, _ = app_client
    resp = await client.post(
        "/api/v1/agents/jobs/poll", headers={"X-Client-Cert-Fingerprint": "no:such:host"}
    )
    assert resp.status_code == 403


async def test_poll_requires_fingerprint(app_client: tuple[httpx.AsyncClient, JobQueue]) -> None:
    client, _ = app_client
    resp = await client.post("/api/v1/agents/jobs/poll")
    assert resp.status_code == 401  # no client cert


async def test_poll_delivers_then_result_resolves(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    client, queue = app_client
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(host_id="nas-1"), host_id="nas-1", timeout_seconds=5)
    )
    poll = await client.post("/api/v1/agents/jobs/poll", headers=NAS1_FP)
    assert poll.status_code == 200
    job_id = poll.json()["job_id"]
    assert poll.json()["signed_job"]["job"]["host_id"] == "nas-1"
    res = await client.post(
        f"/api/v1/agents/jobs/{job_id}/result", json=_result_body(job_id), headers=NAS1_FP
    )
    assert res.status_code == 200
    result = await dispatch
    assert [r.status for r in result.results] == ["quarantined"]


async def test_cross_host_job_leakage_blocked(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    # A job enqueued for nas-1 must never be delivered to node-1's poll.
    client, queue = app_client
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(host_id="nas-1"), host_id="nas-1", timeout_seconds=5)
    )
    leaked = await client.post("/api/v1/agents/jobs/poll", headers=NODE1_FP)
    assert leaked.status_code == 204  # node-1 sees nothing
    mine = await client.post("/api/v1/agents/jobs/poll", headers=NAS1_FP)
    assert mine.status_code == 200
    job_id = mine.json()["job_id"]
    await client.post(
        f"/api/v1/agents/jobs/{job_id}/result", json=_result_body(job_id), headers=NAS1_FP
    )
    await dispatch


async def test_cross_host_result_spoof_refused(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    # node-1 posts a result for nas-1's job_id → 409; nas-1's own result still works.
    client, queue = app_client
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(host_id="nas-1"), host_id="nas-1", timeout_seconds=5)
    )
    mine = await client.post("/api/v1/agents/jobs/poll", headers=NAS1_FP)
    job_id = mine.json()["job_id"]
    spoof = await client.post(
        f"/api/v1/agents/jobs/{job_id}/result", json=_result_body(job_id), headers=NODE1_FP
    )
    assert spoof.status_code == 409
    good = await client.post(
        f"/api/v1/agents/jobs/{job_id}/result", json=_result_body(job_id), headers=NAS1_FP
    )
    assert good.status_code == 200
    await dispatch


async def test_replayed_result_rejected_on_nonce_ledger(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    # A second result for the same job is rejected — the durable used_nonce ledger is the arbiter.
    client, queue = app_client
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(host_id="nas-1"), host_id="nas-1", timeout_seconds=5)
    )
    mine = await client.post("/api/v1/agents/jobs/poll", headers=NAS1_FP)
    job_id = mine.json()["job_id"]
    first = await client.post(
        f"/api/v1/agents/jobs/{job_id}/result", json=_result_body(job_id), headers=NAS1_FP
    )
    assert first.status_code == 200
    await dispatch
    replay = await client.post(
        f"/api/v1/agents/jobs/{job_id}/result", json=_result_body(job_id), headers=NAS1_FP
    )
    assert replay.status_code == 409


async def test_result_for_unknown_job_refused(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    client, _ = app_client
    resp = await client.post(
        "/api/v1/agents/jobs/deadbeef/result", json=_result_body("deadbeef"), headers=NAS1_FP
    )
    assert resp.status_code == 409


async def test_result_path_body_job_id_mismatch_422(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    client, _ = app_client
    resp = await client.post(
        "/api/v1/agents/jobs/AAA/result", json=_result_body("BBB"), headers=NAS1_FP
    )
    assert resp.status_code == 422


async def test_oversized_result_field_rejected_at_boundary(
    app_client: tuple[httpx.AsyncClient, JobQueue],
) -> None:
    # A compromised/buggy agent cannot flood core's audit chain: an over-long field is rejected by
    # the wire model before any route logic runs (anti-flood bound, adversarial-review fix).
    client, _ = app_client
    body = {
        "job_id": "x",
        "plan_id": "p",
        "mode": "execute",
        "results": [
            {"entry_id": "e", "action": "quarantine", "status": "quarantined", "detail": "z" * 5000}
        ],
    }
    resp = await client.post("/api/v1/agents/jobs/x/result", json=body, headers=NAS1_FP)
    assert resp.status_code == 422


async def test_expired_job_not_delivered(app_client: tuple[httpx.AsyncClient, JobQueue]) -> None:
    client, queue = app_client
    dispatch = asyncio.create_task(
        queue.enqueue_and_wait(_signed(host_id="nas-1", ttl=-1), host_id="nas-1", timeout_seconds=5)
    )
    await asyncio.sleep(0)
    poll = await client.post("/api/v1/agents/jobs/poll", headers=NAS1_FP)
    assert poll.status_code == 204  # expired → dropped, never delivered
    from fathom.core.remediation.job_queue import DispatchTimeoutError

    with pytest.raises(DispatchTimeoutError):
        await dispatch
