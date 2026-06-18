"""End-to-end dispatch-channel test (ADR-025 steps 1-3): orchestrator → queue → agent → result.

Unlike ``test_remediation_endpoints`` (which loops the dispatch straight into an in-process
listener), this drives the **real production channel**: the orchestrator's queue-backed dispatch
enqueues a signed job, a concurrent "agent" task long-polls ``/agents/jobs/poll`` over the mTLS
boundary, verifies + executes it with a real :class:`SignedJobListener`/:class:`Executor` over a
tmp filesystem, and posts the result to ``/agents/jobs/{id}/result``. The orchestrator's awaited
dispatch resolves from that posted result and splices the actor's act audit onto the durable chain.

This is the proof the channel actually carries a job to a remote agent and back — every guard
(signature, nonce, expiry, host scope, dry-run-first, audit-before-act) on the real path.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.agent.actor import ActorDispatcher, Executor, SignedJobListener
from fathom.agent.reader.hasher import BackendHasher
from fathom.api.app import create_app
from fathom.api.remediation_runtime import RemediationRuntime, build_queue_dispatch
from fathom.auth.principal import Role
from fathom.backends import PosixBackend
from fathom.core import db
from fathom.core.audit import AuditChain, verify_chain
from fathom.core.audit_store import persisted_records
from fathom.core.remediation.job_queue import (
    AuditRecordPayload,
    ClaimedJob,
    ExecResultPayload,
    JobQueue,
    JobResultPayload,
)
from fathom.core.remediation.nonce_store import InMemoryNonceStore
from fathom.core.remediation.signing import Ed25519Signer, Ed25519Verifier
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal
from tests.api.test_remediation_endpoints import _seed_group

FP = "X-Client-Cert-Fingerprint"
AGENT_FP = "ab:cd"  # the fingerprint _seed_group registers for host "nas-1"


@pytest.fixture
async def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        remediation_enabled=True,
        remediation_blast_cap=100,
    )


class _SimAgent:
    """A real agent listen loop driven over HTTP — the remote side of the channel, in-process."""

    def __init__(
        self, client: httpx.AsyncClient, *, verifier: Ed25519Verifier, quarantine_dir: Path
    ) -> None:
        self._client = client
        executor = Executor(
            quarantine_dir=quarantine_dir,
            audit=AuditChain(sink=lambda _r: None),
            write_enabled=True,
        )
        dispatcher = ActorDispatcher(executor=executor, hasher=BackendHasher(PosixBackend()))
        self._listener = SignedJobListener(
            dispatcher=dispatcher,
            verifier=verifier,
            nonce_store=InMemoryNonceStore(),
            host_id="nas-1",
            write_enabled=True,
        )
        self._stop = asyncio.Event()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                resp = await self._client.post("/api/v1/agents/jobs/poll", headers={FP: AGENT_FP})
            except (httpx.TransportError, RuntimeError):
                return
            if resp.status_code != 200:
                continue  # 204 (no job) → re-poll
            claimed = ClaimedJob.model_validate(resp.json())
            result = await self._listener.handle(claimed.signed_job, confirm_blast=True)
            payload = JobResultPayload(
                job_id=claimed.job_id,
                plan_id=result.plan_id,
                mode=result.mode,  # type: ignore[arg-type]
                drift=result.drift,
                results=[
                    ExecResultPayload(
                        entry_id=r.entry_id, action=r.action, status=r.status, detail=r.detail
                    )
                    for r in result.results
                ],
                audit=[
                    AuditRecordPayload(
                        ts=a.ts,
                        actor=a.actor,
                        action=a.action,
                        target=a.target,
                        before_state=a.before_state,
                        result=a.result,
                        prev_hash=a.prev_hash,
                        row_hash=a.row_hash,
                    )
                    for a in result.audit
                ],
            )
            await self._client.post(
                f"/api/v1/agents/jobs/{claimed.job_id}/result",
                json=payload.model_dump(mode="json"),
                headers={FP: AGENT_FP},
            )

    def stop(self) -> None:
        self._stop.set()


@pytest.fixture
async def wired(
    settings: Settings, tmp_path: Path
) -> AsyncIterator[tuple[httpx.AsyncClient, _SimAgent]]:
    await db.dispose_engine()
    app = create_app(settings)
    priv = Ed25519PrivateKey.generate()
    queue = JobQueue(poll_timeout_seconds=0.2)
    dry_run_dispatch, execute_dispatch = build_queue_dispatch(queue, job_ttl_seconds=300)
    async with LifespanManager(app):
        # Override the lifespan-provisioned queue/runtime with a generated keypair so the agent's
        # verifier can pin the matching public key (no env secrets needed in-test). This is the
        # REAL queue-backed dispatch, not the loopback listener.
        app.state.job_queue = queue
        app.state.remediation_runtime = RemediationRuntime(
            signer=Ed25519Signer(priv, key_id="orchestrator-v1"),
            dry_run_dispatch=dry_run_dispatch,
            execute_dispatch=execute_dispatch,
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            agent = _SimAgent(
                client,
                verifier=Ed25519Verifier(priv.public_key(), key_id="orchestrator-v1"),
                quarantine_dir=tmp_path / "quarantine",
            )
            task = asyncio.create_task(agent.run())
            try:
                yield client, agent
            finally:
                agent.stop()
                await asyncio.wait_for(task, timeout=5)
    await db.dispose_engine()


async def test_execute_quarantines_over_real_channel(
    wired: tuple[httpx.AsyncClient, _SimAgent], tmp_path: Path
) -> None:
    client, _agent = wired
    group_id, keep_id, _ = await _seed_group(tmp_path)
    mfa = await seed_principal(username="e2e", role=Role.REMEDIATOR, mfa_fresh=True)

    built = await client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=mfa,
    )
    assert built.status_code == 201, built.text
    plan_id = built.json()["plan_id"]

    # Dry-run over the real channel: the agent claims the signed DRY_RUN job, re-verifies the live
    # FS, and posts the (clean) drift report back, which resolves the orchestrator's awaited call.
    dr = await client.post(f"/api/v1/remediation/plans/{plan_id}/dry-run", headers=mfa)
    assert dr.status_code == 200, dr.text
    assert dr.json()["ok"] is True

    # Execute over the real channel: dry-run-first job + EXECUTE job both flow agent-side; the
    # duplicate is quarantined on the agent's tmp filesystem and the keeper is untouched.
    ex = await client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute",
        json={"confirm_host": "nas-1"},
        headers=mfa,
    )
    assert ex.status_code == 200, ex.text
    assert [r["status"] for r in ex.json()["results"]] == ["quarantined"]
    assert not (tmp_path / "data" / "dup.bin").exists()
    assert (tmp_path / "data" / "keep.bin").exists()

    # The actor's per-item act audit was carried back over the result channel and spliced onto the
    # durable hash-chained store, and the chain is unbroken end-to-end.
    async with db.session_scope() as session:
        records = await persisted_records(session)
        assert verify_chain(records) is True
        acts = [r for r in records if r.actor == "strata-actor" and r.action == "quarantine"]
        assert any(r.result == "quarantined" for r in acts)


async def test_unknown_agent_cannot_poll(wired: tuple[httpx.AsyncClient, _SimAgent]) -> None:
    # A fingerprint with no registered host is refused (the channel never serves an unknown caller).
    client, _agent = wired
    resp = await client.post("/api/v1/agents/jobs/poll", headers={FP: "zz:zz:zz"})
    assert resp.status_code == 403
