"""Scan Now (P3) — operator endpoint that builds + signs + enqueues a ScanJob for a host.

``POST /api/v1/agents/{host_id}/scan`` is the CORE/operator side of Scan Now: it gates on the
scan-trigger capability + scope (non-destructive → no step-up MFA), validates the host + scan
root server-side, then signs a single-use, time-boxed :class:`ScanJob` with the orchestrator's
signer and enqueues it for the host over the existing ADR-025 dispatch channel. It is
non-blocking (``202`` with a job id) — the agent claims it on its next long-poll and scans async.

These tests cover: a happy enqueue (the signed job lands on the host's queue and verifies under
the orchestrator public key), ``503`` when the dispatch runtime is not armed, ``404`` for an
unknown host, ``422`` for a bad mode / unknown root, and the capability + scope ``403``s.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select

from fathom.api.app import create_app
from fathom.api.remediation_runtime import RemediationRuntime, build_queue_dispatch
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.catalogue.models import Host
from fathom.core.remediation.job_queue import JobQueue
from fathom.core.remediation.signing import Ed25519Signer, Ed25519Verifier
from fathom.core.settings import Settings
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal

KEY_ID = "orchestrator-v1"


async def _seed_host(client: httpx.AsyncClient) -> int:
    """Ingest a batch (registers host ``nas-1`` + volume ``/mnt/pool``); return the DB host id."""
    resp = await client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200, resp.text
    async with db.session_scope() as session:
        return (await session.execute(select(Host).where(Host.name == "nas-1"))).scalar_one().id


@pytest.fixture
async def armed(
    tmp_path: Path,
) -> AsyncIterator[tuple[httpx.AsyncClient, JobQueue, Ed25519PublicKey]]:
    """A running app with the dispatch runtime ARMED: a generated Ed25519 signer + the real queue.

    Mirrors the dispatch-e2e fixture: we override the lifespan-provisioned queue/runtime with a
    generated keypair so a verifier can pin the matching public key without env secrets. Yields the
    client, the queue (to inspect what was enqueued), and the orchestrator public key.
    """
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        remediation_enabled=True,
    )
    await db.dispose_engine()
    app = create_app(settings)
    priv = Ed25519PrivateKey.generate()
    queue = JobQueue(poll_timeout_seconds=0.5)
    dry_run_dispatch, execute_dispatch = build_queue_dispatch(queue, job_ttl_seconds=300)
    async with LifespanManager(app):
        app.state.job_queue = queue
        app.state.remediation_runtime = RemediationRuntime(
            signer=Ed25519Signer(priv, key_id=KEY_ID),
            dry_run_dispatch=dry_run_dispatch,
            execute_dispatch=execute_dispatch,
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client, queue, priv.public_key()
    await db.dispose_engine()


async def test_scan_now_enqueues_signed_job(
    armed: tuple[httpx.AsyncClient, JobQueue, Ed25519PublicKey],
) -> None:
    client, queue, public_key = armed
    host_id = await _seed_host(client)
    auth = await seed_principal(role=Role.OPERATOR)

    resp = await client.post(
        f"/api/v1/agents/{host_id}/scan",
        json={"root": "/mnt/pool", "mode": "metadata"},
        headers=auth,
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["host"] == "nas-1"
    assert body["root"] == "/mnt/pool"
    assert body["mode"] == "metadata"
    assert body["job_id"]

    # The signed job landed on THIS host's queue as a scan_now job that verifies under the
    # orchestrator's public key — the agent's pinned verifier will accept exactly this job.
    claimed = await queue.poll(host_id="nas-1")
    assert claimed is not None
    signed = claimed.signed_job
    assert signed.job.kind == "scan_now"
    assert signed.job.host_id == "nas-1"
    assert signed.job.root == "/mnt/pool"
    assert signed.job.mode == "metadata"
    assert signed.job.nonce == body["job_id"]
    assert Ed25519Verifier(public_key, key_id=KEY_ID).verify_signature(signed) is True


async def test_scan_now_fullbit_mode(
    armed: tuple[httpx.AsyncClient, JobQueue, Ed25519PublicKey],
) -> None:
    # An operator holds TRIGGER_FULLBIT_SCAN, so a full-bit Scan Now is accepted and signed as such.
    client, queue, _public_key = armed
    host_id = await _seed_host(client)
    auth = await seed_principal(role=Role.OPERATOR)

    resp = await client.post(
        f"/api/v1/agents/{host_id}/scan",
        json={"root": "/mnt/pool", "mode": "fullbit"},
        headers=auth,
    )
    assert resp.status_code == 202, resp.text
    claimed = await queue.poll(host_id="nas-1")
    assert claimed is not None
    assert claimed.signed_job.job.mode == "fullbit"


async def test_scan_now_503_when_dispatch_not_armed(api_client: httpx.AsyncClient) -> None:
    # Default posture: remediation disabled → no signer/runtime provisioned → dispatch unavailable.
    host_id = await _seed_host(api_client)
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        f"/api/v1/agents/{host_id}/scan",
        json={"root": "/mnt/pool", "mode": "metadata"},
        headers=auth,
    )
    assert resp.status_code == 503, resp.text
    assert "scan dispatch is not enabled" in resp.json()["detail"]


async def test_scan_now_unknown_host_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        "/api/v1/agents/999999/scan",
        json={"root": "/mnt/pool", "mode": "metadata"},
        headers=auth,
    )
    assert resp.status_code == 404


async def test_scan_now_bad_mode_422(api_client: httpx.AsyncClient) -> None:
    host_id = await _seed_host(api_client)
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        f"/api/v1/agents/{host_id}/scan",
        json={"root": "/mnt/pool", "mode": "turbo"},  # not metadata|fullbit
        headers=auth,
    )
    assert resp.status_code == 422


async def test_scan_now_unknown_root_422(api_client: httpx.AsyncClient) -> None:
    host_id = await _seed_host(api_client)
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        f"/api/v1/agents/{host_id}/scan",
        json={"root": "/not/a/registered/volume", "mode": "metadata"},
        headers=auth,
    )
    assert resp.status_code == 422
    assert "known scan root" in resp.json()["detail"]


async def test_scan_now_viewer_denied_403(api_client: httpx.AsyncClient) -> None:
    # A viewer lacks the scan-trigger capability → deny-by-default 403 (no scan is enqueued).
    host_id = await _seed_host(api_client)
    auth = await seed_principal(role=Role.VIEWER)
    resp = await api_client.post(
        f"/api/v1/agents/{host_id}/scan",
        json={"root": "/mnt/pool", "mode": "metadata"},
        headers=auth,
    )
    assert resp.status_code == 403


async def test_scan_now_out_of_scope_403(api_client: httpx.AsyncClient) -> None:
    # An operator scoped to a different volume cannot trigger a scan of the in-scope-elsewhere
    # volume — server-authoritative scope refuses the target (before any dispatch).
    host_id = await _seed_host(api_client)
    auth = await seed_principal(
        username="scoped", role=Role.OPERATOR, scope_kind="volume", volume_id=999999
    )
    resp = await api_client.post(
        f"/api/v1/agents/{host_id}/scan",
        json={"root": "/mnt/pool", "mode": "metadata"},
        headers=auth,
    )
    assert resp.status_code == 403
