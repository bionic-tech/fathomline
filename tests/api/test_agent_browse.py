"""Live directory browse routes (ADR-034 Phase 2) — agent poll/result + operator gating.

Zero API-level coverage before this (GAPS: agent_browse.py had no tests). Mirrors the preview-pull
test: build an app so the per-host BrowsePullQueue + signer can be set on app.state (as the browse
runtime does at startup), register a host so the cert fingerprint resolves, then exercise the agent
poll→result rendezvous, the inert (off) mappings, and the operator route's auth / step-up-MFA /
503-not-provisioned / 404-unknown-host gates. Browse is read-only — no file contents ever cross.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.api.app import create_app
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.browse import (
    BrowsePullError,
    BrowsePullQueue,
    BrowseRequest,
    BrowseResult,
    BrowseSigner,
    SignedBrowseRequest,
)
from fathom.core.settings import Settings
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal

_HOST = "nas-1"  # the host name conftest.batch registers against FINGERPRINT_HEADER


def _signer() -> BrowseSigner:
    return BrowseSigner(Ed25519PrivateKey.generate(), key_id="browse-v1")


def _signed_request(
    signer: BrowseSigner, *, request_id: str = "r1", host_id: str = _HOST
) -> SignedBrowseRequest:
    now = datetime.now(tz=UTC)
    return signer.sign(
        BrowseRequest(
            request_id=request_id,
            host_id=host_id,
            path="/mnt/pool",
            nonce="a" * 16,
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
        )
    )


async def _app(
    tmp_path: Path,
    *,
    queue: BrowsePullQueue | None = None,
    signer: BrowseSigner | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'ab.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
    )
    app = create_app(settings)
    if queue is not None:
        app.state.browse_pull_queue = queue
    if signer is not None:
        app.state.browse_signer = signer
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
            yield client
    await db.dispose_engine()


# --- agent-facing poll / result -----------------------------------------------------------


async def test_poll_inert_204_when_browse_off(tmp_path: Path) -> None:
    async for client in _app(tmp_path):  # no queue on app.state → browse off
        resp = await client.post("/api/v1/agents/browse/poll", headers=FINGERPRINT_HEADER)
        assert resp.status_code == 204


async def test_result_inert_409_when_browse_off(tmp_path: Path) -> None:
    async for client in _app(tmp_path):
        resp = await client.post(
            "/api/v1/agents/browse/result",
            json={"request_id": "r1", "path": "/mnt/pool"},
            headers=FINGERPRINT_HEADER,
        )
        assert resp.status_code == 409


async def test_poll_requires_client_fingerprint_401(tmp_path: Path) -> None:
    async for client in _app(tmp_path, queue=BrowsePullQueue()):
        resp = await client.post("/api/v1/agents/browse/poll")  # no fingerprint header
        assert resp.status_code == 401


async def test_poll_unregistered_fingerprint_403(tmp_path: Path) -> None:
    async for client in _app(tmp_path, queue=BrowsePullQueue()):
        resp = await client.post(
            "/api/v1/agents/browse/poll", headers={"X-Client-Cert-Fingerprint": "zz:zz:zz:zz"}
        )
        assert resp.status_code == 403  # no registered host for this cert


async def test_poll_then_result_round_trip(tmp_path: Path) -> None:
    queue = BrowsePullQueue()
    signer = _signer()
    async for client in _app(tmp_path, queue=queue, signer=signer):
        # An operator (here: the queue directly) awaits a listing for host nas-1.
        signed = _signed_request(signer)
        task = asyncio.create_task(queue.enqueue_and_wait(signed, host_id=_HOST, timeout_seconds=5))
        await asyncio.sleep(0)  # let the request land on the queue

        polled = await client.post("/api/v1/agents/browse/poll", headers=FINGERPRINT_HEADER)
        assert polled.status_code == 200
        req_id = polled.json()["signed_request"]["request"]["request_id"]
        assert req_id == "r1"

        served = await client.post(
            "/api/v1/agents/browse/result",
            json=BrowseResult(request_id=req_id, path="/mnt/pool").model_dump(),
            headers=FINGERPRINT_HEADER,
        )
        assert served.status_code == 200
        delivered = await task
        assert delivered.request_id == "r1"


async def test_result_unknown_request_409(tmp_path: Path) -> None:
    async for client in _app(tmp_path, queue=BrowsePullQueue()):
        resp = await client.post(
            "/api/v1/agents/browse/result",
            json={"request_id": "never-issued", "path": "/mnt/pool"},
            headers=FINGERPRINT_HEADER,
        )
        assert resp.status_code == 409  # no awaiting browse for this request_id


# --- operator-facing /{host_id}/browse (MANAGE_AGENTS + step-up MFA, scope-checked) -------


async def test_operator_browse_requires_auth_401(tmp_path: Path) -> None:
    async for client in _app(tmp_path):
        resp = await client.post("/api/v1/agents/1/browse", json={"path": "/mnt/pool"})
        assert resp.status_code == 401


async def test_operator_browse_requires_manage_agents_403(tmp_path: Path) -> None:
    async for client in _app(tmp_path):
        viewer = await seed_principal(username="viewer", role=Role.VIEWER, mfa_fresh=True)
        resp = await client.post(
            "/api/v1/agents/1/browse", json={"path": "/mnt/pool"}, headers=viewer
        )
        assert resp.status_code == 403  # lacks MANAGE_AGENTS


async def test_operator_browse_requires_step_up_mfa_401(tmp_path: Path) -> None:
    async for client in _app(tmp_path):
        admin = await seed_principal(username="staleadmin", mfa_fresh=False)
        resp = await client.post(
            "/api/v1/agents/1/browse", json={"path": "/mnt/pool"}, headers=admin
        )
        assert resp.status_code == 401  # MANAGE_AGENTS ok, but step-up MFA not fresh


async def test_operator_browse_503_when_not_provisioned(tmp_path: Path) -> None:
    async for client in _app(tmp_path):  # no queue/signer wired
        admin = await seed_principal(username="admin", mfa_fresh=True)
        resp = await client.post(
            "/api/v1/agents/1/browse", json={"path": "/mnt/pool"}, headers=admin
        )
        assert resp.status_code == 503
        assert resp.json()["detail"] == "live browse is not enabled on this core"


async def test_operator_browse_unknown_host_404(tmp_path: Path) -> None:
    async for client in _app(tmp_path, queue=BrowsePullQueue(), signer=_signer()):
        admin = await seed_principal(username="admin", mfa_fresh=True)
        resp = await client.post(
            "/api/v1/agents/999/browse", json={"path": "/mnt/pool"}, headers=admin
        )
        assert resp.status_code == 404
        assert resp.json()["detail"] == "host not found or out of scope"


async def test_operator_browse_empty_path_422(tmp_path: Path) -> None:
    async for client in _app(tmp_path, queue=BrowsePullQueue(), signer=_signer()):
        admin = await seed_principal(username="admin", mfa_fresh=True)
        resp = await client.post("/api/v1/agents/1/browse", json={"path": ""}, headers=admin)
        assert resp.status_code == 422  # path min_length=1


async def test_operator_browse_agent_timeout_504(tmp_path: Path) -> None:
    # A queue that never gets a delivery → enqueue_and_wait raises BrowsePullError → 504. Use a
    # stub so the test doesn't actually block for the (>=5s) request TTL.
    class _TimeoutQueue(BrowsePullQueue):
        async def enqueue_and_wait(self, signed, *, host_id, timeout_seconds):  # type: ignore[override]
            raise BrowsePullError("agent did not answer")

    async for client in _app(tmp_path, queue=_TimeoutQueue(), signer=_signer()):
        admin = await seed_principal(username="admin", mfa_fresh=True)
        resp = await client.post(
            "/api/v1/agents/1/browse", json={"path": "/mnt/pool"}, headers=admin
        )
        assert resp.status_code == 504
