"""Agent preview-grant pull endpoints — the core side of the distributed signed single-file pull.

Builds its own app so the per-host PreviewPullQueue can be set on app.state (as the distributed
preview runtime does at startup); registers a host via an ingest batch so the cert fingerprint
resolves; then exercises poll → serve round-trip + the fail-closed mappings.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.settings import Settings
from fathom.preview.grant import FileGrant, GrantSigner, SignedFileGrant
from fathom.preview.pull import PreviewPullQueue
from tests.api.conftest import FINGERPRINT_HEADER, batch


def _signed_grant(*, grant_id: str = "g1", host_id: str = "nas-1") -> SignedFileGrant:
    now = datetime.now(tz=UTC)
    grant = FileGrant(
        grant_id=grant_id,
        entry_id=1,
        host_id=host_id,
        volume_id=1,
        inode=1,
        path="/mnt/pool/a.txt",
        nonce="a" * 16,
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    )
    return GrantSigner(Ed25519PrivateKey.generate(), key_id="preview-v1").sign(grant)


async def _app_with_queue(
    tmp_path, queue: PreviewPullQueue | None
) -> AsyncIterator[httpx.AsyncClient]:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'pp.db'}", auto_create_schema=True
    )
    await db.dispose_engine()
    app = create_app(settings)
    if queue is not None:
        app.state.preview_pull_queue = queue
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Register host "nas-1" against FINGERPRINT_HEADER so the pull routes resolve it.
            await client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
            yield client
    await db.dispose_engine()


async def test_poll_is_inert_204_when_preview_not_provisioned(tmp_path) -> None:
    async for client in _app_with_queue(tmp_path, None):
        resp = await client.post("/api/v1/agents/preview-grants/poll", headers=FINGERPRINT_HEADER)
        assert resp.status_code == 204


async def test_serve_is_inert_409_when_preview_not_provisioned(tmp_path) -> None:
    async for client in _app_with_queue(tmp_path, None):
        resp = await client.post(
            "/api/v1/agents/preview-grants/serve",
            json={"grant_id": "g1", "data_b64": base64.b64encode(b"x").decode()},
            headers=FINGERPRINT_HEADER,
        )
        assert resp.status_code == 409


async def test_poll_then_serve_delivers_bytes_to_awaiting_pull(tmp_path) -> None:
    queue = PreviewPullQueue()
    async for client in _app_with_queue(tmp_path, queue):
        # A fetch awaiting on the queue for host "nas-1".
        task = asyncio.create_task(
            queue.enqueue_and_wait(
                _signed_grant(), host_id="nas-1", max_bytes=1000, timeout_seconds=5
            )
        )
        await asyncio.sleep(0)  # let the grant land on the queue

        polled = await client.post("/api/v1/agents/preview-grants/poll", headers=FINGERPRINT_HEADER)
        assert polled.status_code == 200
        body = polled.json()
        assert body["max_bytes"] == 1000
        assert body["signed_grant"]["grant"]["grant_id"] == "g1"

        served = await client.post(
            "/api/v1/agents/preview-grants/serve",
            json={"grant_id": "g1", "data_b64": base64.b64encode(b"FILE-BYTES").decode()},
            headers=FINGERPRINT_HEADER,
        )
        assert served.status_code == 200
        assert await task == b"FILE-BYTES"


async def test_serve_unknown_grant_is_409(tmp_path) -> None:
    queue = PreviewPullQueue()
    async for client in _app_with_queue(tmp_path, queue):
        resp = await client.post(
            "/api/v1/agents/preview-grants/serve",
            json={"grant_id": "never", "data_b64": base64.b64encode(b"x").decode()},
            headers=FINGERPRINT_HEADER,
        )
        assert resp.status_code == 409


async def test_serve_malformed_base64_is_400(tmp_path) -> None:
    queue = PreviewPullQueue()
    async for client in _app_with_queue(tmp_path, queue):
        task = asyncio.create_task(
            queue.enqueue_and_wait(
                _signed_grant(), host_id="nas-1", max_bytes=1000, timeout_seconds=5
            )
        )
        await asyncio.sleep(0)
        await client.post("/api/v1/agents/preview-grants/poll", headers=FINGERPRINT_HEADER)
        resp = await client.post(
            "/api/v1/agents/preview-grants/serve",
            json={"grant_id": "g1", "data_b64": "not!valid!base64!"},
            headers=FINGERPRINT_HEADER,
        )
        assert resp.status_code == 400
        task.cancel()


async def test_poll_unregistered_fingerprint_is_403(tmp_path) -> None:
    queue = PreviewPullQueue()
    async for client in _app_with_queue(tmp_path, queue):
        resp = await client.post(
            "/api/v1/agents/preview-grants/poll",
            headers={"X-Client-Cert-Fingerprint": "zz:zz:zz:zz"},
        )
        assert resp.status_code == 403
