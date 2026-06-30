"""Preview render WORKER route (ADR-014) — the gVisor side of the distributed render split.

Zero API-level coverage before this (GAPS: worker_render.py had no tests). The route is inert
(503) unless this instance is a preview worker, then it requires the shared proxy secret, then it
hands the bytes to the gVisor driver and maps any PreviewError to its HTTP status. We never run a
real sandbox here — `render_request` is monkeypatched so the route's gate/auth/mapping logic is
what's under test.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.settings import Settings
from fathom.preview.remote_driver import RenderResponse
from fathom.preview.types import PreviewError

_SECRET = "worker-shared-secret"


def _payload() -> dict[str, object]:
    return {
        "job_id": "j1",
        "type": "image",
        "caps": {
            "cpu": 1.0,
            "mem_bytes": 512 * 1024 * 1024,
            "time_s": 10.0,
            "max_pages": 50,
            "max_decompressed_bytes": 100 * 1024 * 1024,
        },
        "data_b64": base64.b64encode(b"bytes").decode(),
    }


async def _worker_client(tmp_path: object, *, enabled: bool) -> AsyncIterator[httpx.AsyncClient]:
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/wr.db",  # type: ignore[operator]
        auto_create_schema=True,
        preview_worker_enabled=enabled,
        ingest_proxy_secret=_SECRET,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def test_render_disabled_returns_503(tmp_path: object) -> None:
    async for client in _worker_client(tmp_path, enabled=False):
        resp = await client.post(
            "/api/v1/preview/render", json=_payload(), headers={"X-Fathom-Proxy-Secret": _SECRET}
        )
        assert resp.status_code == 503
        assert resp.json()["detail"] == "this instance is not a preview render worker"


async def test_render_missing_secret_is_401(tmp_path: object) -> None:
    async for client in _worker_client(tmp_path, enabled=True):
        resp = await client.post("/api/v1/preview/render", json=_payload())  # no secret header
        assert resp.status_code == 401


async def test_render_wrong_secret_is_401(tmp_path: object) -> None:
    async for client in _worker_client(tmp_path, enabled=True):
        resp = await client.post(
            "/api/v1/preview/render", json=_payload(), headers={"X-Fathom-Proxy-Secret": "nope"}
        )
        assert resp.status_code == 401


async def test_render_happy_path_returns_artifacts(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _fake_render(_payload: object, *, driver: object) -> RenderResponse:
        return RenderResponse(artifacts=[])

    monkeypatch.setattr("fathom.api.routers.worker_render.render_request", _fake_render)
    async for client in _worker_client(tmp_path, enabled=True):
        resp = await client.post(
            "/api/v1/preview/render", json=_payload(), headers={"X-Fathom-Proxy-Secret": _SECRET}
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"artifacts": []}


async def test_render_maps_preview_error_status(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An unsupported/oversized/timeout render surfaces as a PreviewError carrying its HTTP status;
    # the route must propagate that status verbatim (415 here), not a generic 500.
    async def _boom(_payload: object, *, driver: object) -> RenderResponse:
        raise PreviewError("unsupported type", status_code=415)

    monkeypatch.setattr("fathom.api.routers.worker_render.render_request", _boom)
    async for client in _worker_client(tmp_path, enabled=True):
        resp = await client.post(
            "/api/v1/preview/render", json=_payload(), headers={"X-Fathom-Proxy-Secret": _SECRET}
        )
        assert resp.status_code == 415
        assert resp.json()["detail"] == "unsupported type"
