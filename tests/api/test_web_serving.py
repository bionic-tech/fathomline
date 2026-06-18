"""Security-headers (CSP) + static SPA serving tests (ui-viewer, frontend ADD §12/§15)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.settings import Settings


async def test_csp_header_has_no_unsafe_directives(api_client: httpx.AsyncClient) -> None:
    """The CSP must forbid unsafe-inline / unsafe-eval (frontend ADD §12, security ADD §2)."""
    resp = await api_client.get("/healthz")
    csp = resp.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


async def test_hardening_headers_present(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


async def test_csp_applies_to_api_responses(api_client: httpx.AsyncClient) -> None:
    # Even a 401 JSON problem response carries the security headers.
    resp = await api_client.get("/api/v1/volumes")
    assert resp.status_code == 401
    assert "Content-Security-Policy" in resp.headers


@pytest.fixture
async def web_dist(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>Fathom</title>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log('fathom')", encoding="utf-8")
    return dist


@pytest.fixture
async def spa_client(tmp_path: Path, web_dist: Path) -> AsyncIterator[httpx.AsyncClient]:
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        web_dist=str(web_dist),
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def test_spa_root_serves_index(spa_client: httpx.AsyncClient) -> None:
    resp = await spa_client.get("/")
    assert resp.status_code == 200
    assert "Fathom" in resp.text


async def test_spa_history_fallback_serves_index(spa_client: httpx.AsyncClient) -> None:
    # A client-side route path with no real file → index.html (history fallback).
    resp = await spa_client.get("/explore")
    assert resp.status_code == 200
    assert "Fathom" in resp.text


async def test_spa_does_not_shadow_api(spa_client: httpx.AsyncClient) -> None:
    # The SPA catch-all must not swallow the API surface.
    resp = await spa_client.get("/api/v1/volumes")
    assert resp.status_code == 401  # auth required, NOT the SPA index
    # An unknown /api path is a genuine 404, never the SPA index.
    missing = await spa_client.get("/api/v1/does-not-exist")
    assert missing.status_code == 404


async def test_spa_healthz_unaffected(spa_client: httpx.AsyncClient) -> None:
    resp = await spa_client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_spa_serves_real_asset(spa_client: httpx.AsyncClient) -> None:
    resp = await spa_client.get("/assets/app.js")
    assert resp.status_code == 200
    assert "fathom" in resp.text
