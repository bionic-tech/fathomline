"""Scan coordinator route tests (ADR-036) — the mTLS lease endpoint, the gate, the advisory read.

Covers: the lease endpoint grants-all when disabled (inert by default); when enabled it serializes
heavy scans (grant, then defer with a blocking-host advisory); the run-report releases the lease so
the next heavy scan proceeds; and the advisory surface is auth-gated and lists deferrals.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy import select

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.catalogue.models import AgentRun, Host
from fathom.core.catalogue.scan_lease_meta import LEASE_ACTIVE, ScanLease
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal

_NOW = datetime(2026, 6, 19, 12, 0, tzinfo=UTC)


@pytest.fixture
async def coord_client(tmp_path: object) -> AsyncIterator[httpx.AsyncClient]:
    """A client whose app has the scan coordinator enabled (the default app keeps it OFF)."""
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/cat.db",  # type: ignore[attr-defined]
        auto_create_schema=True,
        session_cookie_secure=False,
        scan_coordinator_enabled=True,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def _seed_heavy_host(name: str, *, entries: int = 600_000) -> dict[str, str]:
    """Insert a host + a heavy last-run; return its mTLS fingerprint header."""
    fp = f"fp:{name}"
    async with db.session_scope() as session:
        host = Host(name=name, cert_fingerprint=fp)
        session.add(host)
        await session.flush()
        session.add(
            AgentRun(
                host_id=host.id,
                started_at=_NOW - timedelta(minutes=10),
                finished_at=_NOW,
                outcome="ok",
                entries_seen=entries,
                rows_changed=0,
                pushed=0,
                scopes_total=1,
                scopes_failed=0,
            )
        )
        await session.flush()
    return {"X-Client-Cert-Fingerprint": fp}


async def test_lease_grants_all_when_disabled(api_client: httpx.AsyncClient) -> None:
    # Default app: coordinator OFF → grants unconditionally, even an unknown fingerprint.
    resp = await api_client.post(
        "/api/v1/agents/scan-lease", headers={"X-Client-Cert-Fingerprint": "whoever"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["granted"] is True


async def test_lease_grant_then_defer(coord_client: httpx.AsyncClient) -> None:
    a = await _seed_heavy_host("host-a")
    b = await _seed_heavy_host("host-b")
    granted = await coord_client.post("/api/v1/agents/scan-lease", headers=a)
    assert granted.json()["granted"] is True

    deferred = await coord_client.post("/api/v1/agents/scan-lease", headers=b)
    body = deferred.json()
    assert body["granted"] is False
    assert body["status"] == "deferred"
    assert body["blocking_host"] == "host-a"
    assert body["retry_after_seconds"] > 0


async def test_run_report_releases_lease(coord_client: httpx.AsyncClient) -> None:
    a = await _seed_heavy_host("host-a")
    b = await _seed_heavy_host("host-b")
    assert (await coord_client.post("/api/v1/agents/scan-lease", headers=a)).json()["granted"]
    assert not (await coord_client.post("/api/v1/agents/scan-lease", headers=b)).json()["granted"]

    # host-a reports its run → its lease releases.
    report = {
        "started_at": (_NOW - timedelta(minutes=5)).isoformat(),
        "finished_at": _NOW.isoformat(),
        "pushed": 10,
        "scopes": [{"root": "/scan/data", "entries_seen": 600000, "rows_changed": 1}],
        "agent_version": "test",
    }
    rr = await coord_client.post("/api/v1/agents/runs", json=report, headers=a)
    assert rr.status_code == 200, rr.text

    # Now host-b's heavy scan can proceed.
    assert (await coord_client.post("/api/v1/agents/scan-lease", headers=b)).json()["granted"]


async def test_lease_unknown_fingerprint_granted_when_enabled(
    coord_client: httpx.AsyncClient,
) -> None:
    # EC-coord-2: with the coordinator ENABLED, a fingerprint with no host row yet (never ingested)
    # has nothing to gate, so it is still granted an active lease — the gate keys on known hosts.
    resp = await coord_client.post(
        "/api/v1/agents/scan-lease", headers={"X-Client-Cert-Fingerprint": "never-ingested"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["granted"] is True
    assert body["status"] == "active"


async def test_at_most_max_concurrent_heavy_active(coord_client: httpx.AsyncClient) -> None:
    # EC-coord-5: three heavy hosts ask at once; with max_concurrent_heavy=1 (the default) exactly
    # one is granted and the rest deferred — the cap lives in the coordinator's count check, not a
    # DB constraint. Asserts the actual observed behavior.
    a = await _seed_heavy_host("host-a")
    b = await _seed_heavy_host("host-b")
    c = await _seed_heavy_host("host-c")
    verdicts = [
        (await coord_client.post("/api/v1/agents/scan-lease", headers=h)).json() for h in (a, b, c)
    ]
    granted = [v for v in verdicts if v["granted"]]
    deferred = [v for v in verdicts if not v["granted"]]
    assert len(granted) == 1  # max_concurrent_heavy default
    assert len(deferred) == 2
    # The cap holds in the catalogue too: exactly one ACTIVE heavy lease exists.
    async with db.session_scope() as session:
        active_heavy = (
            (
                await session.execute(
                    select(ScanLease.id).where(
                        ScanLease.status == LEASE_ACTIVE, ScanLease.is_heavy.is_(True)
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(active_heavy) == 1


async def test_advisories_rejects_out_of_range_limit(coord_client: httpx.AsyncClient) -> None:
    # EC-coord-10: the advisory read clamps its page size at the boundary — limit < 1 or > 200 is a
    # 422 (Query ge=1, le=200), so a client can't request an unbounded scan.
    auth = await seed_principal()
    too_small = await coord_client.get(
        "/api/v1/scan-coordinator/advisories", params={"limit": 0}, headers=auth
    )
    assert too_small.status_code == 422
    too_large = await coord_client.get(
        "/api/v1/scan-coordinator/advisories", params={"limit": 201}, headers=auth
    )
    assert too_large.status_code == 422


async def test_advisories_empty_when_no_events(coord_client: httpx.AsyncClient) -> None:
    # EC-coord-11: with no lease activity there are no coordinator events → an empty list (200),
    # not an error.
    auth = await seed_principal()
    resp = await coord_client.get("/api/v1/scan-coordinator/advisories", headers=auth)
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


async def test_advisories_auth_and_listing(coord_client: httpx.AsyncClient) -> None:
    a = await _seed_heavy_host("host-a")
    b = await _seed_heavy_host("host-b")
    await coord_client.post("/api/v1/agents/scan-lease", headers=a)
    await coord_client.post("/api/v1/agents/scan-lease", headers=b)  # deferred → advisory

    # Unauthenticated read is refused.
    assert (await coord_client.get("/api/v1/scan-coordinator/advisories")).status_code == 401

    auth = await seed_principal()
    resp = await coord_client.get("/api/v1/scan-coordinator/advisories", headers=auth)
    assert resp.status_code == 200, resp.text
    deferrals = [r for r in resp.json() if r["status"] == "deferred"]
    assert any(r["host_name"] == "host-b" and r["blocking_host"] == "host-a" for r in deferrals)
