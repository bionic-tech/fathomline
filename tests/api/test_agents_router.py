"""Agents router tests — read-only fleet topology, VIEW_METADATA-gated, scope-filtered (ADD 04).

GET /api/v1/agents lists registered hosts with agent liveness and a catalogued-volume count. It
is a *read* surface: a viewer may read it, an out-of-scope principal sees only the hosts it can
reach (host-scoped, or carrying a volume it has a volume-scoped grant on), and it never mutates.
"""

from __future__ import annotations

import httpx

from fathom.auth.principal import Role
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


async def _seed_host_with_volumes(api_client: httpx.AsyncClient) -> tuple[int, int]:
    """Ingest two volumes on the one host; return (host_id, first volume_id)."""
    r1 = await api_client.post(
        "/api/v1/agents/ingest", json=batch(mountpoint="/mnt/pool"), headers=FINGERPRINT_HEADER
    )
    r2 = await api_client.post(
        "/api/v1/agents/ingest", json=batch(mountpoint="/mnt/tank"), headers=FINGERPRINT_HEADER
    )
    vol_id = r1.json()["volume_id"]
    assert r2.status_code == 200
    # The ingest batch always names host "nas-1"; both volumes hang off the same host row.
    return r1.json()["host_id"], vol_id


async def test_list_agents_requires_auth(api_client: httpx.AsyncClient) -> None:
    await _seed_host_with_volumes(api_client)
    resp = await api_client.get("/api/v1/agents")
    assert resp.status_code == 401


async def test_list_agents_reports_volume_count(api_client: httpx.AsyncClient) -> None:
    host_id, _ = await _seed_host_with_volumes(api_client)
    viewer = await seed_principal(role=Role.VIEWER)
    resp = await api_client.get("/api/v1/agents", headers=viewer)
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert len(rows) == 1
    host = rows[0]
    assert host["id"] == host_id
    assert host["name"] == "nas-1"
    assert host["os"] == "TrueNAS"
    assert host["agent_version"] == "0.1.0"
    assert host["volume_count"] == 2


async def test_list_agents_volume_scoped_sees_owning_host(api_client: httpx.AsyncClient) -> None:
    # A principal with only a volume-scoped grant must still see the host that owns that volume —
    # a purely host-id filter would wrongly hide it.
    host_id, vol_id = await _seed_host_with_volumes(api_client)
    scoped = await seed_principal(
        username="scoped", role=Role.VIEWER, scope_kind="volume", volume_id=vol_id
    )
    resp = await api_client.get("/api/v1/agents", headers=scoped)
    assert resp.status_code == 200
    rows = resp.json()
    assert [h["id"] for h in rows] == [host_id]


async def test_list_agents_out_of_scope_hidden(api_client: httpx.AsyncClient) -> None:
    host_id, _ = await _seed_host_with_volumes(api_client)
    # Host-scoped to a different host id → the seeded host is out of scope → empty fleet.
    scoped = await seed_principal(
        username="scoped", role=Role.VIEWER, scope_kind="host", host_id=host_id + 999
    )
    resp = await api_client.get("/api/v1/agents", headers=scoped)
    assert resp.status_code == 200
    assert resp.json() == []
