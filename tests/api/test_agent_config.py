"""Agent config report + override endpoints — ADR-033 (#9 view, #10 operator override).

The agent reports its effective config on a run (shown via GET /agents); an operator with
MANAGE_AGENTS sets a per-host override (PUT /agents/{id}/config, audited); the agent pulls its
override over the mTLS channel (GET /agents/config, fingerprint-auth) or gets 204 when none.
"""

from __future__ import annotations

import httpx

from fathom.auth.principal import Role
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal

_OVERRIDE = {
    "scan_scope": ["/scan/data"],
    "exclude_scope": ["/scan/data/cache"],  # ADR-034 subtree exclude
    "cross_mounts": True,
}


async def _seed_host(api_client: httpx.AsyncClient) -> int:
    r = await api_client.post(
        "/api/v1/agents/ingest", json=batch(mountpoint="/mnt/pool"), headers=FINGERPRINT_HEADER
    )
    assert r.status_code == 200, r.text
    return r.json()["host_id"]


async def test_run_report_stores_effective_config_shown_in_agents(
    api_client: httpx.AsyncClient,
) -> None:
    host_id = await _seed_host(api_client)
    rep = {
        "started_at": "2026-06-15T00:00:00+00:00",
        "finished_at": "2026-06-15T00:00:05+00:00",
        "scopes": [{"root": "/scan/data", "entries_seen": 3, "rows_changed": 3}],
        "reported_config": {
            "scan_scope": ["/scan/data"],
            "write_enabled": False,
            "cross_mounts": True,
        },
    }
    r = await api_client.post("/api/v1/agents/runs", json=rep, headers=FINGERPRINT_HEADER)
    assert r.status_code == 200, r.text
    admin = await seed_principal(role=Role.ADMIN)
    host = next(
        h
        for h in (await api_client.get("/api/v1/agents", headers=admin)).json()
        if h["id"] == host_id
    )
    assert host["reported_config"] == {
        "scan_scope": ["/scan/data"],
        "write_enabled": False,
        "cross_mounts": True,
    }


async def test_operator_sets_override_then_agent_pulls_it(api_client: httpx.AsyncClient) -> None:
    host_id = await _seed_host(api_client)
    admin = await seed_principal(role=Role.ADMIN)
    # set the override
    put = await api_client.put(f"/api/v1/agents/{host_id}/config", json=_OVERRIDE, headers=admin)
    assert put.status_code == 204, put.text
    # shown in the UI list
    host = next(
        h
        for h in (await api_client.get("/api/v1/agents", headers=admin)).json()
        if h["id"] == host_id
    )
    assert host["desired_config"] == _OVERRIDE
    # the agent pulls its override over the mTLS channel (fingerprint-auth)
    got = await api_client.get("/api/v1/agents/config", headers=FINGERPRINT_HEADER)
    assert got.status_code == 200
    assert got.json() == _OVERRIDE


async def test_agent_config_is_204_when_no_override(api_client: httpx.AsyncClient) -> None:
    await _seed_host(api_client)
    got = await api_client.get("/api/v1/agents/config", headers=FINGERPRINT_HEADER)
    assert got.status_code == 204


async def test_override_rejects_non_overridable_keys(api_client: httpx.AsyncClient) -> None:
    host_id = await _seed_host(api_client)
    admin = await seed_principal(role=Role.ADMIN)
    for bad in ({"write_enabled": True}, {"host_id": "evil"}, {"ingest_url": "https://x"}):
        r = await api_client.put(f"/api/v1/agents/{host_id}/config", json=bad, headers=admin)
        assert r.status_code == 422, f"{bad} -> {r.status_code}"  # extra=forbid


async def test_override_requires_manage_agents(api_client: httpx.AsyncClient) -> None:
    host_id = await _seed_host(api_client)
    viewer = await seed_principal(role=Role.VIEWER)  # no MANAGE_AGENTS
    r = await api_client.put(f"/api/v1/agents/{host_id}/config", json=_OVERRIDE, headers=viewer)
    assert r.status_code == 403


async def test_empty_override_clears_it(api_client: httpx.AsyncClient) -> None:
    host_id = await _seed_host(api_client)
    admin = await seed_principal(role=Role.ADMIN)
    await api_client.put(f"/api/v1/agents/{host_id}/config", json=_OVERRIDE, headers=admin)
    cleared = await api_client.put(f"/api/v1/agents/{host_id}/config", json={}, headers=admin)
    assert cleared.status_code == 204
    assert (
        await api_client.get("/api/v1/agents/config", headers=FINGERPRINT_HEADER)
    ).status_code == 204
