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


async def test_override_unknown_host_is_404(api_client: httpx.AsyncClient) -> None:
    # A global operator targeting a host_id that does not exist gets a clean 404 (EC-config-2),
    # never a 500 or a silently-created override row.
    admin = await seed_principal(role=Role.ADMIN)
    r = await api_client.put("/api/v1/agents/999999/config", json=_OVERRIDE, headers=admin)
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


async def test_override_out_of_scope_host_is_404(api_client: httpx.AsyncClient) -> None:
    # A host-scoped operator (MANAGE_AGENTS, but only over a DIFFERENT host) cannot target a host
    # outside its scope: the scope predicate filters it out and it reads as 404, not 403 — the
    # route never confirms the existence of a host the principal can't manage (EC-config-2).
    host_id = await _seed_host(api_client)
    scoped_admin = await seed_principal(
        role=Role.ADMIN, scope_kind="host", host_id=host_id + 1000
    )
    r = await api_client.put(
        f"/api/v1/agents/{host_id}/config", json=_OVERRIDE, headers=scoped_admin
    )
    assert r.status_code == 404


async def test_empty_override_clears_it(api_client: httpx.AsyncClient) -> None:
    host_id = await _seed_host(api_client)
    admin = await seed_principal(role=Role.ADMIN)
    await api_client.put(f"/api/v1/agents/{host_id}/config", json=_OVERRIDE, headers=admin)
    cleared = await api_client.put(f"/api/v1/agents/{host_id}/config", json={}, headers=admin)
    assert cleared.status_code == 204
    assert (
        await api_client.get("/api/v1/agents/config", headers=FINGERPRINT_HEADER)
    ).status_code == 204
