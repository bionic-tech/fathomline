"""Agent run-report endpoint + Agents-tab last-run surfacing (observability)."""

from __future__ import annotations

import httpx

from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


async def _register_host(client: httpx.AsyncClient) -> None:
    # Ingest one batch so the host row exists for the calling fingerprint (runs attach to it).
    resp = await client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200


def _run_body(*scopes: dict) -> dict:
    return {
        "started_at": "2026-06-11T02:30:00+00:00",
        "finished_at": "2026-06-11T02:41:00+00:00",
        "pushed": 42,
        "finalized": 1,
        "agent_version": "0.1.0",
        "scopes": list(scopes),
    }


async def test_report_run_requires_fingerprint(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post("/api/v1/agents/runs", json=_run_body())
    assert resp.status_code == 401


async def test_report_run_derives_partial_outcome(api_client: httpx.AsyncClient) -> None:
    await _register_host(api_client)
    resp = await api_client.post(
        "/api/v1/agents/runs",
        json=_run_body(
            {"root": "/mnt/pool/a", "entries_seen": 100, "rows_changed": 5, "error": None},
            {"root": "/mnt/pool/b", "entries_seen": 0, "rows_changed": 0, "error": "EACCES"},
        ),
        headers=FINGERPRINT_HEADER,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "partial" and body["run_id"] > 0  # server-derived, not agent-asserted


async def test_report_run_unknown_fingerprint_is_noop(api_client: httpx.AsyncClient) -> None:
    # A fingerprint that never ingested has no host row → recorded as a no-op, never an error,
    # so run-reporting can't destabilise a scan.
    resp = await api_client.post(
        "/api/v1/agents/runs",
        json=_run_body({"root": "/x", "entries_seen": 1, "rows_changed": 0, "error": None}),
        headers={"X-Client-Cert-Fingerprint": "zz:zz:never:seen"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"run_id": 0, "host_id": 0, "outcome": "unknown_host"}


async def test_agents_tab_shows_last_run(api_client: httpx.AsyncClient) -> None:
    await _register_host(api_client)
    await api_client.post(
        "/api/v1/agents/runs",
        json=_run_body(
            {"root": "/mnt/pool/a", "entries_seen": 100, "rows_changed": 5, "error": None},
            {"root": "/mnt/pool/b", "entries_seen": 0, "rows_changed": 0, "error": "EACCES"},
        ),
        headers=FINGERPRINT_HEADER,
    )
    auth = await seed_principal()
    agents = await api_client.get("/api/v1/agents", headers=auth)
    assert agents.status_code == 200
    host = agents.json()[0]
    assert host["last_run_outcome"] == "partial"
    assert host["last_run_entries_seen"] == 100
    assert host["last_run_scopes_failed"] == 1
    assert host["last_run_finished_at"] is not None
