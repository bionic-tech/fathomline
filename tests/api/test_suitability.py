"""Suitability API tests (ADR-037) — facts persist via ingest, the engine drives the response.

Drives the real path: an agent ingest carries ``host.facts``, the server persists them onto
``host.facts``, and ``GET /api/v1/suitability`` returns the per-host traffic-lights + a pick.
Also covers auth and that the cloud-egress flag tracks the effective settings.
"""

from __future__ import annotations

import httpx
from sqlalchemy import select

from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.catalogue.models import Host
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal

_GIB = 1024**3


async def _ingest_host_with_facts(client: httpx.AsyncClient, facts: dict | None) -> None:
    host: dict = {"name": "nas-1", "os": "TrueNAS", "agent_version": "0.2.0"}
    if facts is not None:
        host["facts"] = facts
    resp = await client.post(
        "/api/v1/agents/ingest", json=batch(host=host), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200, resp.text


async def test_requires_auth(api_client: httpx.AsyncClient) -> None:
    assert (await api_client.get("/api/v1/suitability")).status_code == 401


async def test_reports_traffic_lights_from_reported_facts(api_client: httpx.AsyncClient) -> None:
    await _ingest_host_with_facts(
        api_client, {"cpu_cores": 16, "ram_bytes": 64 * _GIB, "gpu_vram_bytes": 16 * _GIB}
    )
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/suitability", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    host = next(h for h in body["hosts"] if h["name"] == "nas-1")
    assert host["facts_known"] is True
    assert host["facts"]["ram_bytes"] == 64 * _GIB
    ratings = {o["key"]: o["rating"] for o in host["options"]}
    assert ratings["local_chat_large"] == "green"  # 16 GB VRAM
    assert host["recommended_chat_provider"] == "ollama"


async def test_unknown_facts_when_agent_did_not_report(api_client: httpx.AsyncClient) -> None:
    await _ingest_host_with_facts(api_client, None)
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/suitability", headers=auth)
    host = next(h for h in resp.json()["hosts"] if h["name"] == "nas-1")
    assert host["facts_known"] is False
    assert host["facts"] is None


async def test_egress_flag_reflected(api_client: httpx.AsyncClient) -> None:
    await _ingest_host_with_facts(api_client, {"ram_bytes": 2 * _GIB})
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/suitability", headers=auth)
    body = resp.json()
    # Default settings keep egress off, so a tiny box recommends local (no cloud option taken).
    assert body["egress_allowed"] is False


async def test_suitability_lists_only_in_scope_hosts(api_client: httpx.AsyncClient) -> None:
    # Two hosts in the estate; a host-scoped viewer must see only its own host's assessment
    # (the list is scope-filtered server-side, ADD 13 §4) — never another host's facts.
    await _ingest_host_with_facts(api_client, {"ram_bytes": 8 * _GIB})  # nas-1 (ab:cd:ef:01)
    resp2 = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(
            host={"name": "nas-2", "os": "TrueNAS", "agent_version": "0.2.0"},
            mountpoint="/mnt/pool2",
        ),
        headers={"X-Client-Cert-Fingerprint": "99:88:77:66"},
    )
    assert resp2.status_code == 200, resp2.text

    async with db.session_scope() as s:
        nas1_id = (await s.execute(select(Host.id).where(Host.name == "nas-1"))).scalar_one()
    scoped = await seed_principal(
        username="h1only", role=Role.VIEWER, scope_kind="host", host_id=nas1_id
    )
    resp = await api_client.get("/api/v1/suitability", headers=scoped)
    assert resp.status_code == 200
    names = {h["name"] for h in resp.json()["hosts"]}
    assert names == {"nas-1"}  # nas-2 is out of scope → excluded


async def test_wizard_settings_keys_are_accepted(api_client: httpx.AsyncClient) -> None:
    # The onboarding wizard applies its picks through the runtime settings store; drive its exact
    # keys (provider / model / egress / concierge) and confirm each is accepted, then that the
    # egress flag tracks live into the suitability surface. inference_allow_egress is egress-
    # sensitive → it needs fresh step-up MFA, so the wizard admin is mfa_fresh. (EC-onboarding-9)
    admin = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    for key, value in [
        ("inference_provider", "anthropic"),
        ("inference_model", "claude-haiku-4-5"),
        ("inference_allow_egress", True),
        ("concierge_enabled", True),
    ]:
        r = await api_client.put(
            f"/api/v1/settings/{key}", json={"value": value}, headers=admin
        )
        assert r.status_code == 200, (key, r.text)
        assert r.json()["overridden"] is True
    # The suitability surface reads the effective settings per request → egress now allowed.
    resp = await api_client.get("/api/v1/suitability", headers=admin)
    assert resp.status_code == 200
    assert resp.json()["egress_allowed"] is True
