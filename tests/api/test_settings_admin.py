"""Runtime settings admin route tests (ADR-038) — RBAC, validation, live reload, secret gating.

The security-relevant bits: every route is admin-only (MANAGE_SETTINGS); the secret routes (reveal
+ set/clear named secret) additionally require fresh step-up MFA; an out-of-range value is a 422;
secrets are masked in the list and only returned by the explicit reveal; and a setting changed here
takes effect on the very next request (live reload) — proven via the read-only /config view.
"""

from __future__ import annotations

import httpx
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal


async def test_requires_auth(api_client: httpx.AsyncClient) -> None:
    assert (await api_client.get("/api/v1/settings")).status_code == 401


async def test_non_admin_forbidden(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.OPERATOR)
    assert (await api_client.get("/api/v1/settings", headers=auth)).status_code == 403


async def test_admin_lists_settings(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN)
    resp = await api_client.get("/api/v1/settings", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    keys = {s["key"] for s in body["settings"]}
    assert "concierge_enabled" in keys
    assert "ingest_proxy_secret" in keys
    assert body["version"] == 0  # no overrides yet
    # The secret setting is masked in the list.
    secret = next(s for s in body["settings"] if s["key"] == "ingest_proxy_secret")
    assert secret["is_secret"] is True
    assert secret["value"] is None


async def test_set_setting_is_live_without_restart(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN)
    # /config reflects the effective concierge_enabled (read via SettingsDep).
    before = await api_client.get("/api/v1/config", headers=auth)
    assert before.json()["concierge_enabled"] is False
    put = await api_client.put(
        "/api/v1/settings/concierge_enabled", json={"value": True}, headers=auth
    )
    assert put.status_code == 200
    assert put.json()["overridden"] is True
    # Same app, next request: the overlay already won — no restart.
    after = await api_client.get("/api/v1/config", headers=auth)
    assert after.json()["concierge_enabled"] is True


async def test_clear_setting_resets(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN)
    await api_client.put("/api/v1/settings/concierge_enabled", json={"value": True}, headers=auth)
    assert (await api_client.get("/api/v1/config", headers=auth)).json()["concierge_enabled"]
    cleared = await api_client.delete("/api/v1/settings/concierge_enabled", headers=auth)
    assert cleared.status_code == 200
    assert (
        await api_client.get("/api/v1/config", headers=auth)
    ).json()["concierge_enabled"] is False
    # Clearing again with no override → 404.
    assert (
        await api_client.delete("/api/v1/settings/concierge_enabled", headers=auth)
    ).status_code == 404


async def test_invalid_value_is_422(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN)
    resp = await api_client.put(
        "/api/v1/settings/treemap_max_nodes", json={"value": 999999}, headers=auth
    )
    assert resp.status_code == 422


async def test_non_editable_key_is_422(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN)
    resp = await api_client.put(
        "/api/v1/settings/database_url", json={"value": "sqlite://"}, headers=auth
    )
    assert resp.status_code == 422


async def test_secret_routes_require_step_up_mfa(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN, mfa_fresh=False)
    # Set a named secret without fresh MFA → 401.
    resp = await api_client.put(
        "/api/v1/settings/secrets", json={"ref": "ANTHROPIC_KEY", "value": "sk"}, headers=auth
    )
    assert resp.status_code == 401


async def test_egress_endpoint_change_requires_step_up_mfa(api_client: httpx.AsyncClient) -> None:
    # Changing WHERE a credential is sent (an inference/SMTP endpoint) needs fresh step-up MFA, the
    # same gate as revealing a secret: otherwise a non-fresh admin (e.g. a stolen cookie) could
    # repoint the API key off-host and exfiltrate it (security review).
    stale = await seed_principal(role=Role.ADMIN, mfa_fresh=False)
    redirect = await api_client.put(
        "/api/v1/settings/inference_anthropic_url",
        json={"value": "https://collector.attacker.example"},
        headers=stale,
    )
    assert redirect.status_code == 401
    assert "step-up MFA" in redirect.json()["detail"]

    # A non-egress setting is unaffected — still MANAGE_SETTINGS-only, no MFA challenge.
    benign = await api_client.put(
        "/api/v1/settings/concierge_enabled", json={"value": True}, headers=stale
    )
    assert benign.status_code == 200

    # With fresh step-up MFA the egress change is allowed.
    fresh = await seed_principal(username="freshadmin", role=Role.ADMIN, mfa_fresh=True)
    allowed = await api_client.put(
        "/api/v1/settings/inference_anthropic_url",
        json={"value": "https://api.anthropic.com"},
        headers=fresh,
    )
    assert allowed.status_code == 200


async def test_named_secret_set_reveal_and_mask(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    put = await api_client.put(
        "/api/v1/settings/secrets",
        json={"ref": "ANTHROPIC_KEY", "value": "sk-ant-xyz"},
        headers=auth,
    )
    assert put.status_code == 200
    # Listed by name only (never value).
    listing = (await api_client.get("/api/v1/settings", headers=auth)).json()
    assert "ANTHROPIC_KEY" in listing["named_secrets"]
    # Reveal returns the plaintext (admin + fresh MFA).
    rev = await api_client.post("/api/v1/settings/ANTHROPIC_KEY/reveal", headers=auth)
    assert rev.status_code == 200
    assert rev.json()["value"] == "sk-ant-xyz"
    # Clear it.
    assert (
        await api_client.delete("/api/v1/settings/secrets/ANTHROPIC_KEY", headers=auth)
    ).status_code == 200


async def test_reveal_requires_step_up(api_client: httpx.AsyncClient) -> None:
    # Set the secret WITH fresh MFA, then attempt to reveal WITHOUT it (a distinct principal).
    armed = await seed_principal(username="armed", role=Role.ADMIN, mfa_fresh=True)
    await api_client.put(
        "/api/v1/settings/secrets", json={"ref": "K", "value": "v"}, headers=armed
    )
    stale = await seed_principal(username="stale", role=Role.ADMIN, mfa_fresh=False)
    assert (await api_client.post("/api/v1/settings/K/reveal", headers=stale)).status_code == 401


async def test_reveal_unknown_secret_is_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    assert (
        await api_client.post("/api/v1/settings/nope/reveal", headers=auth)
    ).status_code == 404


async def test_in_app_secret_feeds_inference_key_resolution(
    api_client: httpx.AsyncClient,
) -> None:
    # Configure the concierge to use Anthropic with egress + a key-by-reference, supply the key
    # in-app, and assert the concierge no longer 503s on a missing key (the store resolved it).
    # We stop short of a live call; reaching the provider build proves the secret chain works.
    auth = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    for key, value in [
        ("concierge_enabled", True),
        ("inference_provider", "anthropic"),
        ("inference_allow_egress", True),
        ("inference_anthropic_key_ref", "ANTHROPIC_KEY"),
    ]:
        r = await api_client.put(f"/api/v1/settings/{key}", json={"value": value}, headers=auth)
        assert r.status_code == 200, (key, r.text)
    # Without the secret, the concierge would 503 "key reference did not resolve". Add it in-app.
    await api_client.put(
        "/api/v1/settings/secrets",
        json={"ref": "ANTHROPIC_KEY", "value": "sk-ant-live"},
        headers=auth,
    )
    resp = await api_client.post(
        "/api/v1/concierge/ask", json={"question": "how full are my disks?"}, headers=auth
    )
    # The provider was built (key resolved from the store); the call then fails trying to reach
    # the real Anthropic endpoint — NOT a 503 "no key" from the factory. Either a network/timeout
    # mapped error or a non-503 is acceptable; what must NOT happen is the missing-key 503.
    assert resp.status_code != 200  # no live Anthropic in tests
    if resp.status_code == 503:
        assert "did not resolve" not in resp.text and "no API key" not in resp.text


async def test_delete_secret_ref_that_is_a_settings_field_is_400(
    api_client: httpx.AsyncClient,
) -> None:
    # DELETE /settings/secrets/{ref} clears a FREE-FORM named secret; a Settings field name is not
    # one → 400 "not a named secret" (use the setting endpoint), never a 404. (EC-settings-8)
    admin = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await api_client.delete(
        "/api/v1/settings/secrets/concierge_enabled", headers=admin
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "not a named secret"


async def test_reveal_non_secret_key_is_404(api_client: httpx.AsyncClient) -> None:
    # Revealing a key that is SET but is not a secret (a plain override) is a 404 — the reveal path
    # only ever returns stored secrets. (EC-settings-9)
    admin = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    put = await api_client.put(
        "/api/v1/settings/treemap_max_nodes", json={"value": 321}, headers=admin
    )
    assert put.status_code == 200
    resp = await api_client.post(
        "/api/v1/settings/treemap_max_nodes/reveal", headers=admin
    )
    assert resp.status_code == 404


async def test_delete_absent_named_secret_is_404(api_client: httpx.AsyncClient) -> None:
    # Clearing a named secret that was never stored is a 404 "no such secret". (EC-settings-9)
    admin = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await api_client.delete("/api/v1/settings/secrets/NEVER_SET", headers=admin)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "no such secret"


async def test_settings_store_unavailable_is_503(tmp_path: object) -> None:
    # The routes are inert (503) if the runtime settings store somehow isn't installed on
    # app.state. Build an app and null the store after startup to simulate that. (EC-settings-12)
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/cat.db",  # type: ignore[attr-defined]
        auto_create_schema=True,
        session_cookie_secure=False,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        app.state.settings_store = None  # the store is unavailable
        asgi = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=asgi, base_url="http://test") as client:
            admin = await seed_principal(role=Role.ADMIN)
            resp = await client.get("/api/v1/settings", headers=admin)
            assert resp.status_code == 503
            assert resp.json()["detail"] == "runtime settings store is not available"
    await db.dispose_engine()
