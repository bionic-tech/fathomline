"""First-run onboarding flag (Build P4).

``onboarding_completed`` is an editable, non-secret estate-wide bool: exposed (read-only) in
``/config`` for the SPA's first-run gate, and toggled through the settings store (admin-only, live
without a restart). Finishing the setup wizard sets it True; the Settings "run again" control sets
it back to False to re-arm the first-run modal for the next admin login.
"""

from __future__ import annotations

import httpx

from fathom.auth.principal import Role
from tests.api.conftest import seed_principal


async def test_config_exposes_onboarding_completed_default_false(
    api_client: httpx.AsyncClient,
) -> None:
    auth = await seed_principal(username="cfg-ob")
    resp = await api_client.get("/api/v1/config", headers=auth)
    assert resp.status_code == 200
    assert resp.json()["onboarding_completed"] is False


async def test_onboarding_completed_is_editable_non_secret_setting(
    api_client: httpx.AsyncClient,
) -> None:
    auth = await seed_principal(role=Role.ADMIN)
    body = (await api_client.get("/api/v1/settings", headers=auth)).json()
    setting = next(s for s in body["settings"] if s["key"] == "onboarding_completed")
    assert setting["editable"] is True
    assert setting["is_secret"] is False


async def test_admin_can_complete_then_rearm_onboarding_live(
    api_client: httpx.AsyncClient,
) -> None:
    auth = await seed_principal(role=Role.ADMIN)
    # Finishing the wizard sets it True; /config reflects it on the very next request (live reload).
    put = await api_client.put(
        "/api/v1/settings/onboarding_completed", json={"value": True}, headers=auth
    )
    assert put.status_code == 200
    assert put.json()["overridden"] is True
    after = await api_client.get("/api/v1/config", headers=auth)
    assert after.json()["onboarding_completed"] is True
    # Re-arming (the Settings "run again" control) flips it back to False.
    rearm = await api_client.put(
        "/api/v1/settings/onboarding_completed", json={"value": False}, headers=auth
    )
    assert rearm.status_code == 200
    rearmed = await api_client.get("/api/v1/config", headers=auth)
    assert rearmed.json()["onboarding_completed"] is False


async def test_non_admin_cannot_set_onboarding_completed(
    api_client: httpx.AsyncClient,
) -> None:
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.put(
        "/api/v1/settings/onboarding_completed", json={"value": True}, headers=auth
    )
    assert resp.status_code == 403
