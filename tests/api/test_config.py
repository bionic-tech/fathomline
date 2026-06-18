"""Server-config read surface tests (read-only feature flags; secret-free)."""

from __future__ import annotations

import httpx

from tests.api.conftest import seed_principal


async def test_config_requires_auth(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.get("/api/v1/config")
    assert resp.status_code == 401  # deny-by-default


async def test_config_returns_flags_no_secrets(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(username="cfg")
    resp = await api_client.get("/api/v1/config", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    # The feature flags are present...
    assert body["organize_enabled"] is False
    assert body["remediation_enabled"] is False
    assert "inference_ollama_url" in body
    assert "organize_model" in body
    # ...and nothing secret-looking ever leaks.
    blob = " ".join(str(k) for k in body).lower()
    for forbidden in ("secret", "password", "key", "token", "database_url", "db_password"):
        assert forbidden not in blob
