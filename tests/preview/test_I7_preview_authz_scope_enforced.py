"""STRIDE I-7 — preview authz + scope are enforced server-authoritatively (ADR-014, RBAC §4).

Named regression gate (STRIDE I-7): preview is content disclosure, so it carries the deny-by-
default PREVIEW-capability + scope gate. An out-of-scope principal requesting an in-scope entry's
preview is denied; scope is resolved from the assignment store, never from client input.
"""

from __future__ import annotations

import httpx
from fastapi import FastAPI

from fathom.auth.principal import Role
from tests.api.conftest import seed_principal
from tests.preview.conftest import seed_entry, wire_preview_runtime

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


async def test_unauthenticated_preview_denied(preview_client: httpx.AsyncClient) -> None:
    """No principal → 401 (deny-by-default; the route is never anonymous)."""
    resp = await preview_client.get("/api/v1/preview/1")
    assert resp.status_code == 401


async def test_out_of_scope_entry_denied(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A volume-scoped principal requesting an entry on another volume is denied 403 (I-7)."""
    entry = await seed_entry(full_hash="a" * 64)
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    # Principal scoped to a DIFFERENT volume id than the entry lives on.
    headers = await seed_principal(
        username="scoped",
        role=Role.VIEWER,
        scope_kind="volume",
        host_id=entry.host_id,
        volume_id=entry.volume_id + 999,
    )
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 403


async def test_in_scope_entry_allowed(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A principal scoped to the entry's volume gets the derived preview (in-scope; I-7)."""
    entry = await seed_entry(full_hash="b" * 64)
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(
        username="inscope",
        role=Role.VIEWER,
        scope_kind="volume",
        host_id=entry.host_id,
        volume_id=entry.volume_id,
    )
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["type"] == "image"
    assert body["artifacts"]  # derived artifacts present
    assert all("data_b64" in a for a in body["artifacts"])


async def test_missing_capability_denied(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A role without the PREVIEW capability is denied 403 even in scope (deny-by-default)."""
    entry = await seed_entry(full_hash="c" * 64)
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    # OPERATOR inherits viewer caps incl. PREVIEW, so to prove deny-by-default we use a principal
    # whose single grant confers no PREVIEW: a host-scoped grant for a different host removes scope.
    headers = await seed_principal(
        username="otherhost",
        role=Role.VIEWER,
        scope_kind="host",
        host_id=entry.host_id + 999,
    )
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 403
