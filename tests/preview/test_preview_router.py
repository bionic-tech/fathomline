"""Preview route behaviour — all-roles-in-scope, unsupported graceful, audit, default-off, cache.

Covers the preview-worker test_plan route cases:
- every human role gets a preview within its scope (RBAC §3);
- unsupported/deferred (video/audio) and corrupt inputs return sanitised problem+json, not 500;
- a successful preview writes the access audit row BEFORE serving (file-mgmt §4.2);
- default-OFF: the route refuses unless preview_enabled (and a runtime is provisioned);
- the preview_cache_meta row holds metadata only — never artifact/raw bytes (I-8).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.audit_store import persisted_records
from fathom.core.catalogue.preview_cache_meta import PreviewCacheMeta
from tests.api.conftest import seed_principal
from tests.preview.conftest import seed_entry, wire_preview_runtime

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
_MP4 = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32  # video → deferred/unsupported


@pytest.mark.parametrize(
    "role",
    [Role.VIEWER, Role.OPERATOR, Role.REMEDIATOR, Role.AUDITOR, Role.ADMIN],
)
async def test_all_roles_allowed_within_scope(
    preview_app: FastAPI, preview_client: httpx.AsyncClient, role: Role
) -> None:
    """viewer/operator/remediator/auditor/admin all get preview within scope (RBAC §3)."""
    entry = await seed_entry(full_hash=role.value[0] * 64)
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(username=f"u-{role.value}", role=role, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["type"] == "image"


async def test_unsupported_type_graceful(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A deferred/unsupported type (video) returns a sanitised 4xx, not a 500/stack trace."""
    entry = await seed_entry(full_hash="d" * 64)
    wire_preview_runtime(preview_app, files={entry.entry_id: _MP4})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 415
    # Sanitised: the body carries a slug, not an internal path / stack trace.
    assert "/mnt/" not in resp.text
    assert "Traceback" not in resp.text


async def test_missing_entry_404(preview_app: FastAPI, preview_client: httpx.AsyncClient) -> None:
    wire_preview_runtime(preview_app, files={})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get("/api/v1/preview/999999", headers=headers)
    assert resp.status_code == 404


async def test_directory_entry_not_previewable(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A directory has no previewable content → 404 (never tries to render a dir)."""
    entry = await seed_entry(rel="adir", inode=99, is_dir=True)
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 404


async def test_preview_access_audited(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A successful preview writes a hash-chained access audit row (file-mgmt §4.2)."""
    entry = await seed_entry(full_hash="e" * 64)
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(username="auditme", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 200, resp.text
    async with db.session_scope() as session:
        records = await persisted_records(session)
    access = [r for r in records if r.action == "preview.access"]
    assert len(access) == 1
    assert access[0].actor == "auditme"
    assert access[0].target == str(entry.entry_id)
    assert access[0].before_state["type"] == "image"


async def test_cache_meta_holds_no_raw_bytes(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """The preview_cache_meta row records metadata only — never artifact/raw bytes (I-8)."""
    entry = await seed_entry(full_hash="f" * 64)
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 200, resp.text
    async with db.session_scope() as session:
        rows = (await session.execute(select(PreviewCacheMeta))).scalars().all()
    assert len(rows) == 1
    meta = rows[0]
    # The row has no column that could hold bytes — only the hash/ref/size/type/timestamps.
    column_names = {c.name for c in PreviewCacheMeta.__table__.columns}
    assert "data" not in column_names
    assert "artifact" not in column_names  # only artifact_ref / artifact_size, never the bytes
    assert meta.content_hash == "f" * 64
    assert meta.type == "image"
    assert meta.artifact_size > 0  # size of the ENCRYPTED artifact, not raw content


async def test_default_off_refuses(tmp_path: object) -> None:
    """With preview_enabled=False the route refuses (default-OFF, fail-closed)."""
    from pathlib import Path

    from asgi_lifespan import LifespanManager

    from fathom.api.app import create_app
    from fathom.core.settings import Settings

    assert isinstance(tmp_path, Path)
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'off.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        preview_enabled=False,  # default-OFF
    )
    await db.dispose_engine()
    app = create_app(settings)

    async with LifespanManager(app):
        entry = await seed_entry(full_hash="0" * 64)
        wire_preview_runtime(app, files={entry.entry_id: _PNG})
        headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
            assert resp.status_code == 403
            assert "disabled" in resp.text
    await db.dispose_engine()
