"""Preview route behaviour — all-roles-in-scope, unsupported graceful, audit, default-off, cache.

Covers the preview-worker test_plan route cases:
- every human role gets a preview within its scope (RBAC §3);
- unsupported/deferred (video/audio) and corrupt inputs return sanitised problem+json, not 500;
- a successful preview writes the access audit row BEFORE serving (file-mgmt §4.2);
- default-OFF: the route refuses unless preview_enabled (and a runtime is provisioned);
- the preview_cache_meta row holds metadata only — never artifact/raw bytes (I-8).
"""

from __future__ import annotations

import base64

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from fathom.api.preview_runtime import PreviewRuntime
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.audit_store import persisted_records
from fathom.core.catalogue.models import Volume
from fathom.core.catalogue.preview_cache_meta import PreviewCacheMeta
from fathom.workers.preview import PreviewQueue
from tests.api.conftest import seed_principal
from tests.preview.conftest import make_service, seed_entry, wire_preview_runtime

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
_MP4 = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32  # video → deferred/unsupported
_TEXT = b"the quick brown fox jumps over the lazy dog\n" * 4  # inert text (no NUL, printable)


async def test_happy_path_returns_derived_image_artifact(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """The render happy path: request → queue → fake-sandbox → DERIVED artifact, end-to-end.

    The role/audit tests above assert only status + ``type``; this pins that the derived artifact
    *itself* round-trips through the queue + service + route serialisation — the render happy path
    that otherwise needs the gVisor (runsc) sandbox, here exercised with the fake driver. It also
    proves the bytes are DERIVED (a re-encoded marker), never the raw PNG passed through (ADR-014).
    """
    entry = await seed_entry(full_hash="1a" * 32)
    driver, _cache = wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")

    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["type"] == "image"
    assert body["cache_hit"] is False
    assert body["sandbox_job_id"].startswith("preview-")  # the per-render id the route minted
    # Exactly one DERIVED artifact came back through the full pipeline.
    assert len(body["artifacts"]) == 1
    artifact = body["artifacts"][0]
    assert artifact["kind"] == "thumbnail"
    assert artifact["media_type"] == "image/webp"
    assert artifact["meta"] == {"derived": True}
    derived = base64.b64decode(artifact["data_b64"])
    assert derived == f"derived:image:{len(_PNG)}".encode()  # the fake sandbox's derived marker
    assert derived != _PNG  # never the raw original bytes (ADR-014)
    # The fake sandbox driver actually ran once on the fetched bytes (a real render, not a hit).
    assert driver.seen == [(len(_PNG), "image")]


async def test_happy_path_text_returns_text_snippet_artifact(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A text file renders to a derived ``text_snippet`` artifact through the full route chain.

    Exercises the other artifact-kind branch of the render happy path (text → text/plain snippet),
    complementing the image case, so the route's artifact serialisation is covered for both kinds.
    """
    entry = await seed_entry(rel="notes.txt", inode=7, full_hash="2b" * 32)
    driver, _cache = wire_preview_runtime(preview_app, files={entry.entry_id: _TEXT})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")

    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["type"] == "text"
    assert len(body["artifacts"]) == 1
    artifact = body["artifacts"][0]
    assert artifact["kind"] == "text_snippet"
    assert artifact["media_type"] == "text/plain"
    assert base64.b64decode(artifact["data_b64"]) == f"derived:text:{len(_TEXT)}".encode()
    assert driver.seen == [(len(_TEXT), "text")]


async def test_second_request_is_cache_hit_and_skips_render(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A repeat preview of the same content is served from cache; the sandbox is not re-run.

    Covers the route-level cache short-circuit end-to-end: the first request renders (the fake
    sandbox runs once), the second returns ``cache_hit=True`` with the SAME derived bytes and no
    second render. Requires a content hash so the cache key is derivable (I-8).
    """
    entry = await seed_entry(full_hash="3c" * 32)
    driver, _cache = wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")

    first = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    second = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)

    assert first.status_code == 200 and second.status_code == 200, second.text
    assert first.json()["cache_hit"] is False
    assert second.json()["cache_hit"] is True  # served from the encrypted cache, not re-rendered
    assert len(driver.seen) == 1  # the fake sandbox ran exactly once across both requests
    # The same derived artifact bytes came back both times (the cache returned the stored artifact).
    assert first.json()["artifacts"][0]["data_b64"] == second.json()["artifacts"][0]["data_b64"]


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


async def test_oversized_input_413(preview_app: FastAPI, preview_client: httpx.AsyncClient) -> None:
    """A fetched file larger than the preview input cap is refused 413 (EC-PREVIEW-4).

    The route wires a runtime whose service has a tiny ``max_input_bytes``; the fetcher returns
    more bytes than that, so :class:`PreviewService.render` raises a 413-class ``PreviewError`` that
    the route maps to a sanitised problem+json — the oversized blob never reaches the sandbox.
    """
    entry = await seed_entry(full_hash="a1" * 32)
    # A bespoke runtime: 16-byte input cap, fetcher returns 4 KiB → over the cap.
    service, _drv, _cch = make_service(
        files={entry.entry_id: _PNG + b"\x00" * 4096}, max_input_bytes=16
    )
    preview_app.state.preview_runtime = PreviewRuntime(service=service, queue=PreviewQueue())
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 413, resp.text
    assert "/mnt/" not in resp.text and "Traceback" not in resp.text  # sanitised


async def test_remote_backend_file_415(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """A file on a network-transport volume (SMB/SFTP/rclone) is 415 'not available for remote'.

    Its catalogue path is a synthetic ``/smb|/sftp|/rclone/...`` string, so the owning agent's
    local-disk fetch would open an unrelated path. The route refuses remote preview up front rather
    than half-reading the agent's own filesystem (EC-PREVIEW-13; defence in depth).
    """
    entry = await seed_entry(full_hash="b2" * 32)
    # Flip the seeded volume to the remote (network) transport.
    async with db.session_scope() as session:
        volume = await session.get(Volume, entry.volume_id)
        assert volume is not None
        volume.transport = "network"
    wire_preview_runtime(preview_app, files={entry.entry_id: _PNG})
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 415, resp.text
    assert "remote" in resp.text.lower()  # distinct from the unsupported-type 415


async def test_enabled_but_no_runtime_503(
    preview_app: FastAPI, preview_client: httpx.AsyncClient
) -> None:
    """preview_enabled=True but no runtime provisioned → 503 'not provisioned' (EC-PREVIEW-12).

    Distinct from preview_enabled=False (which is a deliberate 403, see test_default_off_refuses):
    the gate is on but the sandbox driver/cache were never wired, so the route is fail-closed 503
    rather than silently degrading. The ``preview_app`` fixture wires no runtime by default.
    """
    entry = await seed_entry(full_hash="c3" * 32)  # no wire_preview_runtime → app.state has none
    headers = await seed_principal(username="viewer", role=Role.VIEWER, scope_kind="global")
    resp = await preview_client.get(f"/api/v1/preview/{entry.entry_id}", headers=headers)
    assert resp.status_code == 503, resp.text
    assert "provisioned" in resp.text.lower()


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
