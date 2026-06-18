"""Preview router — sandboxed derived-artifact preview (ADR-014, ADD 13 §4; STRIDE I-7).

``GET /api/v1/preview/{entry_id}`` is a **content-disclosure** route, so it carries the same
deny-by-default RBAC gate as any content: the ``PREVIEW`` capability + a server-authoritative
:class:`ScopeFilter` scope check on the *resolved* entry's ``(host_id, volume_id)`` (never a
client-supplied path — the entry is resolved from the catalogue). An out-of-scope entry is
rejected 403 (I-7); a missing entry is 404.

The render is **derived-only** (ADR-014): the sandboxed worker returns a re-encoded raster / text
snippet / structured highlight, never raw bytes. Each request is **audited before the artifact is
served** (audit-before-serve, file-mgmt §4.2) into the hash-chained audit. The route is also
default-OFF: it refuses unless ``preview_enabled`` is set AND a preview runtime is provisioned
(fail-closed, mirroring remediation). Errors are sanitised RFC-9457 problem+json — no internal
path / stack trace (ADD 07 §3).
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, update

from fathom.api.auth_deps import PrincipalDep, require
from fathom.api.deps import SessionDep, SettingsDep
from fathom.api.preview_runtime import PreviewRuntime, get_preview_runtime
from fathom.api.schemas import PreviewArtifactOut, PreviewResultOut
from fathom.auth.principal import Capability, Principal
from fathom.auth.scope import ScopeFilter
from fathom.core.audit import append_preview_access
from fathom.core.audit_store import build_persistent_chain
from fathom.core.catalogue.models import FsEntryRow, Host, Volume
from fathom.core.catalogue.preview_cache_meta import PreviewCacheMeta
from fathom.core.settings import Settings
from fathom.logging import get_logger
from fathom.preview.cache import derive_cache_key
from fathom.preview.service import ResolvedEntry
from fathom.preview.types import PreviewError, PreviewResult

_log = get_logger("fathom.api.routers.preview")

router = APIRouter(prefix="/api/v1", tags=["preview"])

# Resolve the PREVIEW capability + scope once (deny-by-default; preview = content disclosure).
PreviewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.PREVIEW))]


def _require_enabled(settings: Settings) -> None:
    """Refuse the preview route unless the server gate is on (default-OFF, fail-closed)."""
    if not settings.preview_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="preview is disabled (preview_enabled=False)",
        )


async def _resolve_entry(session: SessionDep, entry_id: int, scope: ScopeFilter) -> ResolvedEntry:
    """Resolve ``entry_id`` from the catalogue + scope-check it (server-authoritative; I-7).

    The host/volume/path/inode/content-hash come from the catalogue ``fs_entry`` row, never from
    client input. An out-of-scope entry raises 403 via ``ScopeFilter.check_target``; a missing or
    non-file entry is 404 (a directory has no previewable content). The volume's ``kind`` is
    threaded so a file on a ``kind == 'system'`` volume is 403'd for a non-system grant (AR-011):
    preview is content disclosure, so the system-volume gate applies here too.
    """
    entry = await session.get(FsEntryRow, entry_id)
    if entry is None or not entry.present or entry.is_dir:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="entry not found")
    # Scope is server-authoritative: out-of-scope host/volume → 403 (deny-by-default, I-7).
    volume = await session.get(Volume, entry.volume_id)
    volume_kind = volume.kind if volume is not None else None
    scope.check_target(host_id=entry.host_id, volume_id=entry.volume_id, volume_kind=volume_kind)
    # Refuse preview of a REMOTE-backend file (SMB/SFTP/rclone — transport='network'): its catalogue
    # path is a SYNTHETIC ``/smb|/sftp|/rclone/...`` string with a path-derived inode, so the owning
    # agent's local-disk fetch would open an unrelated local path (or 404). Remote preview would
    # need its own fetch over the remote transport (a later phase); until then it is unsupported,
    # not a half-working read against the agent's own filesystem (defence in depth, ADR-014).
    if volume is not None and volume.transport == "network":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="preview is not available for remote (SMB/SFTP/rclone) files",
        )
    # The owning host's name is the agent's poll/grant scope for the distributed pull (the local
    # fetch path ignores it). Fall back to the id as a string if the host row is somehow absent.
    host = await session.get(Host, entry.host_id)
    return ResolvedEntry(
        entry_id=entry.id,
        host_id=entry.host_id,
        volume_id=entry.volume_id,
        path=entry.path,
        inode=entry.inode,
        content_hash=entry.full_hash,
        host_name=host.name if host is not None else str(entry.host_id),
    )


async def _record_cache_meta(
    session: SessionDep,
    *,
    entry: ResolvedEntry,
    result: PreviewResult,
    artifact_size: int,
    ttl_seconds: int,
) -> None:
    """Record/update the metadata-only ``preview_cache_meta`` row (never the artifact bytes; I-8).

    On a fresh render with a content hash, upsert the row by ``cache_key`` (bumping ``hit_count``
    on a re-render). The row holds the encrypted-artifact size and expiry only — no content.
    """
    if not entry.content_hash:
        return
    cache_key = derive_cache_key(
        content_hash=entry.content_hash, render_params=f"v1:{result.type.value}"
    )
    existing = (
        await session.execute(
            select(PreviewCacheMeta).where(PreviewCacheMeta.cache_key == cache_key)
        )
    ).scalar_one_or_none()
    now = datetime.now(tz=UTC)
    if existing is not None:
        # A cache hit re-served: bump the hit counter (accounting only).
        await session.execute(
            update(PreviewCacheMeta)
            .where(PreviewCacheMeta.cache_key == cache_key)
            .values(hit_count=PreviewCacheMeta.hit_count + 1)
        )
        return
    session.add(
        PreviewCacheMeta(
            entry_id=entry.entry_id,
            content_hash=entry.content_hash,
            cache_key=cache_key,
            artifact_ref=cache_key,
            type=result.type.value,
            artifact_size=artifact_size,
            hit_count=0,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
    )


@router.get("/preview/{entry_id}", response_model=PreviewResultOut)
async def get_preview(
    entry_id: int,
    scope: PreviewScopeDep,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    request: Request,
) -> PreviewResultOut:
    """Render (or cache-hit) a single entry's DERIVED preview (PREVIEW cap + scope; audited).

    Default-OFF + RBAC scope gate + audit-before-serve are all enforced before any artifact is
    returned. The response carries derived artifacts only — never raw bytes (ADR-014).
    """
    _require_enabled(settings)
    runtime: PreviewRuntime = get_preview_runtime(request)
    entry = await _resolve_entry(session, entry_id, scope)

    job_id = f"preview-{secrets.token_hex(8)}"
    try:
        result, artifact_size = await runtime.queue.submit(
            lambda: runtime.service.render(entry, job_id=job_id)
        )
    except PreviewError as exc:
        # Sanitised problem+json: a slug only, never an internal path/IP/stack trace (ADD 07 §3).
        raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc

    # Audit-before-serve (file-mgmt §4.2): write the access record into the hash-chained audit,
    # then record the metadata-only cache row, before the artifact is returned to the client.
    audit_chain = await build_persistent_chain(session)
    role = principal.grants[0].role.value if principal.grants else "unknown"
    append_preview_access(
        audit_chain,
        actor=principal.subject,
        role=role,
        entry_id=entry.entry_id,
        preview_type=result.type.value,
        sandbox_job_id=result.sandbox_job_id,
        cache_hit=result.cache_hit,
    )
    await _record_cache_meta(
        session,
        entry=entry,
        result=result,
        artifact_size=artifact_size,
        ttl_seconds=settings.preview_cache_ttl_seconds,
    )
    await session.flush()

    return PreviewResultOut(
        entry_id=result.entry_id,
        type=result.type.value,
        cache_hit=result.cache_hit,
        sandbox_job_id=result.sandbox_job_id,
        artifacts=[
            PreviewArtifactOut(
                kind=a.kind,
                media_type=a.media_type,
                data_b64=base64.b64encode(a.data).decode("ascii"),
                meta=a.meta,
            )
            for a in result.artifacts
        ],
    )


def _principal_subject(principal: Principal) -> str:
    """Small helper kept for symmetry with the audit actor binding (principal-authoritative)."""
    return principal.subject
