"""Agent-initiated preview-grant pull routes (ADR-014; distributed preview) — mTLS agent boundary.

The distributed-preview counterpart of the remediation dispatch routes (:mod:`agent_jobs`): the
agent long-polls for a signed :class:`~fathom.preview.grant.FileGrant` the core minted for one of
ITS files, reads exactly that file, and posts the bytes back — all over the agent-**initiated**
outbound channel (no inbound agent port). Same mTLS + ``X-Client-Cert-Fingerprint`` boundary as
``/ingest`` (the caller is the verified fingerprint, never the body).

Default-OFF: when preview is not provisioned there is no pull queue, so ``poll`` returns ``204`` and
``serve`` ``409`` — the routes are inert (preview is opt-in, unlike the always-on remediation job
queue). This is the ADR-014 review surface (it carries agent file content); every grant is
Ed25519-signed, host-scoped, single-use (agent-side nonce ledger) and TTL-bounded, and the queue
refuses a serve from any host other than the grant's scope.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.deps import FingerprintDep, SessionDep, SettingsDep
from fathom.core.catalogue.models import Host
from fathom.core.db import get_sessionmaker
from fathom.logging import get_logger
from fathom.preview.pull import (
    ClaimedGrant,
    PreviewPullQueue,
    PullCorrelationError,
    ServeRequest,
)

_log = get_logger("fathom.api.routers.preview_pull")

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


def get_preview_pull_queue(request: Request) -> PreviewPullQueue | None:
    """The process-wide pull queue, or ``None`` when preview is not provisioned (default-OFF)."""
    queue = getattr(request.app.state, "preview_pull_queue", None)
    return queue if isinstance(queue, PreviewPullQueue) else None


async def _resolve_host_name(session: AsyncSession, fingerprint: str) -> str:
    """Map the verified cert fingerprint to its registered host name (else 403)."""
    name = (
        await session.execute(select(Host.name).where(Host.cert_fingerprint == fingerprint))
    ).scalar_one_or_none()
    if name is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="no registered host for this client certificate",
        )
    return name


async def _resolve_host_name_transient(fingerprint: str) -> str:
    """Resolve the host name in a short-lived session released before the long-poll wait.

    A fleet of long-polling agents must not each pin a pooled DB connection for the whole window
    (pool-exhaustion guard), so the lookup runs in its own transient session and the subsequent
    long-poll holds no connection — exactly as the remediation job poll does.
    """
    maker = get_sessionmaker()
    async with maker() as session:
        return await _resolve_host_name(session, fingerprint)


@router.post(
    "/preview-grants/poll",
    response_model=ClaimedGrant,
    responses={204: {"description": "no grant"}},
)
async def poll_preview_grant(
    fingerprint: FingerprintDep,
    request: Request,
) -> ClaimedGrant | Response:
    """Long-poll for the next signed file grant scoped to the calling host, or 204 if none."""
    queue = get_preview_pull_queue(request)
    if queue is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)  # preview off → inert
    host_name = await _resolve_host_name_transient(fingerprint)
    polled = await queue.poll(host_id=host_name)
    if polled is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    signed, max_bytes = polled
    return ClaimedGrant(signed_grant=signed, max_bytes=max_bytes)


@router.post("/preview-grants/serve", status_code=status.HTTP_200_OK)
async def serve_preview_grant(
    payload: ServeRequest,
    session: SessionDep,
    fingerprint: FingerprintDep,
    settings: SettingsDep,
    request: Request,
) -> dict[str, str]:
    """Deliver the served bytes (or a failure) for a grant, scoped to the posting host."""
    queue = get_preview_pull_queue(request)
    if queue is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="no awaiting preview pull")
    host_name = await _resolve_host_name(session, fingerprint)
    try:
        if payload.error is not None:
            queue.fail(grant_id=payload.grant_id, host_id=host_name, reason=payload.error)
        else:
            data_b64 = payload.data_b64
            if data_b64 is None:  # pragma: no cover - the model validator guarantees exactly one
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="missing serve payload"
                )
            # Reject an over-cap body BEFORE decoding it into memory: a single authenticated agent
            # must not be able to OOM the core. The configured raw cap maps to ~4/3 base64 chars; a
            # tighter parse-time ceiling (MAX_SERVE_DATA_B64_CHARS) already applied at the model.
            b64_cap = (settings.preview_max_input_bytes + 2) // 3 * 4 + 4
            if len(data_b64) > b64_cap:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="served file exceeds the preview input cap",
                )
            try:
                data = base64.b64decode(data_b64, validate=True)
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="malformed base64 payload",
                ) from exc
            if len(data) > settings.preview_max_input_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="served file exceeds the preview input cap",
                )
            queue.deliver(grant_id=payload.grant_id, host_id=host_name, data=data)
    except PullCorrelationError as exc:
        # Unknown / already-resolved / cross-host serve — a clean 409, no cross-host disclosure.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    _log.info(
        "preview grant served",
        extra={
            "grant_id": payload.grant_id,
            "host": host_name,
            "failed": payload.error is not None,
        },
    )
    return {"status": "accepted"}
