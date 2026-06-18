"""Live directory browse routes (ADR-034 Phase 2).

Two boundaries, like the preview pull (:mod:`preview_pull`):

* **Agent-facing** (mTLS + ``X-Client-Cert-Fingerprint``): the agent long-polls
  ``/agents/browse/poll`` for a signed :class:`~fathom.core.browse.BrowseRequest` scoped to its
  host, lists exactly one directory (metadata only), and posts the :class:`~fathom.core.browse.
  BrowseResult` to ``/agents/browse/result``. Inert (204/409) until the browse runtime is wired.
* **Operator-facing** (``MANAGE_AGENTS`` + a **per-request** step-up MFA, scope-checked, audited):
  ``/agents/{host_id}/browse`` signs a short-TTL ``BrowseRequest`` for the host, enqueues it, and
  returns the listing the agent serves back (or 504 if the agent does not answer in the TTL).

Browse is **read-only** — it never reads file contents and never arms the write path.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.auth_deps import PrincipalDep, require_step_up_mfa
from fathom.api.deps import FingerprintDep, SessionDep
from fathom.api.routers.agents import ManageScopeDep, _host_scope_predicate
from fathom.core.audit_store import build_persistent_chain
from fathom.core.browse import (
    BrowseCorrelationError,
    BrowsePullError,
    BrowsePullQueue,
    BrowseRequest,
    BrowseResult,
    BrowseSigner,
    ClaimedBrowse,
)
from fathom.core.catalogue.models import Host
from fathom.core.db import get_sessionmaker
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.api.routers.agent_browse")

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


class BrowsePathIn(BaseModel):
    """Operator request body: the absolute directory to list on the target host."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=4096)


def _queue(request: Request) -> BrowsePullQueue | None:
    queue = getattr(request.app.state, "browse_pull_queue", None)
    return queue if isinstance(queue, BrowsePullQueue) else None


def _signer(request: Request) -> BrowseSigner | None:
    signer = getattr(request.app.state, "browse_signer", None)
    return signer if isinstance(signer, BrowseSigner) else None


async def _resolve_host_name(session: AsyncSession, fingerprint: str) -> str:
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
    """Resolve the host name in a short-lived session released before the long-poll wait."""
    maker = get_sessionmaker()
    async with maker() as session:
        return await _resolve_host_name(session, fingerprint)


@router.post(
    "/browse/poll",
    response_model=ClaimedBrowse,
    responses={204: {"description": "no browse request"}},
)
async def poll_browse(fingerprint: FingerprintDep, request: Request) -> ClaimedBrowse | Response:
    """Agent long-poll for the next signed browse request scoped to the calling host, or 204."""
    queue = _queue(request)
    if queue is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)  # browse off → inert
    host_name = await _resolve_host_name_transient(fingerprint)
    signed = await queue.poll(host_id=host_name)
    if signed is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return ClaimedBrowse(signed_request=signed)


@router.post("/browse/result", status_code=status.HTTP_200_OK)
async def serve_browse_result(
    payload: BrowseResult,
    session: SessionDep,
    fingerprint: FingerprintDep,
    request: Request,
) -> dict[str, str]:
    """Deliver the directory listing (or error) for a browse request, scoped to the posting host."""
    queue = _queue(request)
    if queue is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="no awaiting browse request"
        )
    host_name = await _resolve_host_name(session, fingerprint)
    try:
        queue.deliver(host_id=host_name, result=payload)
    except BrowseCorrelationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"status": "accepted"}


@router.post("/{host_id}/browse", response_model=BrowseResult)
async def browse_host_directory(
    host_id: int,
    body: BrowsePathIn,
    session: SessionDep,
    scope: ManageScopeDep,
    principal: PrincipalDep,
    request: Request,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
) -> BrowseResult:
    """Operator: list a directory on ``host_id`` live (MANAGE_AGENTS + per-request step-up MFA).

    Signs a short-TTL, single-use, host-scoped :class:`BrowseRequest`, enqueues it for the owning
    agent, and returns the metadata listing the agent serves back. Read-only; audited. 503 when the
    browse runtime is not provisioned; 504 when the agent does not answer within the request TTL.
    """
    queue = _queue(request)
    signer = _signer(request)
    if queue is None or signer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="live browse is not enabled on this core",
        )
    stmt = select(Host).where(Host.id == host_id)
    if not scope.is_global:
        stmt = stmt.where(_host_scope_predicate(scope))
    host = (await session.execute(stmt)).scalar_one_or_none()
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="host not found or out of scope"
        )
    settings: Settings = request.app.state.settings
    ttl = settings.browse_request_ttl_seconds
    issued = datetime.now(tz=UTC)
    signed = signer.sign(
        BrowseRequest(
            request_id=secrets.token_hex(16),
            host_id=host.name,  # the agent verifies against its own config host_id (= its name)
            path=body.path,
            nonce=secrets.token_hex(16),
            issued_at=issued,
            expires_at=issued + timedelta(seconds=ttl),
        )
    )
    chain = await build_persistent_chain(session)
    chain.append(
        actor=principal.subject,
        action="browse_host_directory",
        target=f"{host.name}:{body.path}",
        before_state={},  # a read action — no prior state to capture
        result="requested",
    )
    await session.flush()
    try:
        return await queue.enqueue_and_wait(signed, host_id=host.name, timeout_seconds=float(ttl))
    except BrowsePullError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="the agent did not return the listing in time (offline or slow)",
        ) from exc
    except BrowseCorrelationError as exc:  # pragma: no cover - duplicate request_id (collision)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
