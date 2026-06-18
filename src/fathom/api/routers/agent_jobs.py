"""Agent-initiated signed-job dispatch routes (ADR-025 §1) — on the mTLS agent boundary.

These are the two endpoints that carry remediation jobs to a fleet agent over the *agent-initiated
outbound* channel (the agent long-polls; core never connects to the agent — no inbound port on any
host). They are mounted on the **same** mTLS + ``X-Client-Cert-Fingerprint`` boundary as ``/ingest``
(``FingerprintDep``), NOT the human-auth path: the caller is the verified cert fingerprint, never
the body.

* ``POST /api/v1/agents/jobs/poll`` — long-poll: core resolves the caller's fingerprint to its
  :class:`~fathom.core.catalogue.models.Host`, returns the next pending signed job *for that host*
  (scoped by ``Host.name`` — a host only ever drains its own queue), or ``204`` after a bounded
  long-poll so the agent re-polls.
* ``POST /api/v1/agents/jobs/{job_id}/result`` — the agent posts the :class:`JobResultPayload`.
  Core correlates by ``job_id`` (rejecting a result the posting host was never issued), consumes
  the job's single-use nonce on the **durable** ``used_nonce`` ledger (a replayed result is
  rejected even across a restart), then resolves the awaiting dispatch.

Default-OFF: when no jobs are ever enqueued (remediation disabled / no runtime), poll always
returns ``204`` and a result for an unknown job is a clean ``409`` — the routes are inert.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from fathom.api.deps import FingerprintDep, SessionDep
from fathom.core.catalogue.models import Host
from fathom.core.db import get_sessionmaker
from fathom.core.remediation.job_queue import (
    ClaimedJob,
    JobCorrelationError,
    JobQueue,
    JobResultPayload,
)
from fathom.core.remediation.nonce_store import DbNonceStore
from fathom.logging import get_logger

_log = get_logger("fathom.api.routers.agent_jobs")

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


def get_job_queue(request: Request) -> JobQueue:
    """Return the process-wide :class:`JobQueue` (always provisioned at startup)."""
    queue = getattr(request.app.state, "job_queue", None)
    if not isinstance(queue, JobQueue):
        # The queue is created unconditionally in the lifespan; absence is a wiring bug, not a
        # default-OFF state, so it is a 500 rather than a silent 204.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="job queue not provisioned",
        )
    return queue


async def _resolve_host_name(session: SessionDep, fingerprint: str) -> str:
    """Map the verified cert fingerprint to its registered host *name* on the given session.

    The agent is identified by its fingerprint, exactly like ingest; a fingerprint with no host
    row has nothing to poll for and is refused rather than allowed to probe the queue.
    """
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
    """Resolve the host name in a short-lived session that is closed before any long wait.

    The poll is a *long*-poll (up to ~25s). If it held the request-scoped DB session/connection for
    that whole window, a fleet of long-polling agents would each pin a pooled connection idle and
    exhaust the pool. So the fingerprint→host lookup runs in its own transient session that is
    released immediately; the subsequent long-poll holds **no** DB connection.
    """
    maker = get_sessionmaker()
    async with maker() as session:
        return await _resolve_host_name(session, fingerprint)


@router.post("/jobs/poll", response_model=ClaimedJob, responses={204: {"description": "no job"}})
async def poll_job(
    fingerprint: FingerprintDep,
    request: Request,
) -> ClaimedJob | Response:
    """Long-poll for the next signed job scoped to the calling host, or 204 if none.

    Deliberately does NOT take the request-scoped DB session: it resolves the host in a transient
    session, then long-polls holding no connection (pool-exhaustion guard for a fleet of pollers).
    """
    host_name = await _resolve_host_name_transient(fingerprint)
    queue = get_job_queue(request)
    claimed = await queue.poll(host_id=host_name)
    if claimed is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return claimed


@router.post("/jobs/{job_id}/result", status_code=status.HTTP_200_OK)
async def submit_job_result(
    job_id: str,
    payload: JobResultPayload,
    session: SessionDep,
    fingerprint: FingerprintDep,
    request: Request,
) -> dict[str, str]:
    """Correlate and resolve a job result; consume its nonce on the durable single-use ledger."""
    host_name = await _resolve_host_name(session, fingerprint)
    queue = get_job_queue(request)
    if payload.job_id != job_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="path job_id does not match body job_id",
        )
    # Ownership first: only reveal/consume the nonce for a job THIS host was issued, so a spoofed
    # or cross-host result can never burn another host's nonce or resolve another host's dispatch.
    owner = queue.owner_of(job_id)
    if owner is None or owner != host_name:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no awaiting dispatch for this job",
        )
    nonce = queue.nonce_of(job_id)
    if nonce is None:  # pragma: no cover - owner present implies nonce present
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no awaiting dispatch for this job",
        )
    # Durable single-use: a replayed result (same job, even after a restart) hits the UNIQUE
    # used_nonce constraint and is rejected before the awaiting dispatch is resolved (T-3).
    if not await DbNonceStore(session).consume(nonce, job_id=job_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="job result already submitted (replay)",
        )
    try:
        queue.resolve(host_id=host_name, payload=payload)
    except JobCorrelationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    _log.info(
        "job result correlated",
        extra={"job_id": job_id, "host_id": host_name, "mode": payload.mode},
    )
    return {"status": "accepted"}
