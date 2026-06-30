"""Scans router — full-bit scan creation with a persisted impact ack (fullbit-dedup endpoints).

A control-plane surface for *requesting* a full-bit scan. It is gated by the
``TRIGGER_FULLBIT_SCAN`` capability (operator+, ADD 13 §3) and the returned scope filter
(out-of-scope volume → 403), and it persists the operator's impact acknowledgement on a
``snapshot`` row for the audit trail (ADD 02 non-impact contract). It performs **no** content
read and triggers **no** write — the gated full-bit hashing runs on the owning host's agent, and
dedup grouping remains report-only (security_constraints). No remediation route lives here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select

from fathom.api.auth_deps import PrincipalDep, require
from fathom.api.deps import SessionDep, SettingsDep
from fathom.api.remediation_runtime import RemediationRuntime
from fathom.api.schemas import (
    FullBitScanRequest,
    ScanCreatedOut,
    ScanDispatchedOut,
    ScanNowRequest,
    SnapshotOut,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core.audit_store import build_persistent_chain
from fathom.core.catalogue.models import Host, Snapshot, Volume
from fathom.core.remediation.job import SignedJob
from fathom.core.remediation.job_queue import DispatchTimeoutError, JobQueue
from fathom.core.remediation.orchestrator import RemediationOrchestrator
from fathom.logging import get_logger

_log = get_logger("fathom.api.routers.scans")

router = APIRouter(prefix="/api/v1", tags=["scans"])

FullBitScopeDep = Annotated[ScopeFilter, Depends(require(Capability.TRIGGER_FULLBIT_SCAN))]
# Viewing scan history is a read-surface capability (VIEW_METADATA), distinct from the
# operator+ capability that *requests* a full-bit run.
ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]
# Triggering a scan NOW is the operator+ scan-trigger capability (a full-bit Scan Now additionally
# requires TRIGGER_FULLBIT_SCAN, checked in-handler). Non-destructive → no step-up MFA.
ScanTriggerScopeDep = Annotated[ScopeFilter, Depends(require(Capability.TRIGGER_METADATA_SCAN))]


@router.get("/scans", response_model=list[SnapshotOut])
async def list_scans(
    session: SessionDep,
    scope: ViewScopeDep,
    volume_id: int | None = Query(default=None, ge=1),
) -> list[SnapshotOut]:
    """List scan-run history (newest first), scope-filtered; optionally narrowed to one volume.

    Server-authoritative scope (ADD 13 §4): a non-global principal sees only snapshots on in-scope
    hosts/volumes, with the system-volume gate (AR-011) applied via ``Volume.kind``. When
    ``volume_id`` is given it is scope-checked first so an out-of-scope volume is 403'd, not
    silently empty.
    """
    if volume_id is not None:
        volume = await session.get(Volume, volume_id)
        if volume is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")
        scope.check_target(host_id=volume.host_id, volume_id=volume.id, volume_kind=volume.kind)

    stmt = (
        select(Snapshot).join(Volume, Volume.id == Snapshot.volume_id).order_by(Snapshot.id.desc())
    )
    if volume_id is not None:
        stmt = stmt.where(Snapshot.volume_id == volume_id)
    stmt = scope.apply(
        stmt, host_col=Snapshot.host_id, volume_col=Snapshot.volume_id, kind_col=Volume.kind
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        SnapshotOut(
            id=s.id,
            host_id=s.host_id,
            volume_id=s.volume_id,
            mode=s.mode,
            started_at=s.started,
            finished_at=s.finished,
            entry_count=s.file_count,
            total_size_on_disk=s.total_size,
            warning_ack=s.warning_ack,
        )
        for s in rows
    ]


@router.post("/scans/fullbit", response_model=ScanCreatedOut, status_code=status.HTTP_201_CREATED)
async def create_fullbit_scan(
    body: FullBitScanRequest,
    session: SessionDep,
    principal: PrincipalDep,
    scope: FullBitScopeDep,
) -> ScanCreatedOut:
    """Record a full-bit scan request + impact ack on a snapshot (report-only, no write)."""
    volume = await session.get(Volume, body.volume_id)
    if volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")
    # Server-authoritative scope check: refuse a full-bit request on an out-of-scope volume. Pass
    # volume_kind so the AR-011 system-volume gate applies here too (it was omitted, letting a
    # data-scoped grant trigger a full-bit scan of a system volume — matches list_scans above).
    scope.check_target(host_id=volume.host_id, volume_id=volume.id, volume_kind=volume.kind)

    # The non-impact contract: a full-bit ack must name the backing device class. We can't parse
    # arbitrary prose, but we require a non-trivial acknowledgement so a blank token is refused.
    if len(body.impact_ack.strip()) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="impact_ack must name the backing device class (non-impact contract)",
        )

    snapshot = Snapshot(
        host_id=volume.host_id,
        volume_id=volume.id,
        mode="fullbit",
        warning_ack={
            "operator": principal.subject,
            "acknowledged_at": datetime.now(tz=UTC).isoformat(),
            "target": body.scope_path or volume.mountpoint,
            "mode": "fullbit",
            "impact_ack": body.impact_ack,
        },
    )
    session.add(snapshot)
    await session.flush()
    return ScanCreatedOut(snapshot_id=snapshot.id, volume_id=volume.id, mode="fullbit")


def _job_queue(request: Request) -> JobQueue:
    """Return the process-wide signed-job queue (provisioned unconditionally at startup)."""
    queue = getattr(request.app.state, "job_queue", None)
    if not isinstance(queue, JobQueue):
        # The queue is created in the lifespan; absence is a wiring bug, not a default-OFF state.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="job queue not provisioned",
        )
    return queue


@router.post(
    "/agents/{host_id}/scan",
    response_model=ScanDispatchedOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def scan_now(
    host_id: int,
    body: ScanNowRequest,
    session: SessionDep,
    principal: PrincipalDep,
    scope: ScanTriggerScopeDep,
    settings: SettingsDep,
    request: Request,
) -> ScanDispatchedOut:
    """Build + sign + enqueue a Scan Now job for one host's agent (operator+; non-destructive).

    Dispatched over the existing ADR-025 signed-job channel: the orchestrator signs a single-use,
    time-boxed :class:`~fathom.core.remediation.job.ScanJob` scoped to the host and the agent claims
    it on its next long-poll, verifies it, and runs the scan asynchronously (reporting via the
    normal ingest path). The endpoint is **non-blocking** — it returns ``202`` with a job id.

    Gating: ``TRIGGER_METADATA_SCAN`` + scope (a full-bit Scan Now additionally requires
    ``TRIGGER_FULLBIT_SCAN``). A scan is non-destructive, so step-up MFA is NOT required. The root
    must be a known scan root/volume for the host (``422`` otherwise); an unknown host is ``404``.
    If the signing/dispatch runtime is not provisioned (dispatch not armed) the call ``503``s.
    """
    # A full-bit Scan Now is the higher-privilege scan; require the matching capability (operator
    # holds both). The scope used below comes from the base scan-trigger grant.
    if body.mode == "fullbit" and not principal.has_capability(Capability.TRIGGER_FULLBIT_SCAN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="insufficient capability for full-bit scan",
        )

    host = await session.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown host")

    # Server-authoritative: ``root`` must be one of THIS host's catalogued volume mountpoints (a
    # known scan root). A client-named path that is not a registered volume is refused — a scan can
    # never be aimed at an arbitrary path outside the host's known volumes.
    volume = (
        await session.execute(
            select(Volume).where(Volume.host_id == host_id, Volume.mountpoint == body.root)
        )
    ).scalar_one_or_none()
    if volume is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="root is not a known scan root/volume for this host",
        )
    # Scope-check the target volume (host/volume scope + AR-011 system-volume gate).
    scope.check_target(host_id=host.id, volume_id=volume.id, volume_kind=volume.kind)

    # The signing/dispatch runtime is armed only when remediation is enabled AND a signing key is
    # provisioned (ADR-025 §3). Absent it there is no signer for the channel → 503 (default-OFF).
    runtime = getattr(request.app.state, "remediation_runtime", None)
    if not isinstance(runtime, RemediationRuntime):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="scan dispatch is not enabled",
        )
    queue = _job_queue(request)

    async def _enqueue(signed: SignedJob) -> None:
        # Fire-and-forget: ``enqueue_and_wait`` performs the synchronous enqueue then we let the
        # correlation waiter lapse at once (timeout 0). Per the JobQueue contract the un-claimed
        # job stays in the host's queue for the agent's next long-poll (dropped on TTL expiry by
        # poll if never claimed) — the scan reports back via ingest, not the job-result channel.
        try:
            await queue.enqueue_and_wait(
                signed, host_id=signed.job.host_id, timeout_seconds=0.0
            )
        except DispatchTimeoutError:
            pass

    audit_chain = await build_persistent_chain(session)
    orch = RemediationOrchestrator(
        audit=audit_chain,
        signer=runtime.signer,
        blast_cap=settings.remediation_blast_cap,
        job_ttl_seconds=settings.remediation_job_ttl_seconds,
    )
    # The signed job's host scope is the BUSINESS host id (Host.name) the polling agent resolves to
    # from its cert and independently re-verifies — exactly like a remediation job (ADR-025).
    job_id = await orch.dispatch_scan(
        created_by=principal.subject,
        host_id=host.name,
        root=body.root,
        mode=body.mode,
        enqueue=_enqueue,
    )
    await session.flush()
    return ScanDispatchedOut(job_id=job_id, host=host.name, root=body.root, mode=body.mode)
