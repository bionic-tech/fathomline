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

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from fathom.api.auth_deps import PrincipalDep, require
from fathom.api.deps import SessionDep
from fathom.api.schemas import FullBitScanRequest, ScanCreatedOut, SnapshotOut
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core.catalogue.models import Snapshot, Volume

router = APIRouter(prefix="/api/v1", tags=["scans"])

FullBitScopeDep = Annotated[ScopeFilter, Depends(require(Capability.TRIGGER_FULLBIT_SCAN))]
# Viewing scan history is a read-surface capability (VIEW_METADATA), distinct from the
# operator+ capability that *requests* a full-bit run.
ViewScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]


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
