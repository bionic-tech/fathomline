"""Remediation Write/Action router (ADR-011, remediation-enable; API §1.3 data flow).

A **separate route group** from every read/ingest surface, mounted only when the auth layer is
present (app.py). Read != write at the route layer: nothing here reads catalogue data for a
viewer; every route requires a destructive-write capability and the step-up-MFA-gated routes
additionally require fresh MFA. The data flow (API §1.3):

    operator selection ─▶ POST /plans (BUILD_REMEDIATION + scope, idempotency-key)
                       ─▶ POST /plans/{id}/dry-run (signed DRY_RUN job → drift report)
                       ─▶ POST /plans/{id}/execute (EXECUTE_REMEDIATION + scope + FRESH MFA;
                                                     non-drifted subset only; default-OFF gate)
                       ─▶ POST /quarantine/{item}/restore|purge (QUARANTINE_MANAGE + MFA)

Default-off gating (security_constraints): every mutating route refuses unless the server's
``remediation_enabled`` is True; execute/quarantine additionally require the dispatched agent's
``write_enabled`` (enforced agent-side by the executor and listener — defence in depth). The
orchestrator enforces the server-authoritative blast cap and scope; the actor verifies the
signed single-use job before any FS touch.

GET /api/v1/audit is the read-only hash-chained audit surface (auditor|admin only, READ_AUDIT,
scope-agnostic global-read) — it is a *read* route and is mounted here only for cohesion with
the audit it covers; it performs no mutation and carries no step-up gate.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.auth_deps import PrincipalDep, require, require_step_up_mfa
from fathom.api.deps import SessionDep, SettingsDep
from fathom.api.remediation_runtime import RemediationRuntime, get_runtime
from fathom.api.schemas import AuditPage, AuditRecordOut
from fathom.auth.principal import Capability, Principal
from fathom.auth.scope import ScopeFilter
from fathom.core.audit_store import build_persistent_chain, persisted_records_page
from fathom.core.catalogue.models import DupGroup, DupMember, FsEntryRow, Host
from fathom.core.remediation.models import RemediationPlanItemRow, RemediationPlanRow
from fathom.core.remediation.orchestrator import (
    BlastCapExceededError,
    GroupMember,
    RemediationOrchestrator,
)
from fathom.core.remediation.plan import PlanAction
from fathom.core.riskclass import HIGH_RISK, classify_paths
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.api.routers.remediation")

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])
audit_router = APIRouter(prefix="/api/v1", tags=["audit"])

# Capability + scope deps (deny-by-default). The build route needs BUILD_REMEDIATION; the
# destructive routes need EXECUTE_REMEDIATION / QUARANTINE_MANAGE *and* fresh step-up MFA.
BuildScopeDep = Annotated[ScopeFilter, Depends(require(Capability.BUILD_REMEDIATION))]
ExecuteScopeDep = Annotated[ScopeFilter, Depends(require(Capability.EXECUTE_REMEDIATION))]
QuarantineScopeDep = Annotated[ScopeFilter, Depends(require(Capability.QUARANTINE_MANAGE))]
AuditScopeDep = Annotated[ScopeFilter, Depends(require(Capability.READ_AUDIT))]


def _require_enabled(settings: Settings) -> None:
    """Refuse any mutating remediation route unless the server gate is on (default-OFF)."""
    if not settings.remediation_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="remediation is disabled (remediation_enabled=False)",
        )


class BuildPlanRequest(BaseModel):
    """Build a plan from a confirmed dedup group + the operator's explicit keeper (ADR-011)."""

    group_id: int = Field(ge=1)
    keep_entry_id: int = Field(ge=1)
    action: PlanAction = PlanAction.QUARANTINE
    idempotency_key: str | None = Field(default=None, max_length=128)


class PlanItemOut(BaseModel):
    entry_id: int
    path: str
    action: str


class PlanOut(BaseModel):
    plan_id: str
    keeper_path: str
    host_id: str
    blast_count: int
    reclaimable_bytes: int
    status: str
    items: list[PlanItemOut]


class DriftItemOut(BaseModel):
    entry_id: str
    reason: str


class DryRunOut(BaseModel):
    plan_id: str
    ok: bool
    drifted: list[DriftItemOut]


class ExecuteRequest(BaseModel):
    confirm_blast: bool = False
    # The host name the operator typed to confirm WHICH server they are deleting/moving data on
    # (the "danger zone" gate). The server validates it against the plan's host record — a client
    # cannot skip it or guess. Required: an empty/mismatched value blocks the act before dispatch.
    confirm_host: str = Field(default="", max_length=255)


class ExecResultOut(BaseModel):
    entry_id: str
    action: str
    status: str


class ExecuteOut(BaseModel):
    plan_id: str
    results: list[ExecResultOut]


async def _load_group_members(
    session: AsyncSession, group_id: int, scope: ScopeFilter
) -> tuple[DupGroup, list[GroupMember]]:
    """Load a dedup group's members as orchestrator inputs, scope-checking every member.

    Out-of-scope hosts/volumes are refused (the build cannot reach a path the principal may not
    touch — server-authoritative scope, AR-0012). Prior state (inode/size/hash) comes from the
    catalogue ``fs_entry`` rows, never from client input (T-2/T-3 anchoring).
    """
    group = await session.get(DupGroup, group_id)
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="duplicate group not found"
        )
    members = (
        (await session.execute(select(DupMember).where(DupMember.group_id == group_id)))
        .scalars()
        .all()
    )
    if not members:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="group has no members")
    out: list[GroupMember] = []
    host_id_str: str | None = None
    for member in members:
        # Every member must be in scope; an out-of-scope member fails the whole build (403).
        scope.check_target(host_id=member.host_id, volume_id=member.volume_id)
        entry = await session.get(FsEntryRow, member.entry_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"catalogue entry {member.entry_id} missing (rescan required)",
            )
        out.append(
            GroupMember(
                entry_id=member.entry_id,
                host_id=member.host_id,
                volume_id=member.volume_id,
                path=entry.path,
                inode=entry.inode,
                size=entry.size_logical,
            )
        )
        # A plan targets one host (the actor that owns those inodes). v1 groups members per host.
        host_id_str = str(member.host_id)
    assert host_id_str is not None  # noqa: S101 — guaranteed by the non-empty members check
    return group, out


def _orchestrator(
    runtime: RemediationRuntime, audit_chain: object, settings: Settings
) -> RemediationOrchestrator:
    from fathom.core.audit import AuditChain  # local import avoids a cycle at module load

    assert isinstance(audit_chain, AuditChain)  # noqa: S101
    return RemediationOrchestrator(
        audit=audit_chain,
        signer=runtime.signer,
        blast_cap=settings.remediation_blast_cap,
        job_ttl_seconds=settings.remediation_job_ttl_seconds,
    )


@router.post("/plans", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
async def build_plan_route(
    body: BuildPlanRequest,
    scope: BuildScopeDep,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    request: Request,
) -> PlanOut:
    """Build + persist a remediation plan (no FS touch). Idempotent on ``idempotency_key``."""
    _require_enabled(settings)
    # Idempotency-key replay: a repeated build returns the original plan, never a second one. The
    # lookup is bound to the requesting principal — the key is globally unique but NOT owner-bound,
    # so without this filter a caller could fetch another principal's plan (paths/host disclosure,
    # adversarial-review HIGH). Scope is re-asserted on the cached row before it is returned.
    if body.idempotency_key is not None:
        existing = (
            await session.execute(
                select(RemediationPlanRow).where(
                    RemediationPlanRow.idempotency_key == body.idempotency_key,
                    RemediationPlanRow.created_by == principal.subject,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            scope.check_target(host_id=int(existing.host_id), volume_id=existing.volume_id)
            return await _plan_out(session, existing)

    group, members = await _load_group_members(session, body.group_id, scope)
    if not any(m.entry_id == body.keep_entry_id for m in members):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="keep_entry_id is not a member of the group",
        )
    runtime = get_runtime(request)
    audit_chain = await build_persistent_chain(session)
    orch = _orchestrator(runtime, audit_chain, settings)
    target_host = str(members[0].host_id)
    plan_id = f"plan-{secrets.token_hex(8)}"
    try:
        plan = orch.build(
            plan_id=plan_id,
            members=members,
            keep_id=body.keep_entry_id,
            full_hash=group.full_hash,
            created_by=principal.subject,
            target_host_id=target_host,
            action=body.action,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    row = RemediationPlanRow(
        plan_id=plan.plan_id,
        created_by=principal.subject,
        host_id=target_host,
        keeper_path=plan.keeper_path,
        status="built",
        blast_count=len(plan.items),
        reclaimable_bytes=group.size * len(plan.items),
        idempotency_key=body.idempotency_key,
    )
    row.items = [
        RemediationPlanItemRow(
            entry_id=int(item.entry_id),
            path=item.path,
            prior_inode=item.prior_inode,
            prior_size=item.prior_size,
            prior_hash=item.prior_hash,
            action=item.action.value,
        )
        for item in plan.items
    ]
    session.add(row)
    try:
        await session.flush()
    except IntegrityError as exc:
        # idempotency_key is globally unique; a DIFFERENT principal already used it. Never disclose
        # their plan — fail closed with a clean 409 (adversarial-review fix).
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="idempotency_key already in use"
        ) from exc
    return await _plan_out(session, row)


async def _plan_out(session: AsyncSession, row: RemediationPlanRow) -> PlanOut:
    items = (
        (
            await session.execute(
                select(RemediationPlanItemRow).where(RemediationPlanItemRow.plan_id == row.id)
            )
        )
        .scalars()
        .all()
    )
    return PlanOut(
        plan_id=row.plan_id,
        keeper_path=row.keeper_path,
        host_id=row.host_id,
        blast_count=row.blast_count,
        reclaimable_bytes=row.reclaimable_bytes,
        status=row.status,
        items=[PlanItemOut(entry_id=i.entry_id, path=i.path, action=i.action) for i in items],
    )


async def _load_plan(session: AsyncSession, plan_id: str) -> RemediationPlanRow:
    row = (
        await session.execute(
            select(RemediationPlanRow).where(RemediationPlanRow.plan_id == plan_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="plan not found")
    return row


def _domain_plan(row: RemediationPlanRow, items: list[RemediationPlanItemRow]) -> object:
    from fathom.core.remediation.plan import PlanItem, RemediationPlan

    return RemediationPlan(
        plan_id=row.plan_id,
        created_by=row.created_by,
        keeper_path=row.keeper_path,
        # ``move_root`` + per-item ``dest_rel`` round-trip a MOVE (Organize-apply) plan so the
        # actor re-walks the same approved root; both are NULL for dedup plans (ADR-023).
        move_root=row.move_root,
        items=[
            PlanItem(
                entry_id=i.entry_id,
                path=i.path,
                prior_inode=i.prior_inode,
                prior_size=i.prior_size,
                prior_hash=i.prior_hash,
                action=PlanAction(i.action),
                dest_rel=i.dest_rel,
            )
            for i in items
        ],
    )


@router.post("/plans/{plan_id}/dry-run", response_model=DryRunOut)
async def dry_run_route(
    plan_id: str,
    scope: BuildScopeDep,
    session: SessionDep,
    settings: SettingsDep,
    request: Request,
) -> DryRunOut:
    """Issue a signed DRY_RUN job and return the per-item drift preview (no mutation)."""
    _require_enabled(settings)
    row = await _load_plan(session, plan_id)
    # Re-assert scope at the SAME granularity the build used: an Organize MOVE plan carries the
    # volume it was authorised against, so a volume-scoped grant is re-checked at volume level (and
    # not locked out); ``volume_id`` is NULL for dedup plans → host-level check, as before.
    scope.check_target(host_id=int(row.host_id), volume_id=row.volume_id)
    items = list(
        (
            await session.execute(
                select(RemediationPlanItemRow).where(RemediationPlanItemRow.plan_id == row.id)
            )
        )
        .scalars()
        .all()
    )
    from fathom.core.remediation.plan import RemediationPlan

    plan = _domain_plan(row, items)
    assert isinstance(plan, RemediationPlan)  # noqa: S101
    # The signed job's host scope is the *business* host id (Host.name == the agent's configured
    # host_id), so the polling agent — which knows only its name — can independently re-verify the
    # scope (defence in depth, ADR-025). RBAC scope + the Host lookup stay on the DB host id.
    host = await session.get(Host, int(row.host_id))
    if host is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="target host missing")
    runtime = get_runtime(request)
    audit_chain = await build_persistent_chain(session)
    orch = _orchestrator(runtime, audit_chain, settings)
    report = await orch.dry_run(plan, host_id=host.name, dispatch=runtime.dry_run_dispatch)
    row.status = "dry_run"
    await session.flush()
    return DryRunOut(
        plan_id=plan_id,
        ok=report.ok,
        drifted=[DriftItemOut(entry_id=k, reason=v) for k, v in sorted(report.drifted.items())],
    )


@router.post("/plans/{plan_id}/execute", response_model=ExecuteOut)
async def execute_route(
    plan_id: str,
    body: ExecuteRequest,
    scope: ExecuteScopeDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    request: Request,
) -> ExecuteOut:
    """Execute the approved, non-drifted subset (EXECUTE_REMEDIATION + scope + FRESH MFA).

    Default-OFF gate + server blast cap + dry-run-first are all enforced before any dispatch.
    """
    _require_enabled(settings)
    row = await _load_plan(session, plan_id)
    # Re-assert scope at build granularity (volume for Organize MOVE plans, host for dedup).
    scope.check_target(host_id=int(row.host_id), volume_id=row.volume_id)
    items = list(
        (
            await session.execute(
                select(RemediationPlanItemRow).where(RemediationPlanItemRow.plan_id == row.id)
            )
        )
        .scalars()
        .all()
    )

    # --- Danger-zone acknowledgement gate (in addition to EXECUTE_REMEDIATION + fresh step-up MFA,
    # which the route deps already enforce for every execute). The operator must type the TARGET
    # host's name to confirm WHICH server this acts on; the server validates it against the plan's
    # host record (a client cannot skip or guess it). We also classify the plan's paths server-side
    # so the audit records which risk classes (OS / service data → high-risk) the act touches.
    host = await session.get(Host, int(row.host_id))
    if host is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="target host missing")
    if body.confirm_host.strip().casefold() != host.name.strip().casefold():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="host confirmation does not match",
        )
    risk_counts = classify_paths([i.path for i in items])
    high_risk = any(risk_counts[c] > 0 for c in HIGH_RISK)

    from fathom.core.remediation.plan import RemediationPlan

    plan = _domain_plan(row, items)
    assert isinstance(plan, RemediationPlan)  # noqa: S101
    runtime = get_runtime(request)
    audit_chain = await build_persistent_chain(session)
    # Audit the acknowledgement BEFORE any dispatch (audit-before-act, AR-0012): who, the host they
    # confirmed, the risk classes touched, and whether it was a high-risk (OS/service-data) act.
    audit_chain.append(
        actor=principal.subject,
        action="remediation.acknowledged",
        target=plan_id,
        before_state={
            "confirm_host": host.name,
            "host_id": row.host_id,
            "risk_classes": {k: v for k, v in risk_counts.items() if v > 0},
            "high_risk": high_risk,
            "blast": len(items),
        },
        result="acknowledged",
    )
    orch = _orchestrator(runtime, audit_chain, settings)
    # Dry-run-first is mandatory: re-verify, dispatch EXECUTE only for the non-drifted subset. The
    # job's host scope is the business host id (Host.name) the agent independently re-verifies.
    report = await orch.dry_run(plan, host_id=host.name, dispatch=runtime.dry_run_dispatch)
    try:
        results = await orch.execute(
            plan,
            report,
            host_id=host.name,
            confirm_blast=body.confirm_blast,
            dispatch=runtime.execute_dispatch,
        )
    except BlastCapExceededError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    row.status = "executed"
    await session.flush()
    _log.info(
        "remediation execute dispatched",
        extra={"plan_id": plan_id, "by": principal.subject, "results": len(results)},
    )
    return ExecuteOut(
        plan_id=plan_id,
        results=[ExecResultOut(entry_id=r[0], action=r[1], status=r[2]) for r in results],
    )


def _require_global_quarantine_scope(scope: ScopeFilter) -> None:
    """Fail-closed scope gate for quarantine restore/purge (review HIGH).

    These routes act on a free-form item id that is not yet bound to a ``(host_id, volume_id)``
    by a server-side quarantine record, so a non-global ``QUARANTINE_MANAGE`` grant cannot be
    proven to cover the item. Until that record lands, only a global grant may act — a
    host/volume/path-scoped principal is refused rather than allowed to mutate estate-wide
    quarantine state outside its scope (deny-by-default, AR-0012; ADD 13 §4).
    """
    if not scope.is_global:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="quarantine restore/purge requires a global-scope grant",
        )


@router.post("/quarantine/{item}/restore", status_code=status.HTTP_202_ACCEPTED)
async def quarantine_restore_route(
    item: str,
    scope: QuarantineScopeDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
) -> dict[str, str]:
    """Restore a quarantined item (QUARANTINE_MANAGE + step-up MFA; audited)."""
    _require_enabled(settings)
    _require_global_quarantine_scope(scope)
    audit_chain = await build_persistent_chain(session)
    audit_chain.append(
        actor=principal.subject,
        action="quarantine.restore",
        target=item,
        before_state={"item": item},
        result="requested",
    )
    await session.flush()
    return {"item": item, "status": "restore_requested"}


@router.post("/quarantine/{item}/purge", status_code=status.HTTP_202_ACCEPTED)
async def quarantine_purge_route(
    item: str,
    scope: QuarantineScopeDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
) -> dict[str, str]:
    """Purge a quarantined item after retention (QUARANTINE_MANAGE + step-up MFA; audited)."""
    _require_enabled(settings)
    _require_global_quarantine_scope(scope)
    audit_chain = await build_persistent_chain(session)
    audit_chain.append(
        actor=principal.subject,
        action="quarantine.purge",
        target=item,
        before_state={"item": item, "retention_days": settings.quarantine_retention_days},
        result="requested",
    )
    await session.flush()
    return {"item": item, "status": "purge_requested"}


@audit_router.get("/audit", response_model=AuditPage)
async def read_audit_route(
    _scope: AuditScopeDep,
    session: SessionDep,
    cursor: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
) -> AuditPage:
    """Read a keyset page of the hash-chained audit log, newest first (READ_AUDIT; read-only).

    Auditor|admin only. Paginated by descending ``seq`` (``cursor`` = the last ``seq`` of the
    previous page) so the log stays browsable at scale; each row carries its ``prev_hash``/
    ``row_hash`` so the tamper-evident chain is visible to the UI.
    """
    rows, next_cursor = await persisted_records_page(session, cursor=cursor, limit=limit)
    items = [
        AuditRecordOut(
            id=row.seq,
            ts=row.ts,
            actor=row.actor,
            action=row.action,
            target=row.target,
            result=row.result,
            prev_hash=row.prev_hash,
            row_hash=row.row_hash,
        )
        for row in rows
    ]
    return AuditPage(items=items, next_cursor=str(next_cursor) if next_cursor is not None else None)


def get_principal_subject(principal: Principal) -> str:
    """Small helper kept for symmetry with the audit actor binding (principal-authoritative)."""
    return principal.subject
