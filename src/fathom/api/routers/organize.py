"""Organize router — content-aware reorganisation suggestions + gated apply (ADR-021/023).

``POST /api/v1/organize/suggest`` is **read-only**: it reads catalogue metadata, asks the inference
provider (ADR-022), and returns a proposal whose every target the server has clamped to the
requested root. It mutates nothing; gated by ``VIEW_METADATA`` + scope, default-OFF behind
``organize_enabled``.

``POST /api/v1/organize/plan`` turns an operator-approved subset of a proposal into a **persisted,
reversible MOVE remediation plan** (ADR-023). It is a *write-path build*, not an act: it touches no
filesystem. It is gated by ``BUILD_REMEDIATION`` + scope and is default-OFF behind BOTH
``organize_enabled`` and ``remediation_enabled``. The returned ``plan_id`` is then driven through
the existing remediation spine — ``POST /api/v1/remediation/plans/{id}/dry-run`` then
``/execute`` (EXECUTE_REMEDIATION + fresh step-up MFA) — so the destructive surface, its drift
re-verification, signed single-use jobs, blast cap, and audit chain are all reused unchanged.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.api.auth_deps import PrincipalDep, require
from fathom.api.deps import SecretProviderDep, SessionDep, SettingsDep
from fathom.api.remediation_runtime import get_runtime
from fathom.api.schemas import (
    OrganizeActivityOut,
    OrganizeItemOut,
    OrganizePlanItemOut,
    OrganizePlanOut,
    OrganizePlanRequest,
    OrganizeProposalOut,
    OrganizeSuggestRequest,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import query
from fathom.core.audit_store import build_persistent_chain
from fathom.core.catalogue.models import Volume
from fathom.core.organize import ApprovedMove, OrganizePlanError, OrganizeService
from fathom.core.remediation.models import RemediationPlanItemRow, RemediationPlanRow
from fathom.inference import InferenceError, build_inference_provider
from fathom.logging import get_logger
from fathom.security.paths import PathSafetyError, validate_config_path

_log = get_logger("fathom.api.routers.organize")

router = APIRouter(prefix="/api/v1", tags=["organize"])

OrganizeScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_METADATA))]
OrganizeBuildScopeDep = Annotated[ScopeFilter, Depends(require(Capability.BUILD_REMEDIATION))]


def _require_root_in_volume(path: str, volume: Volume) -> str:
    """Validate the folder root is an absolute path AT or UNDER the volume mountpoint; normalise it.

    The root is the trusted anchor every clamp is computed against and the executor opens directly
    (ADR-023); leaving it unchecked lets ``path="/"`` collapse the in-root prefix test to ``"/"``
    (fail-open) or point the anchor outside the volume the principal was authorised against
    (adversarial-review fix). The containment test runs on the **normalised** path — a string-prefix
    test on raw input would be defeated by ``/mount/../../etc`` (prefix-matches ``/mount/`` yet
    escapes). Returns the normalised root so callers anchor everything downstream to it.
    """
    try:
        # validate_config_path: absolute + no-NUL; returns an os.path.normpath'd Path.
        normalised = validate_config_path(path)
    except PathSafetyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"folder path is not a safe absolute path: {exc}",
        ) from exc
    root = str(normalised)
    mount = os.path.normpath(volume.mountpoint)
    if root != mount and not root.startswith(mount.rstrip("/") + "/"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="folder path is not within the selected volume",
        )
    return root


@router.post("/organize/suggest", response_model=OrganizeProposalOut)
async def organize_suggest(
    body: OrganizeSuggestRequest,
    session: SessionDep,
    settings: SettingsDep,
    secret_provider: SecretProviderDep,
    scope: OrganizeScopeDep,
) -> OrganizeProposalOut:
    """Propose a reorganisation for the files under ``path`` (read-only; nothing is moved)."""
    if not settings.organize_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="organize is disabled (organize_enabled=False)",
        )
    # Server-authoritative scope: the volume (and its root) must be in scope, else 403/404.
    volume = await query.get_volume_in_scope(session, body.volume_id, scope)
    if volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")
    root = _require_root_in_volume(body.path, volume)

    try:
        # One cohesive model: the per-feature override if set, else the global inference_model.
        chat_model = settings.organize_model or settings.inference_model
        provider = build_inference_provider(
            settings, model=chat_model, secret_provider=secret_provider
        )
        service = OrganizeService(session, provider, model=chat_model)
        proposal = await service.suggest(
            volume_id=body.volume_id, root=root, scope=scope, max_files=body.max_files
        )
    except InferenceError as exc:
        # Sanitised mapping — no provider internals leak; the read path changed nothing.
        raise HTTPException(status_code=exc.status_code, detail="inference unavailable") from exc

    return OrganizeProposalOut(
        root=proposal.root,
        volume_id=proposal.volume_id,
        model=proposal.model,
        considered=proposal.considered,
        rejected=proposal.rejected,
        items=[OrganizeItemOut(**asdict(it)) for it in proposal.items],
    )


_ACTIVITY_SCAN_LIMIT = 500


@router.get("/organize/activity", response_model=OrganizeActivityOut)
async def organize_activity(
    session: SessionDep,
    settings: SettingsDep,
    scope: OrganizeScopeDep,
    volume_id: Annotated[int, Query(ge=1)],
    path: Annotated[str, Query(min_length=1, max_length=4096)],
    since_hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> OrganizeActivityOut:
    """Summarise recent churn under ``path`` — a read-only "re-organise?" hint (ADR-021 Phase 3).

    Reads the incremental change feed only; nothing is moved and nothing is auto-applied. Gated by
    ``organize_enabled`` + ``VIEW_METADATA`` + the server-authoritative scope, like /suggest.
    """
    if not settings.organize_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="organize is disabled (organize_enabled=False)",
        )
    volume = await query.get_volume_in_scope(session, volume_id, scope)
    if volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")
    root = _require_root_in_volume(path, volume)

    since = datetime.now(tz=UTC) - timedelta(hours=since_hours)
    changes = await query.get_changes(
        session,
        volume_id=volume_id,
        path=root,
        since=since,
        scope=scope,
        limit=_ACTIVITY_SCAN_LIMIT,
    )
    created = sum(1 for c in changes if c.change_type == "create")
    modified = sum(1 for c in changes if c.change_type == "modify")
    deleted = sum(1 for c in changes if c.change_type == "delete")
    return OrganizeActivityOut(
        volume_id=volume_id,
        path=root,
        since_hours=since_hours,
        created=created,
        modified=modified,
        deleted=deleted,
        capped=len(changes) >= _ACTIVITY_SCAN_LIMIT,
        # New or changed files are what a re-organise would act on; pure deletions are not a nudge.
        suggests_reorganise=(created + modified) > 0,
    )


@router.post("/organize/plan", response_model=OrganizePlanOut, status_code=status.HTTP_201_CREATED)
async def organize_plan(
    body: OrganizePlanRequest,
    scope: OrganizeBuildScopeDep,
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    request: Request,
) -> OrganizePlanOut:
    """Build + persist a reversible MOVE plan from an approved subset (no FS touch; ADR-023).

    Default-OFF behind BOTH gates; idempotent on ``idempotency_key``. The persisted ``plan_id`` is
    then run through the remediation dry-run/execute spine (which carries the signed-job, drift, MFA
    and blast-cap guards). This route only *builds* — it dispatches nothing.
    """
    if not settings.organize_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="organize is disabled (organize_enabled=False)",
        )
    if not settings.remediation_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="remediation is disabled (remediation_enabled=False)",
        )
    # The runtime (signer + dispatch) must be provisioned for the plan to be actionable at all;
    # fail fast here (503) rather than letting the build succeed against a dead write path.
    get_runtime(request)

    # Scope is proven BEFORE any idempotency lookup so a replay can never short-circuit the gate
    # (adversarial-review fix): a caller must hold scope on the volume even to get a cached plan.
    volume = await query.get_volume_in_scope(session, body.volume_id, scope)
    if volume is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown volume")
    root = _require_root_in_volume(body.path, volume)

    if body.idempotency_key is not None:
        # Filter the replay lookup by the requesting principal: the key is NOT owner-bound in the
        # schema (globally unique), so without this a caller could fetch another principal's plan —
        # disclosing its paths/host/plan_id and bypassing scope (adversarial-review HIGH).
        existing = (
            await session.execute(
                select(RemediationPlanRow).where(
                    RemediationPlanRow.idempotency_key == body.idempotency_key,
                    RemediationPlanRow.created_by == principal.subject,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            # Re-assert scope on the cached row (the grant may have narrowed since it was built).
            scope.check_target(host_id=int(existing.host_id), volume_id=existing.volume_id)
            return await _organize_plan_out(session, existing)

    service = OrganizeService(session, model=settings.organize_model or settings.inference_model)
    plan_id = f"org-{secrets.token_hex(8)}"
    try:
        build = await service.build_move_plan(
            plan_id=plan_id,
            created_by=principal.subject,
            volume_id=body.volume_id,
            root=root,
            moves=[ApprovedMove(entry_id=m.entry_id, dest_rel=m.dest_rel) for m in body.moves],
            scope=scope,
        )
    except OrganizePlanError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    # Audit-before-persist: the operator's intent goes on the durable hash-chained log first.
    audit_chain = await build_persistent_chain(session)
    audit_chain.append(
        actor=principal.subject,
        action="organize.plan.build",
        target=plan_id,
        before_state={"root": build.plan.move_root, "blast": len(build.plan.items)},
        result="built",
    )
    row = RemediationPlanRow(
        plan_id=build.plan.plan_id,
        created_by=principal.subject,
        host_id=build.host_id,
        volume_id=body.volume_id,  # the single volume re-asserted at dry-run/execute (scope fix)
        keeper_path=build.plan.keeper_path,
        status="built",
        blast_count=len(build.plan.items),
        reclaimable_bytes=build.total_bytes,
        idempotency_key=body.idempotency_key,
        move_root=build.plan.move_root,
    )
    row.items = [
        RemediationPlanItemRow(
            entry_id=int(item.entry_id),
            path=item.path,
            prior_inode=item.prior_inode,
            prior_size=item.prior_size,
            prior_hash=item.prior_hash,
            action=item.action.value,
            dest_rel=item.dest_rel,
        )
        for item in build.plan.items
    ]
    session.add(row)
    try:
        await session.flush()
    except IntegrityError as exc:
        # The idempotency_key is globally unique; a DIFFERENT principal already used this key. We
        # never disclose their plan — fail closed with a clean 409, not a 500 (adversarial fix).
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="idempotency_key already in use",
        ) from exc
    _log.info(
        "organize move plan built",
        extra={"plan_id": plan_id, "by": principal.subject, "blast": len(build.plan.items)},
    )
    return await _organize_plan_out(session, row)


async def _organize_plan_out(session: AsyncSession, row: RemediationPlanRow) -> OrganizePlanOut:
    items = (
        (
            await session.execute(
                select(RemediationPlanItemRow).where(RemediationPlanItemRow.plan_id == row.id)
            )
        )
        .scalars()
        .all()
    )
    return OrganizePlanOut(
        plan_id=row.plan_id,
        move_root=row.move_root or row.keeper_path,
        host_id=row.host_id,
        blast_count=row.blast_count,
        reclaimable_bytes=row.reclaimable_bytes,
        status=row.status,
        items=[
            OrganizePlanItemOut(entry_id=i.entry_id, path=i.path, dest_rel=i.dest_rel or "")
            for i in items
        ],
    )
