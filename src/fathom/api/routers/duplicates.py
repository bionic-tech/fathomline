"""Duplicates router — the read-only dedup report surface (ADD 09 §4, ADD 13 §4).

A read-only route group (no write/remediation here — report-only per the fullbit-dedup spec).
Every route requires the ``VIEW_DEDUP`` capability (deny-by-default) and applies the returned,
server-authoritative :class:`ScopeFilter`, so a principal only ever sees groups with an in-scope
member and a group's detail never returns an out-of-scope path (security_constraints). Listing is
keyset-paginated (mandatory at 50M rows; API §2) — the cursor is the last group id of the prior
page.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from fathom.api.auth_deps import require
from fathom.api.deps import SessionDep
from fathom.api.schemas import (
    DuplicateGroupDetailOut,
    DuplicateGroupOut,
    DuplicateMemberOut,
    DuplicatesPage,
    DuplicatesSummaryOut,
    ProviderDuplicateGroupOut,
    ProviderDuplicateMemberOut,
    ProviderDuplicatesOut,
)
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import query
from fathom.core.provider_dedup import find_provider_hash_duplicates

router = APIRouter(prefix="/api/v1", tags=["duplicates"])

# Resolve the VIEW_DEDUP capability + scope once; reused by every duplicates route.
DedupScopeDep = Annotated[ScopeFilter, Depends(require(Capability.VIEW_DEDUP))]


@router.get("/duplicates", response_model=DuplicatesPage)
async def list_duplicates(
    session: SessionDep,
    scope: DedupScopeDep,
    volume_id: int | None = Query(default=None, ge=1),
    cursor: int | None = Query(default=None, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> DuplicatesPage:
    """List duplicate groups (keyset-paginated, scope-filtered, read-only)."""
    groups, next_cursor = await query.list_duplicate_groups(
        session, scope=scope, volume_id=volume_id, cursor=cursor, limit=limit
    )
    return DuplicatesPage(
        items=[DuplicateGroupOut.model_validate(g) for g in groups],
        next_cursor=str(next_cursor) if next_cursor is not None else None,
    )


@router.get("/duplicates/summary", response_model=DuplicatesSummaryOut)
async def duplicates_summary(
    session: SessionDep,
    scope: DedupScopeDep,
    volume_id: int | None = Query(default=None, ge=1),
) -> DuplicatesSummaryOut:
    """Return the in-scope dedup headline (group count + total reclaimable) for the dashboard.

    Declared before ``/duplicates/{group_id}`` so the literal ``summary`` segment is never parsed
    as a group id. Scope-filtered (VIEW_DEDUP); ``volume_id`` narrows to one volume.
    """
    count, total = await query.duplicate_summary(session, scope=scope, volume_id=volume_id)
    return DuplicatesSummaryOut(group_count=count, total_reclaimable_bytes=total)


@router.get("/duplicates/provider", response_model=ProviderDuplicatesOut)
async def provider_duplicates(
    session: SessionDep,
    scope: DedupScopeDep,
    volume_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=1000),
) -> ProviderDuplicatesOut:
    """List cross-cloud provider-hash duplicate groups (zero-egress; report-only, ADR-028).

    Declared before ``/duplicates/{group_id}`` so the literal ``provider`` segment is never parsed
    as a group id. Scope-filtered (VIEW_DEDUP) — the RBAC predicate is pushed into the scan so no
    out-of-scope member can appear. These groups come from the provider's own hash (no download)
    and are **report-only**: there is no suggested keeper and no remediation path. Capped at
    ``limit`` (one extra is probed to set ``truncated``).
    """
    groups = await find_provider_hash_duplicates(
        session,
        scope=scope,
        volume_ids=[volume_id] if volume_id is not None else None,
        limit=limit + 1,  # probe one past the cap to detect truncation honestly
    )
    truncated = len(groups) > limit
    return ProviderDuplicatesOut(
        items=[
            ProviderDuplicateGroupOut(
                algo=g.algo,
                provider_hash=g.provider_hash,
                size=g.size,
                member_count=len(g.members),
                reclaimable_bytes=g.reclaimable_bytes,
                members=[
                    ProviderDuplicateMemberOut(
                        entry_id=m.entry_id,
                        host_id=m.host_id,
                        volume_id=m.volume_id,
                        path=m.path,
                    )
                    for m in g.members
                ],
            )
            for g in groups[:limit]
        ],
        truncated=truncated,
    )


@router.get("/duplicates/{group_id}", response_model=DuplicateGroupDetailOut)
async def get_duplicate(
    group_id: int,
    session: SessionDep,
    scope: DedupScopeDep,
) -> DuplicateGroupDetailOut:
    """Return one group with its in-scope members + non-binding suggested keeper (read-only)."""
    found = await query.get_duplicate_group(session, group_id, scope=scope)
    if found is None:
        # Either no such group or none of its copies are in scope — do not distinguish.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="duplicate group not found"
        )
    group, members = found
    # Recompute the aggregate over the VISIBLE members only (EC-dedup-5b). Returning the stored
    # whole-group member_count / reclaimable_bytes would disclose a count of copies the principal
    # cannot see — out-of-scope members are already hidden from `members`. Mirror the build-time
    # formula (dedup_service): reclaimable counts only NATIVE copies, since a network-mount alias
    # is a remote view and frees nothing (ADR-032).
    visible_native = sum(1 for m in members if not m.is_mount_alias)
    visible_reclaimable = group.size * max(0, visible_native - 1)
    # Don't point at a suggested keeper the principal can't see; the suggestion is non-binding.
    keeper_visible = group.suggested_keeper_entry_id in {m.entry_id for m in members}
    return DuplicateGroupDetailOut(
        id=group.id,
        full_hash=group.full_hash,
        size=group.size,
        member_count=len(members),
        reclaimable_bytes=visible_reclaimable,
        suggested_keeper_entry_id=group.suggested_keeper_entry_id if keeper_visible else None,
        suggested_keeper_reason=group.suggested_keeper_reason if keeper_visible else None,
        members=[DuplicateMemberOut.model_validate(m) for m in members],
    )
