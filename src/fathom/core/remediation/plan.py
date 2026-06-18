"""Remediation plan models and builder (ADR-011).

A plan records, for each file to act on, the *prior state* (inode, size, content hash) the
plan was built against. The actor re-verifies that prior state immediately before acting
and aborts on any drift (ADD 02 §Mode 3) — this is what makes a wrong-file deletion from a
stale plan impossible. Fathom never auto-selects the keeper: ``build_plan`` requires the
operator's explicit ``keep_id`` (ADR-011).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class PlanAction(StrEnum):
    """What to do with each file in a remediation plan."""

    QUARANTINE = "quarantine"  # reversible move to a quarantine tier (default, ADR-011)
    HARDLINK = "hardlink"  # replace with a hardlink to the keeper
    HARD_DELETE = "hard_delete"  # irreversible; requires an explicit allow flag
    MOVE = "move"  # reversible relocate/rename to dest_rel under move_root (ADR-023, Organize)


@dataclass(frozen=True, slots=True)
class Member:
    """A dedup-group member as known to the planner."""

    entry_id: int | str
    path: str
    inode: int
    size: int


class PlanItem(BaseModel):
    """One file to act on, with the prior state to re-verify against."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: int | str
    path: str
    prior_inode: int
    prior_size: int = Field(ge=0)
    prior_hash: str | None = None
    action: PlanAction
    # Destination for a MOVE, RELATIVE to the plan's ``move_root`` (ADR-023). The server has already
    # clamped it to the root; the executor re-walks it component-wise under ``O_NOFOLLOW`` so a
    # symlink planted in the destination tree cannot redirect the move out of the approved root.
    dest_rel: str | None = None


class RemediationPlan(BaseModel):
    """An operator-approved set of actions over one duplicate group or one Organize proposal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(min_length=1)
    created_by: str = Field(min_length=1)
    keeper_path: str
    items: list[PlanItem] = Field(min_length=1)
    # The operator-approved root a MOVE plan may relocate within (ADR-023). The executor opens this
    # as the trusted anchor and refuses any destination that is not reached from it via non-symlink
    # components. ``None`` for dedup plans (quarantine/delete), which never move within the estate.
    move_root: str | None = None


def build_plan(
    *,
    plan_id: str,
    created_by: str,
    members: list[Member],
    keep_id: int | str,
    full_hash: str,
    action: PlanAction = PlanAction.QUARANTINE,
) -> RemediationPlan:
    """Build a plan that acts on every member except the operator-chosen ``keep_id``.

    Raises:
        ValueError: If ``keep_id`` is not among ``members`` or no actionable items remain.
    """
    keeper = next((m for m in members if m.entry_id == keep_id), None)
    if keeper is None:
        raise ValueError(f"keep_id {keep_id!r} is not a member of the group")
    items = [
        PlanItem(
            entry_id=m.entry_id,
            path=m.path,
            prior_inode=m.inode,
            prior_size=m.size,
            prior_hash=full_hash,
            action=action,
        )
        for m in members
        if m.entry_id != keep_id
    ]
    if not items:
        raise ValueError("plan has no actionable items (keeper is the only member)")
    return RemediationPlan(
        plan_id=plan_id, created_by=created_by, keeper_path=keeper.path, items=items
    )
