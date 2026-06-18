"""Dry-run re-verification of a remediation plan against the live filesystem (ADD 02 §Mode 3).

Before anything is touched, every plan item is re-resolved and re-stat'd and (optionally)
re-hashed, and compared to the prior state the plan was built against. Any drift — the file
moved, changed size, changed inode, became a symlink, or its content hash no longer matches
— marks the item as drifted and the plan as not-OK. The executor refuses to run a plan that
is not OK. This is the defence against acting on a stale plan or a swapped target.
"""

from __future__ import annotations

import asyncio
import os
import stat as stat_mod
from dataclasses import dataclass, field

from fathom.core.dedup import Hasher
from fathom.core.remediation.plan import PlanItem, RemediationPlan
from fathom.logging import get_logger

_log = get_logger("fathom.agent.actor.planner")


@dataclass(slots=True)
class VerifyReport:
    """Result of a dry-run verification."""

    drifted: dict[str, str] = field(default_factory=dict)  # entry_id (str) -> reason

    @property
    def ok(self) -> bool:
        return not self.drifted


async def dry_run_verify(
    plan: RemediationPlan, hasher: Hasher | None = None, *, verify_hash: bool = True
) -> VerifyReport:
    """Re-verify every plan item against the live filesystem; report any drift."""
    report = VerifyReport()
    for item in plan.items:
        reason = await _verify_item(item, hasher, verify_hash)
        if reason is not None:
            report.drifted[str(item.entry_id)] = reason
            _log.warning(
                "plan item drifted",
                extra={"entry_id": str(item.entry_id), "path": item.path, "reason": reason},
            )
    return report


async def _verify_item(item: PlanItem, hasher: Hasher | None, verify_hash: bool) -> str | None:
    try:
        st = await asyncio.to_thread(os.lstat, item.path)
    except OSError:
        return "missing"
    if stat_mod.S_ISLNK(st.st_mode):
        return "became_symlink"  # a swapped target — never act on it
    if st.st_ino != item.prior_inode:
        return "inode_changed"
    if st.st_size != item.prior_size:
        return "size_changed"
    if verify_hash and item.prior_hash is not None and hasher is not None:
        current = await hasher.full(item.path)
        if current != item.prior_hash:
            return "hash_changed"
    return None
