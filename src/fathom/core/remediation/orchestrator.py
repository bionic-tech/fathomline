"""Remediation orchestrator — server-authoritative plan build + signed-job dispatch (ADR-011).

The orchestrator is the *only* thing that turns an operator's keep/remove selection into action.
It is co-located with the Write API but is a distinct credential from the read surface. Its job
(API §1.3 data flow):

1. **build** a plan from a confirmed dedup group + the operator's explicit ``keep_id``,
   re-validating server-side (the operator's keep/remove choice and every path are re-checked
   against the catalogue and the path-safety primitives — client input is never the authority),
   and enforcing the **server-authoritative blast cap and scope** (the agent's own copy is never
   trusted, AR-0012).
2. **dry_run** by issuing a *signed* DRY_RUN :class:`~fathom.core.remediation.job.ActionJob`,
   collecting the actor's drift report.
3. **execute** by issuing a *signed* EXECUTE job for the **non-drifted subset only** (T-2): a
   drifted item is dropped from the execute job, never acted on.

Every step writes a persisted, hash-chained audit row *before* dispatch (audit-before-act,
fail-closed): the orchestrator audits intent, the actor audits the act. Default-off gating is
enforced by the API route (server ``remediation_enabled``) and the agent (``write_enabled``);
the orchestrator additionally refuses to dispatch an EXECUTE job over the blast cap without an
explicit ``confirm_blast``.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fathom.core.audit import AuditChain, AuditRecord
from fathom.core.remediation.job import ActionJob, JobMode, SignedJob
from fathom.core.remediation.plan import (
    Member,
    PlanAction,
    RemediationPlan,
    build_plan,
)
from fathom.core.remediation.signing import Signer, sign_job
from fathom.logging import get_logger
from fathom.security.paths import PathSafetyError, validate_config_path

if TYPE_CHECKING:
    from fathom.agent.actor.planner import VerifyReport

_log = get_logger("fathom.core.remediation.orchestrator")

DEFAULT_JOB_TTL_SECONDS = 300

# A dispatcher hands a signed job to the actor (over the agent-initiated channel) and returns
# the actor's per-item results. For DRY_RUN the actor returns a drift report; for EXECUTE it
# returns the exec results **and the actor's per-item mutation audit** (so core can put the
# destructive act on its durable chain). The orchestrator never opens a connection to the agent
# — the agent long-polls and the dispatcher is the in-core handle to that already-open channel.
DryRunDispatch = Callable[[SignedJob], "Awaitable[VerifyReport]"]
ExecResultLike = tuple[str, str, str]  # (entry_id, action, status)


@dataclass(frozen=True, slots=True)
class ExecuteOutcome:
    """What an EXECUTE dispatch returns: the per-item results + the actor's act audit records.

    ``audit`` is the actor's per-item mutation audit (built on the agent's own in-memory chain and
    carried back over the result channel); the orchestrator splices each record onto its durable
    hash-chained store so the destructive act itself lands on the tamper-evident log (ADR-025).
    """

    results: list[ExecResultLike]
    audit: list[AuditRecord]


ExecuteDispatch = Callable[[SignedJob], Awaitable[ExecuteOutcome]]


class BlastCapExceededError(RuntimeError):
    """An EXECUTE dispatch over the server blast cap without ``confirm_blast`` (E-1)."""


@dataclass(frozen=True, slots=True)
class GroupMember:
    """The orchestrator's view of one dedup-group member, with the scope it lives in."""

    entry_id: int
    host_id: int
    volume_id: int
    path: str
    inode: int
    size: int


class RemediationOrchestrator:
    """Builds plans and dispatches signed DRY_RUN/EXECUTE jobs with server-authoritative guards."""

    def __init__(
        self,
        *,
        audit: AuditChain,
        signer: Signer,
        blast_cap: int,
        job_ttl_seconds: int = DEFAULT_JOB_TTL_SECONDS,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._audit = audit
        self._signer = signer
        self._blast_cap = blast_cap
        self._job_ttl = job_ttl_seconds
        self._now = now or (lambda: datetime.now(tz=UTC))

    def build(
        self,
        *,
        plan_id: str,
        members: list[GroupMember],
        keep_id: int,
        full_hash: str,
        created_by: str,
        target_host_id: str,
        action: PlanAction = PlanAction.QUARANTINE,
    ) -> RemediationPlan:
        """Build a server-validated plan acting on every member except ``keep_id``.

        Re-validates every member path through the path-safety primitive (no traversal / NUL /
        non-canonical path may reach the DB or a job) and refuses a plan whose target set would
        exceed nothing here (the cap is enforced at dispatch, where ``confirm_blast`` applies).
        The keeper is the operator's explicit choice (ADR-011 — Fathom never auto-selects).
        """
        for member in members:
            try:
                validate_config_path(member.path)
            except PathSafetyError as exc:
                raise ValueError(f"member path {member.path!r} failed path safety: {exc}") from exc
        plan = build_plan(
            plan_id=plan_id,
            created_by=created_by,
            members=[
                Member(entry_id=m.entry_id, path=m.path, inode=m.inode, size=m.size)
                for m in members
            ],
            keep_id=keep_id,
            full_hash=full_hash,
            action=action,
        )
        self._audit.append(
            actor=created_by,
            action="remediation.plan.build",
            target=plan.plan_id,
            before_state={"keeper": plan.keeper_path, "blast": len(plan.items)},
            result="built",
        )
        _log.info(
            "remediation plan built",
            extra={"plan_id": plan.plan_id, "blast": len(plan.items), "host": target_host_id},
        )
        return plan

    def _make_job(self, plan: RemediationPlan, *, mode: JobMode, host_id: str) -> ActionJob:
        issued = self._now()
        return ActionJob(
            plan_id=plan.plan_id,
            mode=mode,
            nonce=secrets.token_hex(16),  # 128-bit single-use nonce
            issued_at=issued,
            expires_at=issued + timedelta(seconds=self._job_ttl),
            host_id=host_id,
            keeper_path=plan.keeper_path,
            items=list(plan.items),
            move_root=plan.move_root,  # carried into the signed envelope for MOVE jobs (ADR-023)
        )

    async def dry_run(
        self, plan: RemediationPlan, *, host_id: str, dispatch: DryRunDispatch
    ) -> VerifyReport:
        """Issue a signed DRY_RUN job and return the actor's drift report (no mutation)."""
        signed = sign_job(self._make_job(plan, mode="dry_run", host_id=host_id), self._signer)
        self._audit.append(
            actor=plan.created_by,
            action="remediation.dry_run.dispatch",
            target=plan.plan_id,
            before_state={"nonce": signed.job.nonce, "items": len(plan.items)},
            result="dispatched",
        )
        report = await dispatch(signed)
        self._audit.append(
            actor=plan.created_by,
            action="remediation.dry_run.result",
            target=plan.plan_id,
            before_state={"drifted": sorted(report.drifted)},
            result="ok" if report.ok else "drift",
        )
        return report

    async def execute(
        self,
        plan: RemediationPlan,
        verify: VerifyReport,
        *,
        host_id: str,
        confirm_blast: bool = False,
        dispatch: ExecuteDispatch,
    ) -> list[ExecResultLike]:
        """Issue a signed EXECUTE job for the **non-drifted subset only** (T-2).

        Drifted items (from the dry-run ``verify``) are dropped from the job — never acted on.
        An execute over the server blast cap requires ``confirm_blast`` (E-1). If every item
        drifted, nothing is dispatched and an empty result is returned. The actor's per-item
        mutation audit (returned over the result channel) is spliced onto the durable hash-chained
        store so the destructive act itself is on the tamper-evident log (ADR-025).
        """
        live_items = [item for item in plan.items if str(item.entry_id) not in verify.drifted]
        if not live_items:
            self._audit.append(
                actor=plan.created_by,
                action="remediation.execute.skip",
                target=plan.plan_id,
                before_state={"reason": "all items drifted"},
                result="noop",
            )
            return []
        if len(live_items) > self._blast_cap and not confirm_blast:
            raise BlastCapExceededError(
                f"execute touches {len(live_items)} items > server cap {self._blast_cap}; "
                "explicit confirm_blast required"
            )
        # The execute job carries only the non-drifted subset (server-authoritative; T-2).
        subset = plan.model_copy(update={"items": live_items})
        signed = sign_job(self._make_job(subset, mode="execute", host_id=host_id), self._signer)
        self._audit.append(
            actor=plan.created_by,
            action="remediation.execute.dispatch",
            target=plan.plan_id,
            before_state={
                "nonce": signed.job.nonce,
                "items": len(live_items),
                "dropped_drifted": sorted(verify.drifted),
            },
            result="dispatched",
        )
        outcome = await dispatch(signed)
        # Splice the actor's per-item mutation audit (the destructive act itself) onto the durable
        # hash-chained store: each record is re-anchored onto the live head and staged via the
        # persistent sink, so the act lands on the tamper-evident log — not only the actor's
        # volatile in-memory chain (ADR-025; closes the deferred security-review fix (2)). The
        # splice runs *before* the result summary so the chain reads dispatch → acts → result.
        for record in outcome.audit:
            self._audit.splice(record)
        self._audit.append(
            actor=plan.created_by,
            action="remediation.execute.result",
            target=plan.plan_id,
            before_state={"results": [list(r) for r in outcome.results]},
            result="completed",
        )
        return outcome.results
