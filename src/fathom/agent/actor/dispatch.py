"""Actor-side job dispatch — verified job → dry-run verify / executor (ADD 02 §Mode 3, E-1).

Once a signed job has passed :class:`~fathom.agent.actor.listener.SignedJobListener` (signature
+ nonce + expiry + scope), this turns it into work:

* ``dry_run`` → :func:`fathom.agent.actor.planner.dry_run_verify` against the live filesystem,
  returning the drift report to the orchestrator (no mutation);
* ``execute`` → :meth:`fathom.agent.actor.executor.Executor.execute`, which itself re-checks
  drift through the parent-dir fd immediately before each mutation (T-2) and audits-before-act.

The dispatcher reconstructs a :class:`~fathom.core.remediation.plan.RemediationPlan` from the
job's signed items — the *signed* item set is the authority, not anything the agent holds
locally — so the executor acts on exactly what the orchestrator signed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fathom.agent.actor.executor import ExecOutcome, ExecResult, Executor
from fathom.agent.actor.planner import VerifyReport, dry_run_verify
from fathom.core.audit import AuditRecord
from fathom.core.dedup import Hasher
from fathom.core.remediation.job import ActionJob
from fathom.core.remediation.plan import RemediationPlan


def plan_from_job(job: ActionJob) -> RemediationPlan:
    """Reconstruct the plan from the *signed* job items (the signed set is the authority)."""
    return RemediationPlan(
        plan_id=job.plan_id,
        created_by="orchestrator",
        keeper_path=job.keeper_path,
        items=list(job.items),
        move_root=job.move_root,  # re-anchor a MOVE job to the signed root (ADR-023)
    )


@dataclass(frozen=True, slots=True)
class JobResult:
    """The outcome the actor returns to the orchestrator for one job."""

    mode: str  # dry_run | execute
    plan_id: str
    drift: dict[str, str]  # entry_id -> reason (populated for dry_run; drifted-at-execute)
    results: list[ExecResult]  # populated for execute
    # The actor's per-item mutation audit (audit-before-act + result per acted item), carried back
    # so core can splice it onto the durable hash-chained store — the destructive act itself on the
    # tamper-evident log (ADR-025; closes the deferred TODO). Empty for a dry-run (no mutation).
    audit: list[AuditRecord] = field(default_factory=list)


class ActorDispatcher:
    """Runs a verified job: dry-run verification or guarded execution."""

    def __init__(self, *, executor: Executor, hasher: Hasher | None = None) -> None:
        self._executor = executor
        self._hasher = hasher

    async def dispatch_dry_run(self, job: ActionJob) -> VerifyReport:
        """Re-verify every signed item against the live FS; return the drift report."""
        return await dry_run_verify(plan_from_job(job), self._hasher)

    async def dispatch_execute(self, job: ActionJob, *, confirm_blast: bool = False) -> ExecOutcome:
        """Re-verify, then execute the guarded mutation for the signed items.

        A fresh dry-run is run here too: the executor refuses a non-OK report, and any item that
        drifted between the orchestrator's dry-run and now is caught (and the executor's own
        parent-fd re-check is the final TOCTOU gate, T-2).

        Returns the full :class:`~fathom.agent.actor.executor.ExecOutcome` — the per-item results
        **and** the executor's per-item mutation audit records — so the result channel can carry
        the act audit back to core for the durable hash-chained splice (ADR-025; the destructive
        act itself on the tamper-evident log). An all-drifted plan returns an aborted-only result
        set with no audit (nothing acted, nothing audited).
        """
        plan = plan_from_job(job)
        report = await dry_run_verify(plan, self._hasher)
        if not report.ok:
            # Drop the drifted items and execute only the clean subset (never act on drift).
            clean = [i for i in plan.items if str(i.entry_id) not in report.drifted]
            if not clean:
                aborted = [
                    ExecResult(str(i.entry_id), i.action.value, "aborted_drift", report.drifted[k])
                    for i in plan.items
                    if (k := str(i.entry_id)) in report.drifted
                ]
                return ExecOutcome(results=aborted, audit=[])
            plan = plan.model_copy(update={"items": clean})
            report = await dry_run_verify(plan, self._hasher)
        return await self._executor.execute_with_audit(plan, report, confirm_blast=confirm_blast)
