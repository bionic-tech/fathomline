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

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from fathom.agent.actor.executor import ExecOutcome, ExecResult, Executor
from fathom.agent.actor.planner import VerifyReport, dry_run_verify
from fathom.core.audit import AuditRecord
from fathom.core.dedup import Hasher
from fathom.core.remediation.job import ActionJob
from fathom.core.remediation.plan import RemediationPlan

if TYPE_CHECKING:
    from fathom.agent.config import AgentConfig
    from fathom.agent.runner import AgentRunSummary
    from fathom.core.remediation.job import ScanJob

# Runs the actual scan -> stage -> push for one verified scan-now job, returning its run summary.
# The default wires :func:`fathom.agent.runner.scan_one_root_now`; tests inject a fake so the
# dispatch logic is exercised without a real filesystem walk or mTLS push.
ScanRunner = Callable[["ScanJob"], Awaitable["AgentRunSummary"]]


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


class ScanScopeError(RuntimeError):
    """A scan-now job targeted a root outside this agent's scan_scope (defence-in-depth refusal).

    Raised AFTER :func:`~fathom.core.remediation.signing.verify_job` has passed (signature, nonce,
    expiry, host scope) but before any scan runs — the actor never trusts that the orchestrator only
    ever signs in-scope roots (AR-0012; mirrors how ``verify_job`` itself refuses an out-of-host
    job). The listener drops the job without acting or posting a result (fail-closed); the nonce
    burned during verification still blocks a replay.
    """


class RemediationUnavailableError(RuntimeError):
    """A remediation (ActionJob) reached a SCAN-ONLY listener, which carries no write path.

    The symmetric twin of :class:`ScanScopeError`: a scan-only listener (``write_enabled=false``,
    no executor/quarantine) verifies + runs read-only Scan Now jobs but has no remediation
    dispatcher, so a dry-run/execute job is refused fail-closed — never silently swallowed. Lets a
    host (incl. a native Windows agent, where the write path is deferred under ADR-027) run Scan Now
    without ever arming the destructive path. The nonce burned during verification blocks a replay.
    """


class ScanDispatcher:
    """Runs a verified scan-now :class:`~fathom.core.remediation.job.ScanJob` (Scan Now, P3).

    The read-only companion to :class:`ActorDispatcher`. It holds the agent config (for the
    defence-in-depth ``in_scope`` re-check) and an injected ``scan_runner`` that performs the actual
    scan -> stage -> push for one root (the default wires
    :func:`fathom.agent.runner.scan_one_root_now`). A scan mutates nothing on the host, so unlike
    the executor it carries no write gate — but it still rides the verified, single-use, host-scoped
    signed-job channel (the listener has already verified the job before this is called).
    """

    def __init__(self, *, config: AgentConfig, scan_runner: ScanRunner) -> None:
        self._config = config
        self._scan_runner = scan_runner

    async def dispatch_scan(self, job: ScanJob) -> JobResult:
        """Re-check ``job.root`` is in scope, run the scan, and return its outcome as a JobResult.

        Raises :class:`ScanScopeError` if the root is outside the agent's ``scan_scope`` (defence in
        depth — the orchestrator's routing is never trusted blindly). On success the returned
        :class:`JobResult` reuses the read-only *dry_run* shape (a scan mutates nothing), carrying a
        single summary row so core's existing result channel can record acceptance/outcome with no
        schema change (see the module/report note on the synthetic plan_id + mode mapping).
        """
        if not self._config.in_scope(job.root):
            raise ScanScopeError(
                f"scan root {job.root!r} is not within this agent's scan_scope (refused)"
            )
        summary = await self._scan_runner(job)
        scope = next((s for s in summary.scopes if s.root == job.root), None)
        if scope is None:
            status, detail = "failed", "scan produced no outcome for the requested root"
        elif scope.error is not None:
            status, detail = "failed", f"scan error: {scope.error}"
        else:
            status = "completed"
            detail = (
                f"mode={job.mode} entries_seen={scope.entries_seen} "
                f"rows_changed={scope.rows_changed} pushed={summary.pushed} "
                f"fullbit_hashed={scope.fullbit_hashed}"
            )
            if scope.fullbit_error is not None:
                detail += f" fullbit_error={scope.fullbit_error}"
        return JobResult(
            # A scan mutates nothing → the read-only dry_run literal is the closest fit in the
            # JobMode the wire JobResultPayload validates (scan has no native wire mode).
            mode="dry_run",
            # JobResultPayload.plan_id is required (min_length 1); a scan has no plan, so the job's
            # synthetic ledger ref ("scan:<host>:<root>") stands in as a correlatable id.
            plan_id=job.ledger_ref,
            drift={},
            results=[
                ExecResult(entry_id=job.root, action="scan_now", status=status, detail=detail)
            ],
            audit=[],
        )
