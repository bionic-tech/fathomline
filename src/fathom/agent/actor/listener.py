"""Agent-side signed-job listener — verify-before-act (STRIDE T-3/S-3, E-1; no-inbound rule).

Owner ruling: remediation dispatch is **agent-initiated outbound** — the agent long-polls the
core over the existing agent-initiated mTLS channel for signed jobs; there is **no inbound port
on the agent**. This listener is the receiver of a job pulled over that channel. It is the
single chokepoint between the wire and the :class:`~fathom.agent.actor.executor.Executor`:

    pulled SignedJob ──▶ verify_job (signature, expiry, host scope, single-use nonce)
                         └─ on ANY failure: raise, never touch the filesystem (T-3/S-3)
                         └─ on success:    ActorDispatcher → dry-run verify / guarded execute

Because the verify happens *before* the dispatcher is ever called, an unsigned, tampered,
expired, replayed, or out-of-scope job never reaches a filesystem syscall (E-1). The reader
identity has no construction path to this class — the executor and this listener live under the
``strata-actor`` OS user only (separation of duties, ADR-011).
"""

from __future__ import annotations

from datetime import datetime

from fathom.agent.actor.dispatch import (
    ActorDispatcher,
    JobResult,
    RemediationUnavailableError,
    ScanDispatcher,
    ScanScopeError,
)
from fathom.core.remediation.job import ScanJob, SignedJob
from fathom.core.remediation.signing import (
    NonceStore,
    Verifier,
    verify_job,
)
from fathom.logging import get_logger

_log = get_logger("fathom.agent.actor.listener")


class SignedJobListener:
    """Verifies a pulled signed job, then dispatches it — never the reverse (verify-before-act).

    The listener binds to the agent-initiated channel only; it opens no inbound socket
    (no-inbound rule, network-segmentation). ``host_id`` is this agent's identity — a job
    addressed to another host is rejected as out of scope before any work.
    """

    def __init__(
        self,
        *,
        dispatcher: ActorDispatcher | None = None,
        verifier: Verifier,
        nonce_store: NonceStore,
        host_id: str,
        write_enabled: bool = False,
        scan_dispatcher: ScanDispatcher | None = None,
    ) -> None:
        # ``dispatcher`` is None on a SCAN-ONLY listener (read-only Scan Now, no write path): a
        # verified remediation job is then refused fail-closed (see handle()), so a host can run
        # Scan Now without arming remediation (and a native Windows agent stays read-only, ADR-027).
        self._dispatcher = dispatcher
        self._verifier = verifier
        self._nonce_store = nonce_store
        self._host_id = host_id
        # The listener carries the same default-off gate as the executor: even a perfectly
        # valid execute job does nothing until write_enabled is deliberately turned on. The
        # executor enforces this too (defence in depth) — this lets the listener refuse early.
        self._write_enabled = write_enabled
        # The read-only Scan Now branch (ADR-025 + Scan Now). A scan mutates nothing, so it does
        # not ride the write gate — but a listener built without one still refuses scan jobs
        # (fail-closed rather than silently swallow a verified job it cannot service).
        self._scan_dispatcher = scan_dispatcher

    async def handle(
        self, signed: SignedJob, *, confirm_blast: bool = False, now: datetime | None = None
    ) -> JobResult:
        """Verify ``signed`` on every axis, then dispatch. Raises before any FS touch on failure.

        Raises:
            JobVerificationError / NonceReuseError: bad signature, expired, out-of-scope, or
                replayed — propagated to the caller; the dispatcher is never invoked.
        """
        # verify_job is fail-closed: bad signature / expiry / scope raise before the nonce is
        # consumed, and the nonce is consumed atomically last (replay → NonceReuseError, T-3).
        job = await verify_job(
            signed,
            verifier=self._verifier,
            nonce_store=self._nonce_store,
            expected_host_id=self._host_id,
            now=now,
        )
        # Branch on the verified job type (the signed-job union, ADR-025). A ScanJob carries no plan
        # and moves nothing — it routes to the read-only Scan Now dispatcher, NOT the remediation
        # executor; only an ActionJob falls through to the dry-run/execute path below (unchanged).
        if isinstance(job, ScanJob):
            if self._scan_dispatcher is None:
                raise ScanScopeError(
                    "received a scan-now job but this listener is not configured to run scans"
                )
            result = await self._scan_dispatcher.dispatch_scan(job)
            _log.info(
                "scan-now job verified and triggered",
                extra={"root": job.root, "mode": job.mode},
            )
            return result
        # ActionJob (remediation): a scan-only listener has no write dispatcher — refuse it
        # fail-closed (never act) rather than swallow a verified job it cannot service. The nonce
        # burned in verify_job above still blocks any replay.
        if self._dispatcher is None:
            raise RemediationUnavailableError(
                "received a remediation job but this listener is scan-only (no write path)"
            )
        if job.mode == "dry_run":
            report = await self._dispatcher.dispatch_dry_run(job)
            _log.info(
                "dry-run job verified and executed",
                extra={"plan_id": job.plan_id, "drifted": len(report.drifted)},
            )
            return JobResult(mode="dry_run", plan_id=job.plan_id, drift=report.drifted, results=[])
        # execute mode — carry the executor's per-item act audit back so core can splice it onto
        # the durable hash-chained store (ADR-025; the destructive act itself on the audit log).
        outcome = await self._dispatcher.dispatch_execute(job, confirm_blast=confirm_blast)
        drift = {r.entry_id: r.detail for r in outcome.results if r.status == "aborted_drift"}
        _log.info(
            "execute job verified and executed",
            extra={"plan_id": job.plan_id, "results": len(outcome.results)},
        )
        return JobResult(
            mode="execute",
            plan_id=job.plan_id,
            drift=drift,
            results=outcome.results,
            audit=outcome.audit,
        )
