"""In-memory per-host job queue + result correlation for the dispatch channel (ADR-025 §1).

The orchestrator (on core) never opens a connection to a fleet agent — the agent **long-polls
core** over the existing agent-initiated mTLS boundary. This module is core's side of that
already-open channel: the orchestrator's dispatch callables :meth:`enqueue_and_wait` a signed
job for a host id and block on the correlated result; the agent's poll route :meth:`poll`
claims the next job for *its* host (resolved from its cert fingerprint), acts, and the result
route :meth:`resolve` hands the awaited result back.

Design (ADR-025 §1 option B — *in-memory per-host queue + DB-backed nonce ledger for single-use*):

* **Per-host queues, keyed by the business host id** (``Host.name`` == the agent's configured
  ``host_id`` == the signed ``job.host_id`` scope). A host only ever drains its own queue, so a
  job for host A can never be delivered to host B (cross-host leakage is structural, not a check).
* **Claim-once.** A job is removed from the queue the instant it is delivered (``asyncio.Queue``
  semantics); it cannot be delivered to a second poll.
* **Resolve-once correlation.** Each enqueue creates an ``asyncio.Future`` keyed by a fresh
  ``job_id``; the result route resolves exactly that future. A second result for the same job, or
  a result from a host that was never issued the job, is rejected (:class:`JobCorrelationError`).
* **Expiry.** The signed job carries its own ``expires_at``; a job that has aged past it in the
  queue is dropped on delivery (its waiter fails) rather than handed to an agent that would
  (correctly) refuse it. The dispatch wait is bounded so a never-claimed job never blocks forever.

**Single-worker requirement.** The queue + correlation futures live in the API process's event
loop, so core must run as a **single worker** (the deployed ``uvicorn`` has no ``--workers`` — one
process). Horizontal scaling would require the DB-backed lifecycle variant (ADR-025 §1 option A);
the durable single-use guard (the ``used_nonce`` ledger consumed in the result route) already is
multi-process-safe, but the awaiting-handler model is inherently in-process.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from fathom.core.remediation.job import JobMode, SignedJob
from fathom.logging import get_logger

_log = get_logger("fathom.core.remediation.job_queue")

# How long a single long-poll blocks before returning 204 (the agent re-polls). Bounded so the
# mTLS connection is recycled and a parked poll never wedges a worker thread.
DEFAULT_POLL_TIMEOUT_SECONDS = 25.0

# Hard caps on a posted result, so a compromised/buggy agent cannot flood core's durable audit
# chain or DB with an unbounded result payload. A legitimate result is bounded by the plan's blast
# radius (the executor emits ≤2 audit records per acted item); these limits sit far above any real
# plan (server blast cap defaults to 100) while still refusing an abusive payload at the boundary.
_MAX_RESULT_ITEMS = 10_000
_MAX_AUDIT_RECORDS = 20_000
_MAX_FIELD_CHARS = 4096


class DispatchTimeoutError(RuntimeError):
    """A dispatched job was not claimed-and-resulted within the dispatch window (fail-closed).

    The orchestrator's await gives up; the route surfaces this as a 504. Because the dispatch
    window is set to the signed job's TTL, a job that times out here has also *expired*, so an
    agent that later pulls it refuses it — there is no path that acts after dispatch gave up.
    """


class JobCorrelationError(RuntimeError):
    """A result could not be correlated to an awaiting dispatch (spoofed / cross-host / replayed).

    Raised when a result names a ``job_id`` that was never issued, was issued to a *different*
    host than the one posting it, or was already resolved. The route maps it to a 409 without
    revealing which case it was (no cross-host disclosure).
    """


class ExecResultPayload(BaseModel):
    """One per-item execution outcome the actor returns (mirrors ``ExecResult``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str = Field(max_length=_MAX_FIELD_CHARS)
    action: str = Field(max_length=64)
    status: str = Field(max_length=64)
    detail: str = Field(default="", max_length=_MAX_FIELD_CHARS)


class AuditRecordPayload(BaseModel):
    """The actor's per-item mutation audit record, carried back over the result channel.

    Core re-chains each onto the durable hash-chained store so the destructive act itself lands
    on the tamper-evident log (ADR-025 §1; closes the deferred audit-threading TODO). The fields
    mirror :class:`~fathom.core.audit.AuditRecord` exactly; ``prev_hash``/``row_hash`` reflect the
    actor's own in-memory chain and are recomputed against core's live head on splice.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    ts: str = Field(max_length=64)
    actor: str = Field(max_length=255)
    action: str = Field(max_length=64)
    target: str = Field(max_length=_MAX_FIELD_CHARS)
    before_state: dict[str, Any]
    result: str = Field(max_length=64)
    prev_hash: str = Field(max_length=128)
    row_hash: str = Field(max_length=128)


class JobResultPayload(BaseModel):
    """The result an agent posts back for one dispatched job (drift for DRY_RUN, acts for EXECUTE).

    ``extra='forbid'`` so a malformed/over-broad result is rejected at the boundary. ``audit`` is
    the actor's per-item act audit (empty for a dry-run); ``results`` the per-item exec status.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str = Field(min_length=1, max_length=_MAX_FIELD_CHARS)
    plan_id: str = Field(min_length=1, max_length=_MAX_FIELD_CHARS)
    mode: JobMode
    drift: dict[str, str] = Field(default_factory=dict)
    results: list[ExecResultPayload] = Field(default_factory=list, max_length=_MAX_RESULT_ITEMS)
    audit: list[AuditRecordPayload] = Field(default_factory=list, max_length=_MAX_AUDIT_RECORDS)


class ClaimedJob(BaseModel):
    """What the poll route returns to the agent: the opaque ``job_id`` + the signed job to act on.

    The ``job_id`` is a fresh correlation token (not the nonce — the nonce stays inside the signed
    envelope); the agent echoes it back on the result so core can resolve the right awaiting call.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str = Field(min_length=1)
    signed_job: SignedJob


class JobQueue:
    """Per-host signed-job queue with awaited result correlation (the core side of the channel)."""

    def __init__(
        self,
        *,
        poll_timeout_seconds: float = DEFAULT_POLL_TIMEOUT_SECONDS,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        # One unbounded asyncio.Queue per host id. ``setdefault`` lazily creates a host's queue on
        # first enqueue or poll, so an unknown host simply long-polls an empty queue (→ 204).
        self._queues: dict[str, asyncio.Queue[tuple[str, SignedJob]]] = {}
        self._results: dict[str, asyncio.Future[JobResultPayload]] = {}
        self._job_host: dict[str, str] = {}
        self._job_nonce: dict[str, str] = {}
        self._poll_timeout = poll_timeout_seconds
        self._now = now or (lambda: datetime.now(tz=UTC))

    def _queue_for(self, host_id: str) -> asyncio.Queue[tuple[str, SignedJob]]:
        return self._queues.setdefault(host_id, asyncio.Queue())

    def _expired(self, signed: SignedJob, *, at: datetime) -> bool:
        expires = signed.job.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return expires <= at

    async def enqueue_and_wait(
        self, signed: SignedJob, *, host_id: str, timeout_seconds: float
    ) -> JobResultPayload:
        """Enqueue ``signed`` for ``host_id`` and block on the agent's correlated result.

        Returns the agent-posted :class:`JobResultPayload`. Raises :class:`DispatchTimeoutError`
        if no result is correlated within ``timeout_seconds`` (set to the job TTL by the caller, so
        a timed-out job is also expired and cannot be acted on late). The correlation state is
        always cleaned up, and an un-claimed job is left to be dropped on expiry by :meth:`poll`.
        """
        job_id = secrets.token_hex(16)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[JobResultPayload] = loop.create_future()
        self._results[job_id] = future
        self._job_host[job_id] = host_id
        self._job_nonce[job_id] = signed.job.nonce
        self._queue_for(host_id).put_nowait((job_id, signed))
        _log.info(
            "job enqueued for dispatch",
            extra={"job_id": job_id, "host_id": host_id, "mode": signed.job.mode},
        )
        try:
            return await asyncio.wait_for(future, timeout_seconds)
        except TimeoutError as exc:
            raise DispatchTimeoutError(
                f"job {job_id} for host {host_id!r} was not claimed-and-resulted in time"
            ) from exc
        finally:
            self._results.pop(job_id, None)
            self._job_host.pop(job_id, None)
            self._job_nonce.pop(job_id, None)

    async def poll(self, *, host_id: str) -> ClaimedJob | None:
        """Claim the next non-expired job for ``host_id``, or ``None`` after the long-poll timeout.

        Claim-once: the job is removed from the queue on delivery. An expired job is dropped (its
        awaiting dispatch fails) and the next is tried, so an agent is never handed a job it would
        only refuse.
        """
        queue = self._queue_for(host_id)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._poll_timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                job_id, signed = await asyncio.wait_for(queue.get(), remaining)
            except TimeoutError:
                return None
            if self._expired(signed, at=self._now()):
                self._fail(job_id, "job expired before an agent claimed it")
                continue
            _log.info("job claimed by agent", extra={"job_id": job_id, "host_id": host_id})
            return ClaimedJob(job_id=job_id, signed_job=signed)

    def owner_of(self, job_id: str) -> str | None:
        """Return the host id a job was issued to, or ``None`` if unknown/already resolved."""
        return self._job_host.get(job_id)

    def nonce_of(self, job_id: str) -> str | None:
        """Return the signed nonce for ``job_id`` (the durable single-use key for the result)."""
        return self._job_nonce.get(job_id)

    def resolve(self, *, host_id: str, payload: JobResultPayload) -> None:
        """Resolve the awaiting dispatch for ``payload.job_id``; fail-closed on mis-correlation.

        Rejects (a) an unknown/already-resolved job, (b) a result from a host the job was not
        issued to (cross-host result spoof), so an agent can only ever return *its own* jobs'
        results. Resolve-once: a second result finds the future already done and is rejected.
        """
        expected_host = self._job_host.get(payload.job_id)
        if expected_host is None:
            raise JobCorrelationError(f"no awaiting dispatch for job {payload.job_id}")
        if expected_host != host_id:
            raise JobCorrelationError("result host does not match the job's issued host")
        future = self._results.get(payload.job_id)
        if future is None or future.done():
            raise JobCorrelationError(f"job {payload.job_id} already resolved")
        future.set_result(payload)

    def _fail(self, job_id: str, reason: str) -> None:
        """Fail an awaiting dispatch (e.g. its job expired in the queue before claim)."""
        future = self._results.get(job_id)
        if future is not None and not future.done():
            future.set_exception(DispatchTimeoutError(reason))
