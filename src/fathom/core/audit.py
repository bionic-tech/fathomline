"""Hash-chained, append-only audit log (ADD 03, ADD 09 §5; AR-0012).

Every mutating action is recorded as a record whose ``row_hash`` covers the previous
record's hash plus the canonical payload, forming a tamper-evident chain: altering or
removing any record breaks every hash after it, which :func:`verify_chain` detects. The
write path's rule is **audit-before-act** — no audit record, no action (ADD 02 §Mode 3).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

import blake3

GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One immutable audit entry in the chain."""

    ts: str
    actor: str
    action: str
    target: str
    before_state: dict[str, object]
    result: str
    prev_hash: str
    row_hash: str


def _canonical(
    *, ts: str, actor: str, action: str, target: str, before_state: dict[str, object], result: str
) -> str:
    return json.dumps(
        {
            "ts": ts,
            "actor": actor,
            "action": action,
            "target": target,
            "before_state": before_state,
            "result": result,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def compute_row_hash(prev_hash: str, payload: str) -> str:
    """Return the chained hash of a record given the prior head and its canonical payload."""
    h = blake3.blake3()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\x00")
    h.update(payload.encode("utf-8"))
    return h.hexdigest()


def record_payload(record: AuditRecord) -> str:
    """Return the canonical payload bytes a record's ``row_hash`` is computed over.

    Lets a caller re-anchor an already-built record onto a different predecessor (e.g. the
    durable store re-chains the actor's returned records onto the live head) without
    re-deriving the canonical form by hand.
    """
    return _canonical(
        ts=record.ts,
        actor=record.actor,
        action=record.action,
        target=record.target,
        before_state=record.before_state,
        result=record.result,
    )


def rechain(record: AuditRecord, *, prev_hash: str) -> AuditRecord:
    """Return ``record`` re-anchored onto ``prev_hash`` with its ``row_hash`` recomputed.

    The content fields (``ts``/``actor``/``action``/``target``/``before_state``/``result``) are
    preserved verbatim; only the chain linkage is recomputed. Used to splice externally-built
    records (the actor's per-item mutation audit) onto the durable chain's live head.
    """
    payload = record_payload(record)
    row_hash = compute_row_hash(prev_hash, payload)
    return AuditRecord(
        ts=record.ts,
        actor=record.actor,
        action=record.action,
        target=record.target,
        before_state=record.before_state,
        result=record.result,
        prev_hash=prev_hash,
        row_hash=row_hash,
    )


@dataclass(slots=True)
class AuditChain:
    """Builds a hash-chained audit log, emitting each record to ``sink``."""

    sink: Callable[[AuditRecord], None]
    head: str = GENESIS_HASH
    _now: Callable[[], datetime] = field(default=lambda: datetime.now(tz=UTC))

    def append(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        before_state: dict[str, object],
        result: str,
    ) -> AuditRecord:
        """Append a record to the chain and return it (audit-before-act)."""
        ts = self._now().isoformat()
        payload = _canonical(
            ts=ts,
            actor=actor,
            action=action,
            target=target,
            before_state=before_state,
            result=result,
        )
        row_hash = compute_row_hash(self.head, payload)
        record = AuditRecord(
            ts=ts,
            actor=actor,
            action=action,
            target=target,
            before_state=before_state,
            result=result,
            prev_hash=self.head,
            row_hash=row_hash,
        )
        self.sink(record)
        self.head = row_hash
        return record

    def splice(self, record: AuditRecord) -> AuditRecord:
        """Re-chain an externally-built ``record`` onto the current head and emit it.

        The content fields (``ts``/``actor``/``action``/``target``/``before_state``/``result``)
        are preserved verbatim; only ``prev_hash``/``row_hash`` are recomputed against this
        chain's head. Used to fold the actor's per-item mutation audit (built on the agent's own
        in-memory chain and returned over the dispatch result channel) into core's durable chain
        so the destructive act itself lands on the tamper-evident log (ADR-025; closes the
        deferred audit-threading TODO). Mirrors
        :func:`fathom.core.audit_store._splice_record_durable` at the in-memory layer.
        """
        rechained = rechain(record, prev_hash=self.head)
        self.sink(rechained)
        self.head = rechained.row_hash
        return rechained


def append_preview_access(
    chain: AuditChain,
    *,
    actor: str,
    role: str,
    entry_id: int,
    preview_type: str,
    sandbox_job_id: str,
    cache_hit: bool,
) -> AuditRecord:
    """Append a preview-access audit record (file-mgmt §4.2; ADR-014, audit-before-serve).

    Records the fields the access-tracking table mandates — user, role, file id, type, sandbox
    job id, cache hit/miss — into the same hash-chained, append-only audit (the chain stays one
    verifiable sequence with the write path's records). Emitted *before* the artifact is served.
    """
    return chain.append(
        actor=actor,
        action="preview.access",
        target=str(entry_id),
        before_state={
            "role": role,
            "type": preview_type,
            "sandbox_job_id": sandbox_job_id,
            "cache_hit": cache_hit,
        },
        result="served",
    )


def verify_chain(records: Sequence[AuditRecord], *, genesis: str = GENESIS_HASH) -> bool:
    """Return whether ``records`` form an unbroken hash chain from ``genesis``."""
    prev = genesis
    for record in records:
        if record.prev_hash != prev:
            return False
        payload = _canonical(
            ts=record.ts,
            actor=record.actor,
            action=record.action,
            target=record.target,
            before_state=record.before_state,
            result=record.result,
        )
        if compute_row_hash(prev, payload) != record.row_hash:
            return False
        prev = record.row_hash
    return True
