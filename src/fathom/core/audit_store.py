"""Persisted hash-chained audit store (ADD 03 §8; audit-before-act, fail-closed).

:class:`fathom.core.audit.AuditChain` builds the tamper-evident chain but emits records to an
in-memory ``sink``. The real write path needs those records **durable**, with the chain head
surviving process restarts so the chain is one unbroken sequence across the lifetime of the
deployment, not per-process. This module provides:

* :func:`load_head` — resume the chain head from the last persisted row (or genesis if empty);
* :func:`build_persistent_chain` — an :class:`AuditChain` whose head is resumed and whose sink
  stages a :class:`RemediationAuditRow` onto a session (the row is flushed/committed by the
  caller's transaction);
* :func:`append_durable` — append one record durably with **fork-rejection + retry**: the row
  is flushed inside a SAVEPOINT, and a UNIQUE ``prev_hash`` violation (a concurrent writer won
  the head) reloads the head and retries against the new head;
* :func:`append_records_durable` — append a batch of pre-computed :class:`AuditRecord`s (e.g.
  the actor's per-item mutation audit returned from the executor) onto the durable chain,
  re-chaining each onto the live head so the destructive act itself is on the tamper-evident
  log (security-review fix (2));
* :func:`write_checkpoint` / :func:`verify_latest_checkpoint` — write a periodic signed head
  anchor and verify the live head still extends the last checkpoint (truncation detection,
  security-architecture OQ3; security-review fix (3));
* :func:`persisted_records` / :func:`verify_persisted_chain` — load the rows back as
  :class:`AuditRecord`s and verify the chain is unbroken (the audit-completeness test).

Fork rejection under concurrency (the audit-persistence-under-failure risk): the chain head
lives on the in-process :class:`AuditChain` after it is seeded from the last row, and every
append advances it in order. Two writers that resume the *same* head and both append would
otherwise fork the chain; the DB's UNIQUE ``prev_hash`` constraint admits exactly one, and the
loser reloads the head and retries (mirrors the ``used_nonce`` arbiter). Because audit-before-act
writes the row *before* the mutation, a failure to persist the audit aborts the action (the
mutation is never reached) — there is no path that mutates without a chained audit row.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.audit import (
    GENESIS_HASH,
    AuditChain,
    AuditRecord,
    rechain,
    verify_chain,
)
from fathom.core.remediation.models import (
    RemediationAuditCheckpointRow,
    RemediationAuditRow,
)

# Bound the fork-retry loop so a pathological hot row can never spin forever (fail-closed).
_MAX_APPEND_RETRIES = 8


@runtime_checkable
class CheckpointSigner(Protocol):
    """Signs a checkpoint head anchor over raw bytes (security-architecture OQ3).

    Distinct from the action-job :class:`~fathom.core.remediation.signing.Signer`, which signs an
    :class:`~fathom.core.remediation.job.ActionJob`; a checkpoint signs the canonical bytes of
    ``(seq, row_hash)``. Key material comes from the pluggable secret backend (ADR-010), never
    from code. The :class:`~fathom.core.remediation.signing.Ed25519Signer` and ``HmacSigner``
    satisfy a compatible ``key_id`` shape; a thin adapter supplies the bytes-level ``sign``.
    """

    @property
    def key_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


@runtime_checkable
class CheckpointVerifier(Protocol):
    """Verifies a checkpoint signature over raw bytes (pairs with :class:`CheckpointSigner`)."""

    def verify(self, message: bytes, signature: bytes) -> bool: ...


async def load_head(session: AsyncSession) -> str:
    """Return the current chain head — the last persisted ``row_hash``, or genesis if empty."""
    row = (
        await session.execute(
            select(RemediationAuditRow.row_hash).order_by(RemediationAuditRow.seq.desc()).limit(1)
        )
    ).scalar_one_or_none()
    return row if row is not None else GENESIS_HASH


def _row_from_record(record: AuditRecord) -> RemediationAuditRow:
    return RemediationAuditRow(
        ts=record.ts,
        actor=record.actor,
        action=record.action,
        target=record.target,
        before_state=record.before_state,
        result=record.result,
        prev_hash=record.prev_hash,
        row_hash=record.row_hash,
    )


async def build_persistent_chain(session: AsyncSession) -> AuditChain:
    """Build an :class:`AuditChain` whose head is resumed from the DB and whose sink persists.

    Each :meth:`AuditChain.append` stages a :class:`RemediationAuditRow` onto ``session`` (sync
    ``session.add``); the surrounding transaction flushes/commits it. The head is seeded from the
    last persisted row so the chain continues unbroken across restarts.
    """
    head = await load_head(session)

    def _sink(record: AuditRecord) -> None:
        session.add(_row_from_record(record))

    return AuditChain(sink=_sink, head=head)


async def append_durable(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str,
    before_state: dict[str, object],
    result: str,
) -> AuditRecord:
    """Append one record durably, rejecting and retrying a forked sibling (fix (1)).

    The record is built off the current head and flushed inside a SAVEPOINT. If a concurrent
    writer already committed a row with the same ``prev_hash``, the UNIQUE ``prev_hash``
    constraint rejects this INSERT (an :class:`IntegrityError`); the head is reloaded and the
    record re-chained onto the new head and retried, bounded by ``_MAX_APPEND_RETRIES``. The row
    is staged but **not committed** here — the caller's audit-before-act transaction commits it
    alongside (or before) the mutation.
    """
    for _ in range(_MAX_APPEND_RETRIES):
        head = await load_head(session)
        chain = AuditChain(sink=lambda _r: None, head=head)
        record = chain.append(
            actor=actor,
            action=action,
            target=target,
            before_state=before_state,
            result=result,
        )
        try:
            async with session.begin_nested():
                session.add(_row_from_record(record))
                await session.flush()
        except IntegrityError:
            # A sibling won the head (UNIQUE prev_hash) — reload and retry against the new head.
            continue
        return record
    raise RuntimeError(
        f"audit append could not win the chain head after {_MAX_APPEND_RETRIES} retries"
    )


async def _splice_record_durable(session: AsyncSession, record: AuditRecord) -> AuditRecord:
    """Re-chain ``record`` onto the live head and append it durably, with fork-rejection.

    Unlike :func:`append_durable`, the content fields — including the actor's original ``ts`` —
    are preserved verbatim; only ``prev_hash``/``row_hash`` are recomputed against the current
    head. A concurrent commit at the same head triggers a UNIQUE ``prev_hash`` retry.
    """
    for _ in range(_MAX_APPEND_RETRIES):
        head = await load_head(session)
        rechained = rechain(record, prev_hash=head)
        try:
            async with session.begin_nested():
                session.add(_row_from_record(rechained))
                await session.flush()
        except IntegrityError:
            continue
        return rechained
    raise RuntimeError(
        f"audit splice could not win the chain head after {_MAX_APPEND_RETRIES} retries"
    )


async def append_records_durable(
    session: AsyncSession, records: list[AuditRecord]
) -> list[AuditRecord]:
    """Splice externally-built records onto the durable chain's live head (fix (2)).

    The actor's executor records its per-item mutation audit via an in-memory
    :class:`AuditChain` and returns those :class:`AuditRecord`s; this re-chains each onto the
    persisted head (recomputing ``prev_hash``/``row_hash``, preserving the actor's original
    content and ``ts``) and appends it durably, so the destructive act itself lands on the
    tamper-evident, hash-chained store — not only the actor's volatile in-memory sink. Each
    splice goes through the fork-rejection path, so a concurrent core writer cannot fork the
    chain. Returns the re-chained, persisted records (their hashes now reflect durable linkage).
    """
    return [await _splice_record_durable(session, record) for record in records]


def _checkpoint_message(seq: int, row_hash: str) -> bytes:
    """Canonical bytes a checkpoint signature covers: the anchored ``(seq, row_hash)`` head."""
    return f"{seq}:{row_hash}".encode()


async def write_checkpoint(
    session: AsyncSession, signer: CheckpointSigner
) -> RemediationAuditCheckpointRow | None:
    """Write a periodic signed anchor of the current audit head (fix (3); OQ3).

    Records ``(seq, row_hash, signature, key_id)`` for the last persisted row so a later verifier
    can confirm the live chain still extends this head (truncation detection). Returns ``None``
    when the chain is empty (genesis — nothing to anchor). Never on an action's critical path;
    staged onto ``session`` and committed by the caller.
    """
    last = (
        await session.execute(
            select(RemediationAuditRow.seq, RemediationAuditRow.row_hash)
            .order_by(RemediationAuditRow.seq.desc())
            .limit(1)
        )
    ).first()
    if last is None:
        return None
    seq, row_hash = int(last[0]), str(last[1])
    signature = signer.sign(_checkpoint_message(seq, row_hash))
    row = RemediationAuditCheckpointRow(
        seq=seq,
        row_hash=row_hash,
        signature=signature.hex(),
        key_id=signer.key_id,
    )
    session.add(row)
    return row


async def latest_checkpoint(
    session: AsyncSession,
) -> RemediationAuditCheckpointRow | None:
    """Return the most recently written checkpoint row, or ``None`` if none exist."""
    return (
        await session.execute(
            select(RemediationAuditCheckpointRow)
            .order_by(RemediationAuditCheckpointRow.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def verify_latest_checkpoint(session: AsyncSession, verifier: CheckpointVerifier) -> bool:
    """Verify the live head still extends the last signed checkpoint (fix (3); OQ3).

    Three things must hold, else the audit log has been tampered with or truncated (fail-closed,
    returns ``False``):

    1. the checkpoint's signature is valid over its ``(seq, row_hash)`` (not forged);
    2. a row with that ``seq`` still exists and still carries that ``row_hash`` (the anchored row
       was not rewritten);
    3. the live chain at ``seq`` and everything up to it forms an unbroken hash chain, and the
       chain still has at least ``seq`` rows (nothing before the anchor was dropped).

    Truncating the tail (dropping rows *after* the checkpoint) is itself benign for *this* check
    — a fresh checkpoint advances the anchor — but dropping the anchored row or any row at/before
    it is caught. When no checkpoint exists yet, there is nothing to extend, so this returns
    ``True`` (vacuously) — callers gate on "has a checkpoint" separately if they require one.
    """
    cp = await latest_checkpoint(session)
    if cp is None:
        return True
    if not verifier.verify(_checkpoint_message(cp.seq, cp.row_hash), bytes.fromhex(cp.signature)):
        return False
    records = await persisted_records(session)
    if len(records) < cp.seq:
        return False  # rows at/before the anchor were dropped → truncation
    anchored = records[cp.seq - 1]  # seq is 1-based (SQLite/PG autoincrement starts at 1)
    if anchored.row_hash != cp.row_hash:
        return False  # the anchored row was rewritten
    return verify_chain(records[: cp.seq])


async def persisted_records(session: AsyncSession) -> list[AuditRecord]:
    """Load all persisted audit rows back as ordered :class:`AuditRecord`s (for verification)."""
    rows = (
        (await session.execute(select(RemediationAuditRow).order_by(RemediationAuditRow.seq)))
        .scalars()
        .all()
    )
    return [
        AuditRecord(
            ts=row.ts,
            actor=row.actor,
            action=row.action,
            target=row.target,
            before_state=row.before_state,
            result=row.result,
            prev_hash=row.prev_hash,
            row_hash=row.row_hash,
        )
        for row in rows
    ]


async def persisted_records_page(
    session: AsyncSession, *, cursor: int | None = None, limit: int = 50
) -> tuple[list[RemediationAuditRow], int | None]:
    """Return a keyset page of audit rows newest-first, plus the next cursor (read surface).

    Ordered by descending ``seq`` so the Audit tab shows the most recent activity first; ``cursor``
    is the ``seq`` of the last row of the previous page (rows with a strictly smaller ``seq`` are
    returned). One extra row is fetched to decide whether an older page exists. Unlike
    :func:`persisted_records` (which loads the whole chain for verification), this is bounded by
    ``limit`` so the audit log stays paginable at scale. Returns the raw rows (carrying ``seq`` and
    the ``prev_hash``/``row_hash`` linkage) so the router can expose the chain to the UI.
    """
    stmt = select(RemediationAuditRow).order_by(RemediationAuditRow.seq.desc())
    if cursor is not None:
        stmt = stmt.where(RemediationAuditRow.seq < cursor)
    rows = (await session.execute(stmt.limit(limit + 1))).scalars().all()
    page = list(rows[:limit])
    next_cursor = page[-1].seq if len(rows) > limit else None
    return page, next_cursor
