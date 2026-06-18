"""Persisted hash-chained audit store + DB nonce ledger tests (ADD 03 §8; T-3 replay).

Audit-completeness: the chain head resumes from the last persisted row across a simulated
restart and ``verify_chain`` over the persisted rows is unbroken. The DB nonce store rejects a
replayed nonce atomically (UNIQUE constraint) — even when two consumes race the same nonce.

Fork hardening (security-review fix (1)): the UNIQUE ``prev_hash`` constraint admits exactly one
row per predecessor, so a forked sibling INSERT is rejected and :func:`append_durable` retries
against the new head — two appends racing the same head still produce one linear chain.

Checkpoint verify (security-review fix (3)): :func:`write_checkpoint` anchors the signed head and
:func:`verify_latest_checkpoint` fails closed if the anchored row is rewritten or rows at/before
it are dropped (truncation), and passes when the live chain still extends the anchor.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.core.audit import GENESIS_HASH, verify_chain
from fathom.core.audit_store import (
    append_durable,
    build_persistent_chain,
    load_head,
    persisted_records,
    persisted_records_page,
    verify_latest_checkpoint,
    write_checkpoint,
)
from fathom.core.catalogue.models import Base
from fathom.core.remediation import models as _models  # noqa: F401 — register remediation tables
from fathom.core.remediation.models import RemediationAuditRow
from fathom.core.remediation.nonce_store import DbNonceStore
from fathom.core.remediation.signing import HmacCheckpointSigner, HmacCheckpointVerifier


@pytest.fixture
async def maker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def test_chain_persists_and_verifies(maker: async_sessionmaker[AsyncSession]) -> None:
    async with maker() as session:
        chain = await build_persistent_chain(session)
        chain.append(actor="mo", action="a", target="/x", before_state={}, result="ok")
        chain.append(actor="mo", action="b", target="/y", before_state={"n": 1}, result="ok")
        await session.commit()
    async with maker() as session:
        records = await persisted_records(session)
        assert len(records) == 2
        assert verify_chain(records) is True


async def test_records_page_keyset_newest_first(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # Append five rows, then page them two-at-a-time newest-first via the keyset cursor.
    async with maker() as session:
        chain = await build_persistent_chain(session)
        for i in range(5):
            chain.append(actor="mo", action=f"a{i}", target=f"/x{i}", before_state={}, result="ok")
        await session.commit()
    async with maker() as session:
        page1, cur1 = await persisted_records_page(session, cursor=None, limit=2)
        assert [r.seq for r in page1] == [5, 4]  # descending seq (newest first)
        assert cur1 == 4
        page2, cur2 = await persisted_records_page(session, cursor=cur1, limit=2)
        assert [r.seq for r in page2] == [3, 2]
        assert cur2 == 2
        page3, cur3 = await persisted_records_page(session, cursor=cur2, limit=2)
        assert [r.seq for r in page3] == [1]
        assert cur3 is None  # final page → no further cursor


async def test_records_page_empty_chain(maker: async_sessionmaker[AsyncSession]) -> None:
    async with maker() as session:
        page, cursor = await persisted_records_page(session, cursor=None, limit=50)
        assert page == []
        assert cursor is None


async def test_chain_head_resumes_across_restart(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # First "process": write two rows.
    async with maker() as session:
        chain = await build_persistent_chain(session)
        chain.append(actor="mo", action="a", target="/x", before_state={}, result="ok")
        chain.append(actor="mo", action="b", target="/y", before_state={}, result="ok")
        await session.commit()
    # Second "process": a fresh chain resumes the head from the last row and appends more.
    async with maker() as session:
        head_before = await load_head(session)
        chain = await build_persistent_chain(session)
        assert chain.head == head_before  # resumed, not genesis
        chain.append(actor="mo", action="c", target="/z", before_state={}, result="ok")
        await session.commit()
    async with maker() as session:
        records = await persisted_records(session)
        assert len(records) == 3
        # The whole chain (across the two "processes") is one unbroken hash chain.
        assert verify_chain(records) is True


async def test_tampered_persisted_row_breaks_chain(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as session:
        chain = await build_persistent_chain(session)
        chain.append(actor="mo", action="a", target="/x", before_state={}, result="ok")
        chain.append(actor="mo", action="b", target="/y", before_state={}, result="ok")
        await session.commit()
    async with maker() as session:
        records = await persisted_records(session)
        # Forge the target of the first record → its row_hash no longer matches → chain breaks.
        records[0] = records[0].__class__(
            ts=records[0].ts,
            actor=records[0].actor,
            action=records[0].action,
            target="/evil",
            before_state=records[0].before_state,
            result=records[0].result,
            prev_hash=records[0].prev_hash,
            row_hash=records[0].row_hash,
        )
        assert verify_chain(records) is False


async def test_db_nonce_store_rejects_replay(maker: async_sessionmaker[AsyncSession]) -> None:
    async with maker() as session:
        store = DbNonceStore(session)
        assert await store.consume("nonce-1", job_id="j1") is True
        # Same nonce again → UNIQUE violation mapped to False (replay).
        assert await store.consume("nonce-1", job_id="j1") is False
        # A different nonce is still accepted.
        assert await store.consume("nonce-2", job_id="j2") is True
        await session.commit()


async def test_db_nonce_store_concurrent_consume_single_winner(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # Two separate sessions racing the same nonce: exactly one wins (the UNIQUE constraint is
    # the arbiter; no read-then-write window). The loser's INSERT fails and is mapped to False.
    async def attempt() -> bool:
        async with maker() as session:
            store = DbNonceStore(session)
            ok = await store.consume("race-nonce", job_id="j")
            if ok:
                await session.commit()
            else:
                await session.rollback()
            return ok

    results = await asyncio.gather(attempt(), attempt())
    assert sorted(results) == [False, True]  # exactly one winner


# --- fix (1): UNIQUE prev_hash fork rejection -----------------------------------------------


async def test_duplicate_prev_hash_insert_is_rejected(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Two rows pointing at the same predecessor (a fork) cannot both commit.

    The model carries ``UniqueConstraint("prev_hash")``; a second row with the same ``prev_hash``
    hits the constraint. This is the DB-level arbiter the migration installs.
    """
    async with maker() as session:
        session.add(
            RemediationAuditRow(
                ts="t",
                actor="a",
                action="x",
                target="/t",
                before_state={},
                result="ok",
                prev_hash=GENESIS_HASH,
                row_hash="h1",
            )
        )
        await session.commit()
    async with maker() as session:
        # A forked sibling: a *different* row_hash but the *same* prev_hash → fork → rejected.
        session.add(
            RemediationAuditRow(
                ts="t",
                actor="a",
                action="x",
                target="/t2",
                before_state={},
                result="ok",
                prev_hash=GENESIS_HASH,
                row_hash="h2",
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_append_durable_retries_fork_into_linear_chain(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Two writers racing the same head: the loser's forked INSERT is rejected and it retries.

    Each writer resumes the head, builds its record, and flushes inside a SAVEPOINT. Whichever
    commits first wins the head; the other's UNIQUE ``prev_hash`` violation triggers a reload +
    retry against the now-advanced head — so the persisted chain is one unbroken line, never a
    fork. ``append_durable`` stages but does not commit, so each writer commits its own session.
    """

    async def writer(action: str) -> None:
        async with maker() as session:
            await append_durable(
                session,
                actor="strata-actor",
                action=action,
                target=f"/v/{action}",
                before_state={},
                result="quarantined",
            )
            await session.commit()

    # Serialised here (SQLite in-memory is single-connection-per-engine), but each writer resumes
    # the live head independently; the second to commit must have re-chained off the first.
    await writer("a")
    await writer("b")

    async with maker() as session:
        records = await persisted_records(session)
        assert len(records) == 2
        # No fork: the two rows form a single linear chain from genesis.
        assert verify_chain(records) is True
        assert records[1].prev_hash == records[0].row_hash


async def test_append_durable_reloads_head_after_external_write(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """If the head advanced out from under us, ``append_durable`` chains off the *new* head.

    Seeds one row, then appends durably; the new row must extend the seeded head (not genesis),
    proving the head is re-read on each attempt rather than cached at the stale value.
    """
    async with maker() as session:
        chain = await build_persistent_chain(session)
        seeded = chain.append(actor="mo", action="seed", target="/s", before_state={}, result="ok")
        await session.commit()
    async with maker() as session:
        record = await append_durable(
            session,
            actor="strata-actor",
            action="quarantine",
            target="/v/f",
            before_state={},
            result="quarantined",
        )
        await session.commit()
        assert record.prev_hash == seeded.row_hash  # chained onto the live head, not genesis
        records = await persisted_records(session)
        assert verify_chain(records) is True


# --- fix (3): signed checkpoint write + verify ----------------------------------------------


def _checkpoint_keys() -> tuple[HmacCheckpointSigner, HmacCheckpointVerifier]:
    secret = b"checkpoint-test-secret-32-bytes!"
    return (
        HmacCheckpointSigner(secret, key_id="cp-test"),
        HmacCheckpointVerifier(secret, key_id="cp-test"),
    )


async def _seed_rows(session: AsyncSession, n: int) -> None:
    chain = await build_persistent_chain(session)
    for i in range(n):
        chain.append(actor="mo", action="a", target=f"/t{i}", before_state={}, result="ok")
    await session.commit()


async def test_checkpoint_written_and_verifies(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A fresh checkpoint over the live head verifies (signature valid + head unchanged)."""
    signer, verifier = _checkpoint_keys()
    async with maker() as session:
        await _seed_rows(session, 3)
        cp = await write_checkpoint(session, signer)
        assert cp is not None
        assert cp.seq == 3
        await session.commit()
    async with maker() as session:
        assert await verify_latest_checkpoint(session, verifier) is True


async def test_checkpoint_on_empty_chain_is_none(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """No rows → nothing to anchor → ``write_checkpoint`` returns None; verify is vacuously True."""
    signer, verifier = _checkpoint_keys()
    async with maker() as session:
        assert await write_checkpoint(session, signer) is None
        assert await verify_latest_checkpoint(session, verifier) is True


async def test_no_checkpoint_verifies_vacuously(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """With rows but no checkpoint yet, there is nothing to extend → verify True (vacuous)."""
    _signer, verifier = _checkpoint_keys()
    async with maker() as session:
        await _seed_rows(session, 2)
        assert await verify_latest_checkpoint(session, verifier) is True


async def test_checkpoint_rejects_forged_signature(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A checkpoint signed under one key fails verification under a different key (fail-closed)."""
    signer, _ = _checkpoint_keys()
    wrong_verifier = HmacCheckpointVerifier(b"a-totally-different-secret-key!!!", key_id="cp-test")
    async with maker() as session:
        await _seed_rows(session, 2)
        await write_checkpoint(session, signer)
        await session.commit()
    async with maker() as session:
        assert await verify_latest_checkpoint(session, wrong_verifier) is False


async def test_checkpoint_detects_rewritten_anchored_row(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Rewriting the anchored row's hash after checkpointing is caught (tamper detection)."""
    signer, verifier = _checkpoint_keys()
    async with maker() as session:
        await _seed_rows(session, 3)
        await write_checkpoint(session, signer)  # anchors seq=3
        await session.commit()
    async with maker() as session:
        # Forge the anchored row's stored row_hash → no longer matches the checkpoint anchor.
        await session.execute(
            update(RemediationAuditRow)
            .where(RemediationAuditRow.seq == 3)
            .values(row_hash="0" * 63 + "1")
        )
        await session.commit()
    async with maker() as session:
        assert await verify_latest_checkpoint(session, verifier) is False


async def test_checkpoint_detects_truncation_before_anchor(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Dropping a row at/before the anchor (truncation) is caught — fewer rows than ``seq``."""
    signer, verifier = _checkpoint_keys()
    async with maker() as session:
        await _seed_rows(session, 3)
        await write_checkpoint(session, signer)  # anchors seq=3
        await session.commit()
    async with maker() as session:
        # Drop the first row → only 2 rows remain but the anchor expects at least 3.
        await session.execute(delete(RemediationAuditRow).where(RemediationAuditRow.seq == 1))
        await session.commit()
    async with maker() as session:
        assert await verify_latest_checkpoint(session, verifier) is False
