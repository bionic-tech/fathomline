"""Single-use nonce ledgers (STRIDE T-3 replay rejection).

A signed action job carries a CSPRNG ``nonce``. The actor consumes it exactly once: a second
arrival of the same nonce (a replay of a previously-acted job) must be rejected *before* any
filesystem access. Correctness hinges on the consume being **atomic** — an insert-or-fail, not
a read-then-write — so two concurrent executions of the same job can never both succeed (the
nonce-store race risk noted in the spec).

* :class:`InMemoryNonceStore` — a process-local set guarded by an ``asyncio.Lock``; used by the
  orchestrator's own dispatch path and by tests. Single-writer within a process.
* :class:`DbNonceStore` — backed by the ``used_nonce`` table whose ``nonce`` column carries a
  UNIQUE constraint; consume is an ``INSERT`` that the DB rejects on duplicate, which we map to
  "already consumed". This is the durable, multi-process-safe ledger for the live write path.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fathom.core.remediation.models import UsedNonceRow


class InMemoryNonceStore:
    """A process-local single-use nonce ledger (atomic via an ``asyncio.Lock``)."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._lock = asyncio.Lock()

    async def consume(self, nonce: str, *, job_id: str) -> bool:
        """Return ``True`` if ``nonce`` was fresh (now consumed), ``False`` if already seen."""
        async with self._lock:
            if nonce in self._seen:
                return False
            self._seen.add(nonce)
            return True


class SqliteNonceStore:
    """A durable single-process nonce ledger backed by a local SQLite file (the AGENT actor).

    The actor has no central DB (the :class:`DbNonceStore` is the server side); its replay guard
    must instead survive an agent restart/crash so a replayed job is still rejected after a bounce
    — the gap :class:`InMemoryNonceStore` leaves (its set is lost on restart, so a replay landing
    after a restart would be accepted). ``consume`` is an INSERT against a PRIMARY-KEY ``nonce``
    column — insert-or-fail, never read-then-write — so even two concurrent consumes of the same
    nonce see exactly one success (the loser hits an ``IntegrityError`` → ``False``). SQLite is
    synchronous, so the work runs in a worker thread; the DB's own locking arbitrates concurrency.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        # The ledger records past job nonces/ids — keep it owner-only. Pre-create the file 0o600
        # (so sqlite opens an already-restricted file) and enforce on restart; the actor-owned
        # quarantine dir is also created 0o700, which covers the -wal/-shm sidecars.
        os.close(os.open(self._db_path, os.O_CREAT | os.O_RDWR, 0o600))
        Path(self._db_path).chmod(0o600)
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS used_nonce ("
                "  nonce TEXT PRIMARY KEY,"
                "  job_id TEXT NOT NULL,"
                "  consumed_at TEXT NOT NULL DEFAULT (datetime('now'))"
                ")"
            )
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        # FULL (not NORMAL): this ledger's guarantee is durability, not throughput. NORMAL+WAL can
        # roll a committed row back to the last checkpoint on an OS crash / power loss, reopening
        # the T-3 replay window the store exists to close. Consumes are infrequent, so the
        # per-commit fsync cost is irrelevant.
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _consume_sync(self, nonce: str, job_id: str) -> bool:
        conn = self._connect()
        try:
            with conn:  # commits on success, rolls back on the IntegrityError
                conn.execute(
                    "INSERT INTO used_nonce (nonce, job_id) VALUES (?, ?)", (nonce, job_id)
                )
        except sqlite3.IntegrityError:
            return False  # PRIMARY KEY (UNIQUE) violation → already consumed (a replay)
        except sqlite3.OperationalError as exc:
            # A busy-timeout lock is NOT a replay and must never map to False. Surface a clear
            # transient error so the listener logs a ledger lock (recoverable via core redispatch),
            # not a verification failure — the job is never silently treated as already-seen.
            raise RuntimeError(f"nonce ledger temporarily locked: {exc}") from exc
        finally:
            conn.close()
        return True

    async def consume(self, nonce: str, *, job_id: str) -> bool:
        """Return ``True`` if ``nonce`` was fresh (now consumed), ``False`` if already seen."""
        return await asyncio.to_thread(self._consume_sync, nonce, job_id)


class DbNonceStore:
    """A durable, multi-process-safe nonce ledger backed by ``used_nonce`` (UNIQUE nonce).

    Consume is an INSERT inside a SAVEPOINT: the DB's UNIQUE constraint is the single arbiter
    of single-use, so even concurrent executors racing the same nonce see exactly one success
    (the loser hits an :class:`~sqlalchemy.exc.IntegrityError`, mapped to ``False``). The
    SAVEPOINT keeps the surrounding transaction usable after the (expected) duplicate failure.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def consume(self, nonce: str, *, job_id: str) -> bool:
        try:
            async with self._session.begin_nested():
                self._session.add(UsedNonceRow(nonce=nonce, job_id=job_id))
                await self._session.flush()
        except IntegrityError:
            return False  # UNIQUE violation → already consumed (a replay)
        return True
