"""SqliteNonceStore — the agent actor's durable single-use replay guard (STRIDE T-3).

Unlike InMemoryNonceStore (covered indirectly by the listener/signing suites), the SQLite ledger
must reject a replay *across an agent restart*, which is the gap it exists to close.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fathom.core.remediation.nonce_store import SqliteNonceStore


async def test_sqlite_nonce_consume_is_single_use(tmp_path: Path) -> None:
    store = SqliteNonceStore(tmp_path / "nonce.sqlite")
    assert await store.consume("n1", job_id="j1") is True
    assert await store.consume("n1", job_id="j1") is False  # replay → rejected
    assert await store.consume("n2", job_id="j2") is True  # a distinct nonce is still fresh


async def test_sqlite_nonce_survives_restart(tmp_path: Path) -> None:
    # The whole point vs InMemoryNonceStore: a new instance on the same file (an agent
    # restart/crash) must still reject a nonce consumed before the restart.
    db = tmp_path / "nonce.sqlite"
    assert await SqliteNonceStore(db).consume("n1", job_id="j1") is True
    assert await SqliteNonceStore(db).consume("n1", job_id="j1") is False


def test_sqlite_nonce_ledger_is_owner_only(tmp_path: Path) -> None:
    import stat

    db = tmp_path / "nonce.sqlite"
    SqliteNonceStore(db)
    mode = stat.S_IMODE(db.stat().st_mode)
    assert mode == 0o600, f"ledger must be owner-only, got {oct(mode)}"


async def test_sqlite_nonce_concurrent_consume_has_one_winner(tmp_path: Path) -> None:
    # Insert-or-fail atomicity (never read-then-write): many concurrent consumes of the SAME
    # nonce must yield exactly one success — the DB's PRIMARY KEY is the single arbiter.
    store = SqliteNonceStore(tmp_path / "nonce.sqlite")
    results = await asyncio.gather(*[store.consume("n", job_id="j") for _ in range(12)])
    assert sum(results) == 1
