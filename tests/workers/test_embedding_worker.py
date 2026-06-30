"""EmbeddingWorker tests (ADR-035 Phase 2) — the periodic embed loop's contract.

The worker is a stdlib-asyncio periodic loop (no broker): it validates its interval, ticks
prune-then-embed returning the batch count, and — the load-bearing guarantee — a single failing
tick (e.g. the embedding provider is down) must be logged and retried next interval, NEVER kill the
loop. These are unit tests over a fake provider + monkeypatched batch functions; no real model.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from fathom.core import db
from fathom.core.catalogue.models import Base
from fathom.core.settings import Settings
from fathom.workers.embedding import EmbeddingWorker


class _StubProvider:
    """A stand-in EmbeddingProvider — the worker only stores it; batch fns are monkeypatched."""

    name = "stub"
    dimension = 8


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[None]:
    await db.dispose_engine()
    eng = db.init_engine(Settings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'c.db'}"))
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await db.dispose_engine()


def _worker(interval: float = 0.01, batch: int = 5) -> EmbeddingWorker:
    return EmbeddingWorker(provider=_StubProvider(), interval_seconds=interval, batch=batch)


def test_interval_must_be_positive() -> None:
    with pytest.raises(ValueError, match="interval_seconds"):
        EmbeddingWorker(provider=_StubProvider(), interval_seconds=0, batch=5)


async def test_tick_prunes_then_embeds_and_returns_count(
    engine: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The worker's tick must prune orphaned vectors BEFORE embedding a batch (index-freshness
    # ordering, ADR-035 addendum) and return the embedded count. Isolate the orchestration by
    # monkeypatching the two batch functions the worker imported (run_embedding_batch is exercised
    # in test_concierge_embeddings).
    calls: list[str] = []

    async def _fake_prune(session: object) -> int:
        calls.append("prune")
        return 0

    async def _fake_run(session: object, *, provider: object, batch: int) -> int:
        calls.append("embed")
        assert batch == 5  # the configured batch is threaded through
        return 7

    monkeypatch.setattr("fathom.workers.embedding.prune_orphan_embeddings", _fake_prune)
    monkeypatch.setattr("fathom.workers.embedding.run_embedding_batch", _fake_run)

    embedded = await _worker().tick()
    assert embedded == 7
    assert calls == ["prune", "embed"]  # prune strictly before embed


async def test_loop_survives_a_failing_tick() -> None:
    # THE contract: a tick that raises (provider down, DB blip) is logged and retried next interval,
    # never killing the loop. Replace tick with one that raises the first time then records, run the
    # loop briefly, and assert it kept ticking past the failure.
    worker = _worker(interval=0.01)
    seen = 0
    second_ok = asyncio.Event()

    async def _flaky_tick() -> int:
        nonlocal seen
        seen += 1
        if seen == 1:
            raise RuntimeError("embedding provider unreachable")
        second_ok.set()
        return 0

    worker.tick = _flaky_tick  # type: ignore[method-assign]
    worker.start()
    try:
        await asyncio.wait_for(second_ok.wait(), timeout=2.0)  # a tick ran AFTER the raise
    finally:
        await worker.stop()
    assert seen >= 2  # survived the failure and kept going


async def test_start_is_idempotent_and_stop_is_safe() -> None:
    worker = _worker()
    await worker.stop()  # never started → no-op, no error
    worker.start()
    first = worker._task
    worker.start()  # second start is a no-op while the first is live
    assert worker._task is first
    await worker.stop()
    assert worker._task is None
    await worker.stop()  # double stop is safe


async def test_loop_stops_cleanly_on_cancel() -> None:
    # stop() cancels the loop and awaits teardown without surfacing CancelledError.
    worker = _worker(interval=10.0)  # long interval: the loop is parked in sleep when cancelled
    worker.start()
    await asyncio.sleep(0.01)
    await worker.stop()
    assert worker._task is None
