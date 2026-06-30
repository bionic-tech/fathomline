"""Concierge embedding worker (ADR-035 Phase 2) — keeps path-name embeddings current.

A stdlib-``asyncio`` periodic loop (same shape as :class:`~fathom.workers.retention.RetentionWorker`
— no broker) that calls :func:`fathom.core.concierge.embeddings.run_embedding_batch` on an interval
to backfill + maintain the ``fs_entry_embedding`` table. Default-OFF: the API lifespan only starts
it when ``concierge_embeddings_enabled`` is set. Each tick embeds at most ``batch`` files, so the
one-time backfill drains in bounded steps and steady state tracks new files.
"""

from __future__ import annotations

import asyncio
import contextlib

from fathom.core.concierge.embeddings import prune_orphan_embeddings, run_embedding_batch
from fathom.core.db import session_scope
from fathom.inference.embeddings import EmbeddingProvider
from fathom.logging import get_logger

_log = get_logger("fathom.workers.embedding")


class EmbeddingWorker:
    """A cancellable periodic ``asyncio`` task that embeds not-yet-embedded files (stdlib only)."""

    def __init__(
        self,
        *,
        provider: EmbeddingProvider,
        interval_seconds: float,
        batch: int,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._provider = provider
        self._interval = interval_seconds
        self._batch = batch
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Launch the periodic embed loop (idempotent — a second start is a no-op)."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(), name="concierge-embedding")

    async def stop(self) -> None:
        """Cancel the loop and await its teardown (safe to call when never started)."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def tick(self) -> int:
        """Prune orphaned vectors, then embed one batch; return the count embedded.

        Prune-before-embed keeps the index fresh (ADR-035 addendum): deleted/renamed entries'
        vectors are dropped, then a bounded batch of new files is embedded.
        """
        async with session_scope() as session:
            await prune_orphan_embeddings(session)
            return await run_embedding_batch(
                session, provider=self._provider, batch=self._batch
            )

    async def _loop(self) -> None:
        while True:
            try:
                embedded = await self.tick()
                if embedded:
                    _log.info("embedding tick", extra={"embedded": embedded})
            except asyncio.CancelledError:
                raise
            except Exception:  # one failed batch must never kill the loop
                _log.exception("embedding tick failed; will retry next interval")
            await asyncio.sleep(self._interval)
