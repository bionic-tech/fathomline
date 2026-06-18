"""Change-log retention worker — caps the churn feed at its retention window (ADR-006, ADD 24).

The ``change_log`` feed is "ENABLED per-volume; retention-capped" (ADD 09 §2) at 90 days
(incremental owner ruling). This worker prunes rows past the window so the feed stays bounded at
estate scale.

Per the owner ruling on background queues ("a stdlib asyncio queue if adding Redis is heavy —
keep it testable and gate-green; document the choice"), this is a **stdlib-asyncio periodic loop**
— no Redis/Valkey, no arq broker. The single-prune body (:func:`run_retention`) is the unit of
work and is independently testable against a DB session; :class:`RetentionWorker` is the thin
``asyncio``-task scheduler that calls it on an interval and can be cancelled cleanly on shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib

from fathom.core.db import session_scope
from fathom.core.incremental import CHANGE_LOG_RETENTION_DAYS, prune_change_log
from fathom.logging import get_logger

_log = get_logger("fathom.workers.retention")

# Default cadence: prune once a day. The window (90d) is far larger than the cadence, so an
# occasional missed tick (restart) never loses retention correctness — the next tick catches up.
DEFAULT_INTERVAL_SECONDS = 24 * 60 * 60


async def run_retention(*, retention_days: int = CHANGE_LOG_RETENTION_DAYS) -> int:
    """Prune churn rows past ``retention_days`` in a fresh transaction; return rows removed.

    The single source of truth for "prune the change_log", shared by the scheduled worker and any
    inline/admin invocation. Opens its own transaction and commits (read-modify-delete only).
    """
    async with session_scope() as session:
        removed = await prune_change_log(session, retention_days=retention_days)
    return removed


class RetentionWorker:
    """A cancellable periodic ``asyncio`` task that prunes the change_log (stdlib, no broker).

    Start with :meth:`start` (e.g. from the API lifespan) and stop with :meth:`stop`. Each tick
    runs :func:`run_retention`; a tick that raises is logged and swallowed so one failed prune
    never kills the loop (the next tick retries). Cadence and retention are injectable for tests.
    """

    def __init__(
        self,
        *,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        retention_days: int = CHANGE_LOG_RETENTION_DAYS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._interval = interval_seconds
        self._retention_days = retention_days
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Launch the periodic prune loop (idempotent — a second start is a no-op)."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(), name="change-log-retention")

    async def stop(self) -> None:
        """Cancel the loop and await its teardown (safe to call when never started)."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def tick(self) -> int:
        """Run a single prune now (exposed for tests / an admin 'prune now')."""
        return await run_retention(retention_days=self._retention_days)

    async def _loop(self) -> None:
        while True:
            try:
                removed = await self.tick()
                if removed:
                    _log.info("retention tick pruned change_log", extra={"removed": removed})
            except asyncio.CancelledError:
                raise
            except Exception:  # one failed prune must never kill the loop
                _log.exception("retention tick failed; will retry next interval")
            await asyncio.sleep(self._interval)
