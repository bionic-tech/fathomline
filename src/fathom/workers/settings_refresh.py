"""Settings-store refresh worker (ADR-038) — cross-worker live reload of in-app overrides.

The worker that *writes* an override refreshes its own in-memory store immediately, but other API
workers/processes hold their own store. This periodic loop re-reads the DB override-set so a change
made anywhere converges everywhere within one interval — no restart. It is a thin stdlib-asyncio
scheduler (the owner ruling on background queues: no broker), mirroring :class:`RetentionWorker`.
A tick that raises is logged and swallowed so a transient DB blip never kills live reload.
"""

from __future__ import annotations

import asyncio
import contextlib

from fathom.core.db import session_scope
from fathom.core.settings_store import RuntimeSettingsStore
from fathom.logging import get_logger

_log = get_logger("fathom.workers.settings_refresh")

DEFAULT_INTERVAL_SECONDS = 15.0


class SettingsRefreshWorker:
    """A cancellable periodic task that reloads the settings store from the DB (live reload)."""

    def __init__(
        self,
        store: RuntimeSettingsStore,
        *,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._store = store
        self._interval = interval_seconds
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Launch the periodic refresh loop (idempotent — a second start is a no-op)."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(), name="settings-refresh")

    async def stop(self) -> None:
        """Cancel the loop and await its teardown (safe to call when never started)."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def tick(self) -> int:
        """Reload the store from the DB once; return the loaded override-set version."""
        async with session_scope() as session:
            await self._store.refresh(session)
        return self._store.version

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # a transient DB error must never kill live reload
                _log.exception("settings refresh tick failed; will retry next interval")
            await asyncio.sleep(self._interval)
