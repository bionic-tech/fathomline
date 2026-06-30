"""Proactive watch worker (ADR-040) — periodically re-assess the estate and post to the bell.

A stdlib-asyncio periodic loop (mirroring :class:`RetentionWorker`; no broker). Each tick reads the
**effective** settings (so threshold/interval changes are live), self-gates on ``watch_enabled`` +
``notifications_enabled``, runs the watch rules (`core/watch.evaluate`), and raises each alert via
`emit_and_dispatch` — bell row + outbound channels (ADR-039), coalesced on the alert's dedup key. A
tick that raises is logged and swallowed so one failed sweep never kills the loop. The worker is
always scheduled; the gate lives in the tick, so enabling/disabling the watcher needs no restart.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable

from fathom.core import watch
from fathom.core.db import session_scope
from fathom.core.notify import emit_and_dispatch
from fathom.core.notify.channels import SecretProvider
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.workers.watch")

DEFAULT_INTERVAL_SECONDS = 60 * 60


class WatchWorker:
    """A cancellable periodic task that raises proactive estate alerts into the bell."""

    def __init__(
        self,
        settings_provider: Callable[[], Settings],
        secret_provider: SecretProvider,
    ) -> None:
        self._settings = settings_provider
        self._secret_provider = secret_provider
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Launch the periodic watch loop (idempotent — a second start is a no-op)."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(), name="proactive-watch")

    async def stop(self) -> None:
        """Cancel the loop and await its teardown (safe to call when never started)."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def tick(self) -> int:
        """Run one assessment now; return how many alerts were raised (0 when gated off)."""
        settings = self._settings()
        if not (settings.watch_enabled and settings.notifications_enabled):
            return 0
        async with session_scope() as session:
            alerts = await watch.evaluate(session, settings)
            for alert in alerts:
                await emit_and_dispatch(
                    session,
                    settings,
                    self._secret_provider,
                    category=alert.category,
                    title=alert.title,
                    source=alert.source,
                    body=alert.body,
                    severity=alert.severity,
                    host_id=alert.host_id,
                    volume_id=alert.volume_id,
                    dedup_key=alert.dedup_key,
                )
        if alerts:
            _log.info("watch tick raised alerts", extra={"count": len(alerts)})
        return len(alerts)

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # one failed sweep must never kill the loop
                _log.exception("watch tick failed; will retry next interval")
            await asyncio.sleep(self._settings().watch_interval_seconds)
