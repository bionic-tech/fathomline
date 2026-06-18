"""Preview render queue — bounded, stdlib-asyncio (ADR-014; preview-worker background work).

Per the owner ruling on background queues ("prefer a simple asyncio/arq-style queue; if adding
Redis/Valkey is heavy, use a stdlib asyncio queue — keep it testable and gate-green; document the
choice"), the preview render path uses a **stdlib ``asyncio`` bounded queue**, not arq/Valkey.

Rationale: the `/preview` route is request/response (the UI awaits the derived artifact), and the
expensive part is the per-render ``runsc`` container. A bounded :class:`asyncio.Semaphore` queue
caps how many sandbox renders run concurrently (the LibreOffice render is heavy — ADD 07 §5 flags
tighter rate limits) and shed-loads cleanly when saturated, all without a broker. The unit of work
(:meth:`PreviewQueue.submit`) is independently testable; a future move to arq/Valkey only swaps
this class.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from fathom.logging import get_logger
from fathom.preview.types import PreviewError, PreviewResult

_log = get_logger("fathom.workers.preview")


class PreviewQueue:
    """A bounded concurrency gate for sandbox renders (stdlib asyncio; no broker).

    ``max_concurrent`` caps simultaneous ``runsc`` renders (host-protection: each render is a CPU/
    memory-capped container, but unbounded concurrency would still exhaust the node). A submission
    that cannot acquire a slot before ``acquire_timeout`` is shed with a 503-class
    :class:`~fathom.preview.types.PreviewError` rather than queueing unboundedly (fail-fast under
    load; ADD 07 §5 tighter preview rate-limiting).
    """

    def __init__(self, *, max_concurrent: int = 2, acquire_timeout: float = 30.0) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        self._sema = asyncio.Semaphore(max_concurrent)
        self._acquire_timeout = acquire_timeout

    async def submit(
        self, render: Callable[[], Awaitable[tuple[PreviewResult, int]]]
    ) -> tuple[PreviewResult, int]:
        """Run ``render`` under the concurrency cap, shedding load if no slot frees in time.

        ``render`` is the bound render coroutine factory (the service call). The queue only gates
        concurrency; the render's own per-render caps (CPU/mem/time/pages) live in the sandbox.
        """
        try:
            await asyncio.wait_for(self._sema.acquire(), timeout=self._acquire_timeout)
        except TimeoutError as exc:
            _log.warning("preview queue saturated; shedding render")
            raise PreviewError("preview service busy", status_code=503) from exc
        try:
            return await render()
        finally:
            self._sema.release()
