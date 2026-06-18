"""Bridge an adapter's pool health into the LoadSupervisor's resync guard (ADD 04 → ADD 02).

The full-bit scan guard (ADD 02, ADD 16) keys on "is an array resyncing?". The default reads
``/proc/mdstat`` — which is **absent on a pure-ZFS host**, making the guard a silent no-op on
the primary data host (AR-0002 §5, and the load-bearing reason this adapter exists). When an
API adapter is present, the resync state must instead come from ``pool.status`` via the
adapter's :meth:`~fathom.adapters.base.PlatformAdapter.is_array_healthy`.

The supervisor's resync provider is an **async** callable (``AsyncResyncProvider``); this shim
adapts an adapter + pool name into one. It fails **closed**: any adapter error during the check
is treated as "an array might be resyncing" so the guard errs toward *blocking* a full-bit scan
rather than running one during a possible resilver (ADD 16 hard rule).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fathom.adapters.base import AdapterError, PlatformAdapter
from fathom.logging import get_logger

_log = get_logger("fathom.adapters.resync")


def adapter_resync_provider(adapter: PlatformAdapter, pool: str) -> Callable[[], Awaitable[bool]]:
    """Return an async ``() -> bool`` reporting whether ``pool`` is resyncing (fail-closed).

    Suitable for ``LoadSupervisor(resync_provider=...)``. Returns ``True`` (resyncing → block
    full-bit) when the adapter reports the array unhealthy *or* when the adapter call fails —
    a control-plane read error must never silently disable the safety gate (ADD 16).
    """

    async def _resyncing() -> bool:
        try:
            healthy = await adapter.is_array_healthy(pool)
        except AdapterError:
            _log.warning(
                "resync check failed; failing closed (treat as resyncing)",
                extra={"pool": pool},
            )
            return True
        return not healthy

    return _resyncing
