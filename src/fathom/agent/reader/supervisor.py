"""Adaptive load supervisor (ADD 02 §"Enforced throttling").

Samples host load and moves a running scan into ``Paused`` when a ceiling is crossed,
resuming only after load recovers below a *lower* threshold (hysteresis, so a scan can't
flap on and off at the boundary). Also enforces the hard rule that blocks full-bit scans
while a RAID array is resyncing/resilvering.

Load and resync providers are injectable so the decision logic is unit-testable without a
real ``/proc``. The defaults read ``os.getloadavg`` and ``/proc/mdstat``. The default resync
provider **fails closed**: an absent ``/proc/mdstat`` with no injected adapter is treated as
"cannot prove the array is idle" and *blocks* full-bit (ADD 16 — never a silent no-op).

The resync provider may be **sync** (the ``/proc/mdstat`` default) or **async** (an
:mod:`fathom.adapters` shim reading ``pool.status`` over the persistent control-plane session
— load-bearing on a pure-ZFS host, which has no ``/proc/mdstat``; ADD 04, AR-0002 §5). Use
:meth:`LoadSupervisor.should_block_fullbit_async` when an async provider is injected.
"""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import Awaitable, Callable
from pathlib import Path

from fathom.agent.config import ThrottleProfile
from fathom.logging import get_logger

_log = get_logger("fathom.agent.supervisor")

_RESYNC_MARKERS = ("resync", "recovery", "rebuild", "reshape", "check")

Load1Provider = Callable[[], float]
PercentProvider = Callable[[], float]
ResyncProvider = Callable[[], bool]
AsyncResyncProvider = Callable[[], Awaitable[bool]]
Sleeper = Callable[[float], Awaitable[None]]


def _default_load1() -> float:
    # ``os.getloadavg`` is Unix-only: on Windows it is *absent* (AttributeError), not merely
    # failing (OSError). Load average has no Windows equivalent, so there we degrade to 0.0 —
    # load-based pausing becomes a no-op (like iowait already is by default) rather than
    # crashing the scan. The CPU-percent proxy that would restore throttling on Windows is
    # ADR-027 W1 follow-up; until then the agent runs unthrottled there.
    getloadavg = getattr(os, "getloadavg", None)
    if getloadavg is None:  # Windows / any platform without loadavg
        return 0.0
    try:
        return float(getloadavg()[0])
    except OSError:  # pragma: no cover — platform with the symbol but no readable loadavg
        return 0.0


def _default_resync() -> bool:
    """Default (no-adapter) resync signal: read ``/proc/mdstat``, **failing closed**.

    Returns ``True`` (→ block full-bit) when an md array is resyncing/rebuilding. Crucially it
    also returns ``True`` when ``/proc/mdstat`` is **absent**: with no adapter injected and no
    mdstat there is no usable resync signal, so we cannot prove the backing array is idle and
    must refuse full-bit rather than silently allow it during a possible resilver (ADD 16 — the
    gate must never be a silent no-op; a pure-ZFS host has no ``/proc/mdstat``, AR-0002 §5).
    """
    try:
        text = Path("/proc/mdstat").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        # No mdstat and no adapter ⇒ no proof the array is safe ⇒ fail closed (block full-bit).
        return True
    return any(marker in text for marker in _RESYNC_MARKERS)


class LoadSupervisor:
    """Decides when a scan pauses and resumes, and whether full-bit is blocked."""

    def __init__(
        self,
        throttle: ThrottleProfile,
        *,
        load1_provider: Load1Provider = _default_load1,
        iowait_provider: PercentProvider | None = None,
        resync_provider: ResyncProvider | AsyncResyncProvider = _default_resync,
        sample_interval: float = 2.0,
        sleeper: Sleeper = asyncio.sleep,
    ) -> None:
        self._throttle = throttle
        self._load1 = load1_provider
        # iowait needs a /proc/stat delta to compute honestly; default to 0.0 (load-only
        # gating) until that sampler lands, rather than fabricating a number.
        self._iowait = iowait_provider or (lambda: 0.0)
        self._resync: ResyncProvider | AsyncResyncProvider = resync_provider
        self._resync_is_async = inspect.iscoroutinefunction(resync_provider)
        self._sample_interval = sample_interval
        self._sleep = sleeper
        self._paused = False

    @property
    def paused(self) -> bool:
        return self._paused

    def should_block_fullbit(self) -> bool:
        """True when a full-bit scan must not run because an array is resyncing (sync provider).

        Requires a **sync** resync provider; with an async (adapter-backed) provider, call
        :meth:`should_block_fullbit_async` instead — this raises rather than silently skip the
        guard (ADD 16: the gate must never be a silent no-op).
        """
        if not self._throttle.hard_rules.block_fullbit_during_raid_resync:
            return False
        if self._resync_is_async:
            raise RuntimeError(
                "resync provider is async; call should_block_fullbit_async() (ADD 04 adapter)"
            )
        resync = self._resync
        result = resync()
        assert isinstance(result, bool)  # noqa: S101 — sync provider contract (mypy narrowing)
        return result

    async def should_block_fullbit_async(self) -> bool:
        """Async-aware full-bit guard: awaits an adapter-backed resync provider when present.

        Works with either provider kind, so callers on the (async) scan path can always use
        this. The adapter shim feeds ``pool.status`` here — the only resync signal available on
        a pure-ZFS host (AR-0002 §5).
        """
        if not self._throttle.hard_rules.block_fullbit_during_raid_resync:
            return False
        resync = self._resync
        outcome = resync()
        if inspect.isawaitable(outcome):
            return bool(await outcome)
        return bool(outcome)

    async def wait_if_paused(self) -> None:
        """Block while host load is over the ceiling; return once it is safe to proceed.

        Idempotent and cheap to call between batches: if load is fine it returns at once.
        """
        while self._over_ceiling():
            if not self._paused:
                self._paused = True
                _log.warning(
                    "scan paused — host load over ceiling",
                    extra={
                        "load1": self._load1(),
                        "ceiling": self._throttle.pause_when.load1_above,
                    },
                )
            await self._sleep(self._sample_interval)
        if self._paused:
            self._paused = False
            _log.info("scan resumed — host load recovered", extra={"load1": self._load1()})

    def _over_ceiling(self) -> bool:
        load1 = self._load1()
        iowait = self._iowait()
        pause = self._throttle.pause_when
        resume = self._throttle.resume_when
        if iowait > pause.iowait_above_percent:
            return True
        if self._paused:
            # Stay paused until load drops below the (lower) resume threshold.
            return load1 >= resume.load1_below
        return load1 > pause.load1_above
