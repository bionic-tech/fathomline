"""Tests for the adaptive load supervisor — pause/resume hysteresis & resync guard."""

from __future__ import annotations

from pathlib import Path

import pytest

from fathom.adapters.base import CapabilityManifest, DiskInfo, PoolInfo
from fathom.adapters.resync import adapter_resync_provider
from fathom.agent.config import ThrottleProfile
from fathom.agent.reader import LoadSupervisor
from fathom.agent.reader import supervisor as _sup_mod
from fathom.agent.reader.supervisor import _default_load1, _default_resync


def _throttle(*, block_fullbit: bool = True) -> ThrottleProfile:
    return ThrottleProfile.model_validate(
        {
            "pause_when": {"load1_above": 6.0, "iowait_above_percent": 25},
            "resume_when": {"load1_below": 3.0},
            "hard_rules": {"block_fullbit_during_raid_resync": block_fullbit},
        }
    )


async def test_no_pause_when_load_low() -> None:
    sup = LoadSupervisor(_throttle(), load1_provider=lambda: 1.0)
    await sup.wait_if_paused()
    assert sup.paused is False


async def test_pauses_then_resumes_with_hysteresis() -> None:
    # Hysteresis: once paused at 7.0 it stays paused at 4.0 (between resume=3.0 and
    # pause=6.0) and only resumes once load drops below the resume threshold (3.0).
    state = {"load": 7.0}
    later = iter([4.0, 2.0])
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        state["load"] = next(later)

    sup = LoadSupervisor(_throttle(), load1_provider=lambda: state["load"], sleeper=fake_sleep)
    await sup.wait_if_paused()
    assert sup.paused is False
    assert len(sleeps) == 2  # slept through 7.0 and 4.0, resumed at 2.0


async def test_resync_blocks_fullbit() -> None:
    sup = LoadSupervisor(_throttle(), resync_provider=lambda: True)
    assert sup.should_block_fullbit() is True


async def test_resync_guard_can_be_disabled() -> None:
    sup = LoadSupervisor(_throttle(block_fullbit=False), resync_provider=lambda: True)
    assert sup.should_block_fullbit() is False


def test_default_resync_fails_closed_when_mdstat_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Pure-ZFS host (no /proc/mdstat) with no adapter injected: the default provider has no
    # usable resync signal and must fail closed (report "resyncing" → block full-bit), not
    # silently return False (AR-0002 §5, ADD 16).
    def _no_mdstat(self: Path, **_: object) -> str:
        raise FileNotFoundError(self)

    monkeypatch.setattr(Path, "read_text", _no_mdstat)
    assert _default_resync() is True


def test_default_load1_returns_zero_when_loadavg_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows has no os.getloadavg at all (AttributeError, not OSError). The default load
    # provider must degrade to 0.0 there — load-based pausing becomes a no-op — rather than
    # crashing the scan with AttributeError (native Windows agent, ADR-027 W1).
    monkeypatch.delattr(_sup_mod.os, "getloadavg", raising=False)
    assert _default_load1() == 0.0


def test_default_load1_returns_zero_when_loadavg_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # A platform that has the symbol but cannot read loadavg (OSError) also degrades to 0.0.
    def _boom() -> tuple[float, float, float]:
        raise OSError("loadavg unavailable")

    monkeypatch.setattr(_sup_mod.os, "getloadavg", _boom, raising=False)
    assert _default_load1() == 0.0


async def test_no_mdstat_no_adapter_blocks_fullbit(monkeypatch: pytest.MonkeyPatch) -> None:
    # End-to-end on the default wiring: no mdstat + no adapter ⇒ should_block_fullbit() is True
    # (full-bit refused — we cannot prove the array is idle).
    def _no_mdstat(self: Path, **_: object) -> str:
        raise FileNotFoundError(self)

    monkeypatch.setattr(Path, "read_text", _no_mdstat)
    sup = LoadSupervisor(_throttle())  # default _default_resync provider
    assert sup.should_block_fullbit() is True


class _StubAdapter:
    """Minimal in-process PlatformAdapter reporting a single, healthy (idle) pool."""

    def __init__(self, *, healthy: bool) -> None:
        self._healthy = healthy

    async def probe(self) -> CapabilityManifest:
        return CapabilityManifest(platform="generic-linux", api_available=True)

    async def list_pools(self) -> list[PoolInfo]:
        return [PoolInfo(name="tank", resyncing=not self._healthy)]

    async def list_disks(self) -> list[DiskInfo]:
        return []

    async def volume_usage(self, mountpoint: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    async def is_array_healthy(self, pool: str) -> bool:
        return self._healthy

    async def close(self) -> None:
        return None


async def test_adapter_present_and_idle_allows_fullbit() -> None:
    # Adapter injected and the pool is idle/healthy: the async guard reads pool.status via the
    # adapter shim and allows full-bit (no /proc/mdstat involved).
    sup = LoadSupervisor(
        _throttle(),
        resync_provider=adapter_resync_provider(_StubAdapter(healthy=True), "tank"),
    )
    assert await sup.should_block_fullbit_async() is False


async def test_adapter_present_and_resilvering_blocks_fullbit() -> None:
    sup = LoadSupervisor(
        _throttle(),
        resync_provider=adapter_resync_provider(_StubAdapter(healthy=False), "tank"),
    )
    assert await sup.should_block_fullbit_async() is True


async def test_iowait_ceiling_pauses() -> None:
    sleeps: list[float] = []
    state = {"iowait": 80.0}

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        state["iowait"] = 0.0  # recover after one sample

    sup = LoadSupervisor(
        _throttle(),
        load1_provider=lambda: 1.0,
        iowait_provider=lambda: state["iowait"],
        sleeper=fake_sleep,
    )
    await sup.wait_if_paused()
    assert sleeps == [2.0]
    assert sup.paused is False
