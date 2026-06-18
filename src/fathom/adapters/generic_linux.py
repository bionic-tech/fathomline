"""GenericLinuxAdapter — the CLI/sysfs control-plane fallback (ADD 04, explicit second choice).

When no vendor API is available (a generic server/PC, or a NAS whose API is unreachable), the
control plane is read from ``lsblk``, ``/proc/mdstat``, ``zpool status``, and ``statvfs`` —
the same heuristics the POSIX *data-plane* backend uses, kept consistent so the API-truth vs
CLI-parsing drift the fallback-parity test guards against stays visible (ADD 04 Testing
Strategy). ``manifest.api_available`` is always ``False`` here — this path is, by design, the
fallback (ADD 04).

Commands are run through an injectable ``runner`` so the parsers are unit-testable against
fixtures without a real host. Every shell-out is read-only (``lsblk``/``zpool status``/
``statvfs``); the adapter has no write surface (ADR-008, STRIDE T-4/E-5).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from collections.abc import Awaitable, Callable

from fathom.adapters.base import (
    Capability,
    CapabilityManifest,
    DiskInfo,
    PoolInfo,
    Transport,
)
from fathom.adapters.discovery import PlatformClass
from fathom.logging import get_logger

_log = get_logger("fathom.adapters.generic_linux")

# Capabilities the CLI fallback can honestly supply. No SMART by default (it needs root and a
# separate ``smartctl`` shell-out) — the capability-honest manifest simply omits it (ADD 04).
_GENERIC_PROVIDES: frozenset[Capability] = frozenset({"pools", "disks", "usage", "topology"})

# md-array resync markers, kept in lock-step with the supervisor/posix backend (ADD 02).
_RESYNC_MARKERS: tuple[str, ...] = ("resync", "recovery", "rebuild", "reshape", "check")

# lsblk transport tokens → our normalised vocabulary (mirrors the TrueNAS map).
_TRANSPORT_MAP: dict[str, Transport] = {
    "nvme": "nvme",
    "sata": "sata",
    "ata": "sata",
    "sas": "sas",
    "usb": "usb",
}

# An async "run this argv, return stdout text (or None on failure)" seam — injectable in tests.
CommandRunner = Callable[[list[str]], Awaitable[str | None]]


async def _default_runner(argv: list[str]) -> str | None:
    """Run ``argv`` read-only and return decoded stdout, or ``None`` if it is unavailable.

    Resolves the binary on ``PATH`` first so a missing tool is a clean ``None`` (clean
    per-capability fallback) rather than an exception, and never invokes a shell (no
    ``shell=True`` — argv only, defeating shell-injection by construction; S602/S603).
    """
    if shutil.which(argv[0]) is None:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return None
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        return None
    return stdout.decode("utf-8", errors="replace")


def _coerce_transport(raw: object) -> Transport:
    if isinstance(raw, str):
        return _TRANSPORT_MAP.get(raw.lower(), "unknown")
    return "unknown"


class GenericLinuxAdapter:
    """A read-only :class:`~fathom.adapters.base.PlatformAdapter` from lsblk/mdstat/zpool/statvfs.

    ``mdstat_text`` is injectable (defaults to reading ``/proc/mdstat``) so the md-array resync
    parsing is testable on hosts — like a pure-ZFS TrueNAS box — that have no ``/proc/mdstat``.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        mdstat_text: Callable[[], str | None] | None = None,
    ) -> None:
        self._run = runner or _default_runner
        self._mdstat = mdstat_text or _read_mdstat

    async def probe(self) -> CapabilityManifest:
        """Report the fallback manifest — ``api_available`` is always ``False`` (ADD 04)."""
        return CapabilityManifest(
            platform=PlatformClass.GENERIC_LINUX.value,
            api_available=False,
            provides=_GENERIC_PROVIDES,
            api_version=None,
        )

    async def list_pools(self) -> list[PoolInfo]:
        """Combine md-array (``/proc/mdstat``) and ZFS (``zpool status``) pools (read-only)."""
        pools: list[PoolInfo] = []
        pools.extend(self._parse_mdstat(self._mdstat() or ""))
        zpool = await self._run(["zpool", "status"])
        if zpool:
            pools.extend(self._parse_zpool_status(zpool))
        return pools

    async def list_disks(self) -> list[DiskInfo]:
        """Map ``lsblk -J -b -o ...`` disk rows to :class:`DiskInfo` frames (read-only)."""
        out = await self._run(["lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,ROTA,TRAN,TYPE"])
        if not out:
            return []
        try:
            doc = json.loads(out)
        except json.JSONDecodeError:
            _log.warning("lsblk output was not valid JSON; reporting no disks")
            return []
        disks: list[DiskInfo] = []
        for dev in doc.get("blockdevices", []) or []:
            if dev.get("type") != "disk":
                continue
            disks.append(
                DiskInfo(
                    name=str(dev.get("name", "")),
                    transport=_coerce_transport(dev.get("tran")),
                    size=int(dev.get("size", 0) or 0),
                    rotational=bool(dev.get("rota")),
                    smart_status=None,  # not provided by the CLI fallback (capability-honest)
                    pool_or_array=None,
                )
            )
        return disks

    async def volume_usage(self, mountpoint: str) -> tuple[int, int, int]:
        """Return ``(total, used, free)`` for ``mountpoint`` via ``statvfs`` (off the loop)."""
        stat = await asyncio.to_thread(os.statvfs, mountpoint)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
        return total, used, free

    async def is_array_healthy(self, pool: str) -> bool:
        """Return ``False`` while ``pool`` is resyncing — gates full-bit scans (ADD 02, 16)."""
        for info in await self.list_pools():
            if info.name == pool:
                return not info.resyncing
        # Unknown pool on the fallback path: be permissive only when there is genuinely no array
        # to gate (no md/zpool pools found at all); otherwise fail-closed (ADD 16).
        pools = await self.list_pools()
        if not pools:
            return True
        _log.warning("is_array_healthy: pool not found, failing closed", extra={"pool": pool})
        return False

    async def close(self) -> None:
        """No persistent session to release (the CLI path is stateless)."""
        return None

    # ----------------------------------------------------------------- parsers

    @staticmethod
    def _parse_mdstat(text: str) -> list[PoolInfo]:
        """Parse ``/proc/mdstat`` into md-array pools, flagging an in-flight resync.

        A resync/recovery line (``[===>...]  recovery = ...``) sets ``resyncing=True`` for the
        array it follows — the load-bearing signal for the RAID5 gate on node-1 (AR-0002).
        """
        pools: list[PoolInfo] = []
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            match = re.match(r"^(md\d+)\s*:\s*active\s+(\S+)\s+(.*)$", line)
            if not match:
                continue
            name, raid_level, rest = match.group(1), match.group(2), match.group(3)
            members = [tok.split("[")[0] for tok in rest.split() if tok and tok[0].isalpha()]
            window = " ".join(lines[idx : idx + 3]).lower()
            resyncing = any(marker in window for marker in _RESYNC_MARKERS)
            pools.append(
                PoolInfo(name=name, raid_level=raid_level, members=members, resyncing=resyncing)
            )
        return pools

    @staticmethod
    def _parse_zpool_status(text: str) -> list[PoolInfo]:
        """Parse ``zpool status`` into ZFS pools, flagging an active resilver (not DEGRADED).

        DEGRADED-but-not-resilvering (the node-0 nextcloud evidence, AR-0002 §5) is unhealthy but
        does **not** set ``resyncing`` — only an in-flight ``scan: resilver in progress`` does,
        matching the TrueNAS adapter's discrimination so the guard fires identically.
        """
        pools: list[PoolInfo] = []
        current: str | None = None
        resyncing = False
        for line in text.splitlines():
            pool_match = re.match(r"^\s*pool:\s+(\S+)", line)
            if pool_match:
                if current is not None:
                    pools.append(PoolInfo(name=current, resyncing=resyncing))
                current, resyncing = pool_match.group(1), False
                continue
            if current is not None and "resilver in progress" in line.lower():
                resyncing = True
        if current is not None:
            pools.append(PoolInfo(name=current, resyncing=resyncing))
        return pools


def _read_mdstat() -> str | None:
    from pathlib import Path

    try:
        return Path("/proc/mdstat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None  # pure-ZFS hosts have no /proc/mdstat — clean None, not a crash
