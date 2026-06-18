"""GenericLinuxAdapter: fallback manifest, mdstat/zpool resync parsing, and API-parity.

The CLI/sysfs fallback (ADD 04) is exercised with injected command output so the parsers are
deterministic. The parity test guards against API-truth vs CLI-parsing drift (ADD 04 Testing
Strategy); the mdstat tests pin the load-bearing RAID5 resync signal on node-1 (AR-0002).
"""

from __future__ import annotations

import json

from fathom.adapters.generic_linux import GenericLinuxAdapter

_LSBLK = json.dumps(
    {
        "blockdevices": [
            {
                "name": "nvme0n1",
                "size": 2_000_000_000_000,
                "rota": False,
                "tran": "nvme",
                "type": "disk",
            },
            {
                "name": "sda",
                "size": 8_000_000_000_000,
                "rota": True,
                "tran": "sata",
                "type": "disk",
            },
            {"name": "sr0", "size": 0, "rota": True, "tran": "usb", "type": "rom"},
        ]
    }
)

_MDSTAT_HEALTHY = (
    "Personalities : [raid6] [raid5] [raid4]\n"
    "md127 : active raid5 sdb[0] sdc[1] sdd[2]\n"
    "      14650670720 blocks super 1.2 level 5 [3/3] [UUU]\n"
    "      bitmap: 0/15 pages [0KB], 65536KB chunk\n"
)

_MDSTAT_RESYNCING = (
    "md127 : active raid5 sdb[0] sdc[1] sdd[2](S)\n"
    "      14650670720 blocks super 1.2 level 5 [3/2] [UU_]\n"
    "      [==>..................]  recovery = 12.3% (1801/14650) finish=99.9min\n"
)

_ZPOOL_DEGRADED = (
    "  pool: nextcloud\n"
    " state: DEGRADED\n"
    "status: One or more devices has experienced an error.\n"
    "  scan: resilvered 2.3T in 04:12:33 with 40 errors on Sep 1 2025\n"
)

_ZPOOL_RESILVERING = (
    "  pool: tank\n state: ONLINE\n  scan: resilver in progress since Mon Jun  2 00:00:00 2026\n"
)


def _adapter(
    *, lsblk: str | None = _LSBLK, zpool: str | None = None, mdstat: str | None = None
) -> GenericLinuxAdapter:
    async def runner(argv: list[str]) -> str | None:
        if argv[0] == "lsblk":
            return lsblk
        if argv[0] == "zpool":
            return zpool
        return None

    return GenericLinuxAdapter(runner=runner, mdstat_text=lambda: mdstat)


async def test_manifest_api_unavailable() -> None:
    manifest = await _adapter().probe()
    assert manifest.platform == "generic-linux"
    assert manifest.api_available is False
    assert "smart" not in manifest.provides  # capability-honest: CLI fallback omits SMART


async def test_list_disks_skips_non_disks_and_maps_transport() -> None:
    disks = {d.name: d for d in await _adapter().list_disks()}
    assert set(disks) == {"nvme0n1", "sda"}  # sr0 (rom) skipped
    assert disks["nvme0n1"].transport == "nvme"
    assert disks["nvme0n1"].rotational is False
    assert disks["sda"].transport == "sata"
    assert disks["sda"].smart_status is None


async def test_mdstat_healthy_not_resyncing() -> None:
    pools = {p.name: p for p in await _adapter(mdstat=_MDSTAT_HEALTHY).list_pools()}
    assert pools["md127"].resyncing is False
    assert pools["md127"].raid_level == "raid5"
    assert await _adapter(mdstat=_MDSTAT_HEALTHY).is_array_healthy("md127") is True


async def test_mdstat_resync_in_progress_blocks() -> None:
    adapter = _adapter(mdstat=_MDSTAT_RESYNCING)
    pools = {p.name: p for p in await adapter.list_pools()}
    assert pools["md127"].resyncing is True
    assert await adapter.is_array_healthy("md127") is False


async def test_missing_mdstat_is_not_a_crash() -> None:
    # A pure-ZFS host has no /proc/mdstat; the adapter must report no md pools, not error.
    adapter = _adapter(mdstat=None)
    pools = await adapter.list_pools()
    assert all(not p.name.startswith("md") for p in pools)


async def test_zpool_degraded_not_resilvering_is_clean() -> None:
    adapter = _adapter(zpool=_ZPOOL_DEGRADED)
    pools = {p.name: p for p in await adapter.list_pools()}
    assert pools["nextcloud"].resyncing is False  # DEGRADED but not resyncing (AR-0002 §5)


async def test_zpool_resilvering_is_detected() -> None:
    adapter = _adapter(zpool=_ZPOOL_RESILVERING)
    pools = {p.name: p for p in await adapter.list_pools()}
    assert pools["tank"].resyncing is True
    assert await adapter.is_array_healthy("tank") is False


async def test_unknown_pool_with_no_arrays_is_permissive() -> None:
    # No md and no zpool output → nothing to gate → healthy (don't block on a host with no RAID).
    adapter = _adapter(lsblk=_LSBLK, zpool=None, mdstat=None)
    assert await adapter.is_array_healthy("anything") is True


async def test_fallback_parity_disk_shape_matches_api_vocabulary() -> None:
    # Catch CLI-vs-API drift: the fallback's disk transport vocabulary must be the same set the
    # API adapter normalises to (ADD 04 Testing Strategy).
    disks = await _adapter().list_disks()
    assert {d.transport for d in disks} <= {"nvme", "sata", "sas", "usb", "unknown"}
