"""The reusable adapter conformance suite — every adapter must pass it (ADD 04 Testing Strategy).

Both the API-backed ``TrueNASAdapter`` (driven by the fake JSON-RPC transport) and the
``GenericLinuxAdapter`` (driven by a fixture command runner) are exercised through the *same*
shape assertions: probe → manifest, well-shaped pools/disks, ``(total, used, free)`` usage, and
a ``bool`` health contract. A community adapter proves itself by passing this file unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from fathom.adapters import (
    CapabilityManifest,
    DiskInfo,
    GenericLinuxAdapter,
    PlatformAdapter,
    PoolInfo,
    TrueNASAdapter,
)
from fathom.adapters.config import AdapterConfig
from fathom.adapters.discovery import PlatformClass
from tests.adapters.conftest import FakeJsonRpcTransport

_MDSTAT_HEALTHY = "md127 : active raid5 sdb[0] sdc[1] sdd[2]\n      14650670720 blocks [UUU]\n"


def _truenas() -> TrueNASAdapter:
    config = AdapterConfig.model_validate(
        {
            "platform": "truenas",
            "endpoint": "wss://nas.example.test/api/current",
            "api_key_ref": "FATHOM_TRUENAS_KEY",
            "endpoint_allowlist": ["nas.example.test"],
        }
    )
    return TrueNASAdapter(
        config, secret_provider=lambda _ref: "secret-key", transport=FakeJsonRpcTransport()
    )


def _generic() -> GenericLinuxAdapter:
    async def runner(argv: list[str]) -> str | None:
        if argv[0] == "lsblk":
            return json.dumps(
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
                    ]
                }
            )
        if argv[0] == "zpool":
            return "  pool: tank\n state: ONLINE\n"
        return None

    return GenericLinuxAdapter(runner=runner, mdstat_text=lambda: _MDSTAT_HEALTHY)


# A factory per adapter so each test gets a fresh instance (no shared transport state).
ADAPTER_FACTORIES: list[Callable[[], PlatformAdapter]] = [_truenas, _generic]


@pytest.fixture(params=ADAPTER_FACTORIES, ids=["truenas", "generic-linux"])
def adapter(request: pytest.FixtureRequest) -> PlatformAdapter:
    factory: Callable[[], PlatformAdapter] = request.param
    return factory()


def test_all_factories_satisfy_protocol() -> None:
    for factory in ADAPTER_FACTORIES:
        assert isinstance(factory(), PlatformAdapter)


async def test_probe_returns_manifest(adapter: PlatformAdapter) -> None:
    manifest = await adapter.probe()
    assert isinstance(manifest, CapabilityManifest)
    assert manifest.platform in {p.value for p in PlatformClass}
    assert isinstance(manifest.provides, frozenset)
    assert {"pools", "disks"} <= set(manifest.provides)


async def test_list_pools_well_shaped(adapter: PlatformAdapter) -> None:
    pools = await adapter.list_pools()
    assert isinstance(pools, list)
    for pool in pools:
        assert isinstance(pool, PoolInfo)
        assert isinstance(pool.name, str) and pool.name
        assert isinstance(pool.resyncing, bool)


async def test_list_disks_well_shaped(adapter: PlatformAdapter) -> None:
    disks = await adapter.list_disks()
    assert isinstance(disks, list)
    for disk in disks:
        assert isinstance(disk, DiskInfo)
        assert disk.transport in {"nvme", "sata", "sas", "usb", "unknown"}
        assert disk.size >= 0


async def test_is_array_healthy_returns_bool(adapter: PlatformAdapter) -> None:
    pools = await adapter.list_pools()
    target = pools[0].name if pools else "does-not-exist"
    result = await adapter.is_array_healthy(target)
    assert isinstance(result, bool)


async def test_close_is_idempotent(adapter: PlatformAdapter) -> None:
    await adapter.close()
    await adapter.close()  # second close must not raise


async def test_volume_usage_returns_triple(
    adapter: PlatformAdapter, tmp_path_factory: pytest.TempPathFactory
) -> None:
    # TrueNAS resolves a dataset mountpoint from the fixture; generic uses real statvfs.
    if isinstance(adapter, TrueNASAdapter):
        total, used, free = await adapter.volume_usage("/mnt/tank/Docker")
    else:
        total, used, free = await adapter.volume_usage(str(tmp_path_factory.getbasetemp()))
    assert isinstance(total, int) and isinstance(used, int) and isinstance(free, int)
    assert total >= 0 and used >= 0 and free >= 0
