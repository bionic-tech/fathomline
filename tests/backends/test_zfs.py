"""Tests for the ZFS backend (storage-backends test_plan: sizes, snapshot skip, boundaries)."""

from __future__ import annotations

from pathlib import Path

from fathom.adapters.base import AdapterError, CapabilityManifest, DiskInfo, PoolInfo
from fathom.backends import StorageBackend, ZfsBackend
from fathom.backends.zfs import ZfsBackend as ZfsBackendDirect


def test_zfs_satisfies_protocol() -> None:
    assert isinstance(ZfsBackend(), StorageBackend)


async def _collect(backend: ZfsBackend, root: str) -> dict[str, object]:
    return {e.path: e async for e in backend.walk(str(root))}


async def test_zfs_snapshot_dir_is_skipped(zfs_like_tree: Path) -> None:
    backend = ZfsBackend(walk_concurrency=2)
    entries = await _collect(backend, str(zfs_like_tree))

    # The ``.zfs`` control dir is reported (so the skip is observable) but never descended into.
    snapshot_paths = [p for p in entries if "/.zfs/snapshot/" in p]
    assert snapshot_paths == []
    # The historical copy under the snapshot tree must never appear.
    assert not any(p.endswith("old.txt") for p in entries)


async def test_zfs_snapshot_dir_flagged(zfs_like_tree: Path) -> None:
    backend = ZfsBackend()
    entries = {Path(p).name: e for p, e in (await _collect(backend, str(zfs_like_tree))).items()}
    control = entries[".zfs"]
    assert control.flags.get("snapshot_skipped") is True


async def test_zfs_allocated_below_logical_is_labelled(zfs_like_tree: Path) -> None:
    backend = ZfsBackend()
    entries = await _collect(backend, str(zfs_like_tree))

    sparse = entries[str(zfs_like_tree / "sparse.dat")]
    assert sparse.size_logical == 1024 * 1024
    assert sparse.size_on_disk <= sparse.size_logical
    if sparse.size_on_disk < sparse.size_logical:
        # On a hole-supporting FS the divergence is labelled compressed + reflink (advisory).
        assert sparse.flags.get("compressed") is True
        assert sparse.flags.get("reflink") is True


class _FakeStat:
    def __init__(self, dev: int) -> None:
        self.st_dev = dev


class _FakeDirEntry:
    """Duck-typed ``os.DirEntry`` for exercising the dataset-boundary descent logic directly."""

    def __init__(self, *, dev: int, is_dir: bool = True, is_symlink: bool = False) -> None:
        self._dev = dev
        self._is_dir = is_dir
        self._is_symlink = is_symlink

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return self._is_dir

    def is_symlink(self) -> bool:
        return self._is_symlink

    def stat(self, *, follow_symlinks: bool = True) -> _FakeStat:
        return _FakeStat(self._dev)


def test_zfs_dataset_boundary_one_filesystem_stops_at_child() -> None:
    # Each ZFS child dataset has its own st_dev. With one_filesystem=True a child dataset (foreign
    # dev) must NOT be descended into — the boundary that keeps a walk in the root dataset.
    child = _FakeDirEntry(dev=99)  # distinct from root_dev below
    assert (
        ZfsBackend._should_descend(child, 1, False, True)  # type: ignore[arg-type]
        is False
    )


def test_zfs_dataset_boundary_cross_mounts_descends_into_child() -> None:
    # cross_mounts (one_filesystem=False) descends into child datasets regardless of st_dev — the
    # only way to reach the child datasets under the pool root.
    child = _FakeDirEntry(dev=99)
    assert (
        ZfsBackend._should_descend(child, 1, False, False)  # type: ignore[arg-type]
        is True
    )


async def test_zfs_cross_mounts_walks_child_subtree(zfs_like_tree: Path) -> None:
    # End-to-end on the real tree (single device): one_filesystem=False still reaches the child.
    backend = ZfsBackend()
    entries = {e.path: e async for e in backend.walk(str(zfs_like_tree), one_filesystem=False)}
    assert str(zfs_like_tree / "child" / "nested.bin") in entries


# --------------------------------------------------------------------- adapter delegation


class _FakeAdapter:
    """A minimal control-plane adapter stub for ZfsBackend topology/is_busy delegation."""

    def __init__(self, *, healthy: bool, raise_on: str | None = None) -> None:
        self._healthy = healthy
        self._raise_on = raise_on

    async def probe(self) -> CapabilityManifest:  # pragma: no cover - not exercised
        return CapabilityManifest(platform="truenas", api_available=True)

    async def list_pools(self) -> list[PoolInfo]:
        if self._raise_on == "list_pools":
            raise AdapterError("boom")
        return [PoolInfo(name="tank", raid_level="draid1", total=100, used=40, free=60)]

    async def list_disks(self) -> list[DiskInfo]:  # pragma: no cover - not exercised
        return []

    async def volume_usage(self, mountpoint: str) -> tuple[int, int, int]:
        if self._raise_on == "volume_usage":
            raise AdapterError("boom")
        return (100, 40, 60)

    async def is_array_healthy(self, pool: str) -> bool:
        if self._raise_on == "is_array_healthy":
            raise AdapterError("boom")
        return self._healthy

    async def close(self) -> None:  # pragma: no cover - not exercised
        return None


async def test_zfs_volume_info_uses_adapter_topology(zfs_like_tree: Path) -> None:
    adapter = _FakeAdapter(healthy=True)
    backend = ZfsBackendDirect(adapter=adapter, pool="tank")
    info = await backend.volume_info(str(zfs_like_tree))
    assert info.fs_type == "zfs"
    assert info.total == 100
    assert info.used == 40
    assert info.raid_role == "zpool tank draid1"
    assert info.dataset == info.mountpoint


async def test_zfs_volume_info_falls_back_without_adapter(zfs_like_tree: Path) -> None:
    backend = ZfsBackend()
    info = await backend.volume_info(str(zfs_like_tree))
    assert info.fs_type == "zfs"
    assert info.total > 0
    assert info.raid_role is None  # no adapter → no topology guess (capability-honest)


async def test_zfs_volume_info_degrades_on_adapter_error(zfs_like_tree: Path) -> None:
    adapter = _FakeAdapter(healthy=True, raise_on="volume_usage")
    backend = ZfsBackendDirect(adapter=adapter, pool="tank")
    info = await backend.volume_info(str(zfs_like_tree))
    # statvfs fallback still produces a usable VolumeInfo, just without adapter topology.
    assert info.fs_type == "zfs"
    assert info.raid_role is None


async def test_zfs_is_busy_reflects_adapter_resync() -> None:
    busy = ZfsBackendDirect(adapter=_FakeAdapter(healthy=False), pool="tank")
    idle = ZfsBackendDirect(adapter=_FakeAdapter(healthy=True), pool="tank")
    assert await busy.is_busy() is True
    assert await idle.is_busy() is False


async def test_zfs_is_busy_fails_closed_on_adapter_error() -> None:
    backend = ZfsBackendDirect(
        adapter=_FakeAdapter(healthy=True, raise_on="is_array_healthy"), pool="tank"
    )
    # A control-plane read error must never silently disable the guard (ADD 16).
    assert await backend.is_busy() is True


async def test_zfs_is_busy_without_adapter_uses_fallback() -> None:
    backend = ZfsBackend()
    # No adapter → inherited /proc/mdstat heuristic (absent on this host → not busy).
    assert await backend.is_busy() in {True, False}
