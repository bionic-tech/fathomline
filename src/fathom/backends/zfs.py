"""ZFS storage backend — logical-vs-allocated size, snapshot skip, dataset boundaries (ADR-004).

ZFS hides three truths a generic POSIX walk gets wrong, which this backend surfaces honestly
(ADD 02 §"Backend-specific truths", ADD 04):

* **Logical vs allocated size.** Compression and block sharing mean ``st_size`` (logical) and
  ``st_blocks * 512`` (post-compression *allocated*) diverge. Both are already carried on
  :class:`~fathom.backends.base.FsEntry`; this backend additionally *labels* the divergence —
  ``flags["compressed"]`` when on-disk < logical for a regular file (compression or sharing),
  ``flags["reflink"]`` when the same block sharing makes on-disk an under-count of unique bytes.
  Per-pool *usage* still comes from the adapter (``zpool``/``pool.status``), never summed entries
  — summing per-file allocated bytes double-counts shared blocks (risks §allocated-vs-logical).
* **The ``.zfs/snapshot`` control directory.** Walking into it re-expands every snapshot of the
  dataset — a combinatorial explosion of read-only historical copies. It is reported once (so the
  skip is observable, ``flags["snapshot_skipped"]``) and never descended into.
* **Dataset boundaries.** Each ZFS child dataset is its own filesystem with a distinct
  ``st_dev``, so ``one_filesystem=True`` (the default) keeps a pool-root walk inside the root
  dataset, and ``cross_mounts=True`` (``one_filesystem=False``) descends into the child datasets
  — e.g. dozens of child datasets under a single pool root.
  This reuses the inherited POSIX ``st_dev`` descent check unchanged.

Topology and the resilver/resync state are **control-plane** truth (ADR-008, ADD 04): when a
:class:`~fathom.adapters.base.PlatformAdapter` is supplied, ``volume_info`` takes the dataset
name / pool capacity / raid_role from it and ``is_busy`` reflects its resilver state (the only
resync signal on a pure-ZFS host with no ``/proc/mdstat`` — AR-0002). With no adapter the backend
degrades cleanly to ``statvfs`` + the inherited ``/proc/mdstat``/``zpool status`` heuristics.
"""

from __future__ import annotations

import os
from pathlib import Path

from fathom.adapters.base import AdapterError, PlatformAdapter
from fathom.backends.base import VolumeInfo
from fathom.backends.posix import DEFAULT_WALK_CONCURRENCY, PosixBackend
from fathom.logging import get_logger

_log = get_logger("fathom.backends.zfs")

# The ZFS snapshot control path segment. ``<dataset>/.zfs/snapshot/<snap>/...`` exposes every
# snapshot as a read-only tree; walking in re-reads the whole history, so the ``snapshot`` dir
# under a ``.zfs`` control dir is pruned (ADD 02 §"skip .zfs/snapshot").
_ZFS_CONTROL_DIR = ".zfs"
_SNAPSHOT_DIR = "snapshot"


class ZfsBackend(PosixBackend):
    """A ZFS-aware :class:`~fathom.backends.base.StorageBackend` (structural conformance).

    Reuses the POSIX worker-pool walk verbatim — the entire point of the ADR-004 Protocol
    boundary is that ZFS needs no new walker — and overrides only the four ZFS-specific seams:
    ``supports`` (fs_type detection), ``_skip_subdir`` (snapshot prune), ``_annotate_flags``
    (compression/reflink labelling), and ``volume_info``/``is_busy`` (adapter delegation).
    """

    def __init__(
        self,
        *,
        walk_concurrency: int = DEFAULT_WALK_CONCURRENCY,
        adapter: PlatformAdapter | None = None,
        pool: str | None = None,
    ) -> None:
        super().__init__(walk_concurrency=walk_concurrency)
        self._adapter = adapter
        self._pool = pool

    def supports(self, mountpoint: str) -> bool:
        """True when ``mountpoint`` is backed by a ZFS filesystem (``/proc/mounts`` fs type)."""
        real = os.path.realpath(mountpoint)
        if not Path(real).is_dir():
            return False
        _device, fs_type = self._resolve_mount(real)
        return fs_type == "zfs"

    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        """Report ZFS capacity + topology, preferring the control-plane adapter (ADD 04).

        Capacity, ``dataset``, ``raid_role``, and the SATA/NVMe ``transport`` class come from the
        :class:`~fathom.adapters.base.PlatformAdapter` when one is wired (its API/CLI is
        authoritative for pool→vdev→disk topology, ADD 04). Without an adapter — or if the adapter
        read fails — it falls back to the inherited ``statvfs``-based info with ``transport`` left
        ``unknown`` and ``dataset`` set to the resolved mount, never guessing topology it cannot
        confirm (capability-honest, AR-027).
        """
        info = await super().volume_info(mountpoint)
        # The POSIX fallback may report fs_type via /proc/mounts; force the ZFS truth we matched on.
        info = info.model_copy(update={"fs_type": "zfs", "dataset": info.mountpoint})
        if self._adapter is None or self._pool is None:
            return info
        try:
            total, used, free = await self._adapter.volume_usage(info.mountpoint)
            pools = await self._adapter.list_pools()
        except AdapterError:
            _log.warning(
                "zfs adapter volume_info failed; using statvfs fallback",
                extra={"mountpoint": info.mountpoint, "pool": self._pool},
            )
            return info
        raid_role: str | None = None
        for pool in pools:
            if pool.name == self._pool:
                raid_role = self._raid_role(pool.name, pool.raid_level)
                break
        return info.model_copy(
            update={
                "total": total,
                "used": used,
                "free": free,
                "raid_role": raid_role,
                "dataset": info.mountpoint,
            }
        )

    async def is_busy(self) -> bool:
        """Reflect the pool's resilver state from the adapter, fail-closed (ADD 02, ADD 16).

        On a pure-ZFS host there is no ``/proc/mdstat``, so the inherited heuristic is a silent
        no-op (AR-0002). When an adapter + pool are wired, the resilver state is authoritative:
        an unhealthy (resilvering) pool — or an adapter read error — returns ``True`` so a
        full-bit scan is blocked rather than running during a possible resilver (fail-closed).
        With no adapter it falls back to the inherited ``/proc/mdstat``/``zpool`` check.
        """
        if self._adapter is None or self._pool is None:
            return await super().is_busy()
        try:
            healthy = await self._adapter.is_array_healthy(self._pool)
        except AdapterError:
            _log.warning(
                "zfs is_busy adapter check failed; failing closed (treat as resyncing)",
                extra={"pool": self._pool},
            )
            return True
        return not healthy

    # ----------------------------------------------------------------- internals

    def _skip_subdir(self, path: str, name: str) -> bool:
        """Prune the ``.zfs/snapshot`` control tree (reported once, never descended into)."""
        return self._is_snapshot_dir(path, name)

    @staticmethod
    def _is_snapshot_dir(path: str, name: str) -> bool:
        """True for a ``.zfs/snapshot`` directory — the snapshot control tree to skip."""
        parts = Path(path).parts
        if name == _SNAPSHOT_DIR and len(parts) >= 2 and parts[-2] == _ZFS_CONTROL_DIR:
            return True
        # Also skip the ``.zfs`` control root itself (its only child is ``snapshot``/``shares``).
        return name == _ZFS_CONTROL_DIR

    def _annotate_flags(
        self,
        flags: dict[str, bool],
        path: str,
        name: str,
        stat: os.stat_result,
        *,
        is_dir: bool,
        is_symlink: bool,
    ) -> None:
        """Label ZFS compression / block-sharing / a skipped snapshot dir from the per-file stat.

        ``st_blocks * 512`` (allocated) being below ``st_size`` (logical) for a regular file is,
        on ZFS, the signature of compression *or* block sharing. The base class already flags it
        ``sparse``; ZFS adds ``compressed`` so the UI can label "stored compressed", and
        ``reflink`` to mark that the on-disk figure under-counts unique bytes because blocks are
        shared (do not sum allocated bytes for a pool total — risks §allocated-vs-logical). The
        per-file stat cannot distinguish hole-sparseness from compression with certainty, so both
        flags are set conservatively and the catalogue/UI treat them as advisory hints. A
        ``.zfs/snapshot`` control directory is flagged ``snapshot_skipped`` so the prune (it is
        reported but never walked into) is observable in the catalogue.
        """
        if is_dir and self._is_snapshot_dir(path, name):
            flags["snapshot_skipped"] = True
            return
        if is_dir or is_symlink:
            return
        size_on_disk = stat.st_blocks * 512
        if 0 < size_on_disk < stat.st_size:
            flags["compressed"] = True
            flags["reflink"] = True

    @staticmethod
    def _raid_role(pool_name: str, raid_level: str | None) -> str:
        """Format a human-readable ``raid_role`` from pool name + level (ADD 04 vocabulary)."""
        if raid_level:
            return f"zpool {pool_name} {raid_level}"
        return f"zpool {pool_name}"
