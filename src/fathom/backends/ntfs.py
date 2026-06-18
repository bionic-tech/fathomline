"""NTFS / exFAT / FAT storage backend — Linux-mounted, capability-honest (ADR-004, AR-027).

Per the owner ruling for this pass, this is **NTFS/exFAT mounted on Linux** (ntfs-3g / exfat /
vfat under the POSIX path) — *not* a native Windows agent (design_questions §4: "NO native
Windows agent this pass"). It therefore reuses the POSIX walk and annotates the two filesystem
truths that path gets wrong:

* **No ownership model (FAT/exFAT/vfat).** These filesystems have no real uid/gid; the Linux
  driver reports the *mounting user's* uid/gid (a ``uid=``/``gid=`` mount option), which is an
  artefact, not a fact. Reporting it would imply a permission the filesystem cannot enforce, so
  this backend substitutes :data:`~fathom.backends.base.SYNTHETIC_UID` /
  :data:`~fathom.backends.base.SYNTHETIC_GID` and sets ``flags["synthetic_owner"]=True`` — the
  UI special-cases the flag rather than rendering ``uid -1`` (AR-027, the one ☑ for AR-027 in
  ADD 02 Review Readiness).
* **NTFS alternate data streams + compression.** NTFS keeps real ownership (preserved), but it
  has ADS (extra hidden byte streams) and per-file compression that ``st_blocks`` alone does not
  explain. Where the ntfs-3g driver surfaces them — ``user.*`` xattrs for named streams, on-disk
  < logical for compression — they are flagged ``ads`` / ``compressed`` so the size figure is
  honest about what it does and does not include.

``size_on_disk`` still comes from ``st_blocks * 512`` (cluster allocation, as the inherited POSIX
``_entry`` computes it); FAT/exFAT report cluster-rounded allocation there, which is correct.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Collection
from pathlib import Path

from fathom.backends.base import SYNTHETIC_GID, SYNTHETIC_UID, FsEntry
from fathom.backends.posix import DEFAULT_WALK_CONCURRENCY, PosixBackend
from fathom.logging import get_logger

_log = get_logger("fathom.backends.ntfs")

# Filesystems with no real POSIX ownership model — synthesise a sentinel owner (AR-027).
_NO_OWNERSHIP_FS: frozenset[str] = frozenset({"exfat", "vfat", "fat", "msdos"})
# Filesystems this backend specialises (NTFS keeps ownership; the rest synthesise it).
_SUPPORTED_FS: frozenset[str] = frozenset({"ntfs", "ntfs3", "fuseblk", *_NO_OWNERSHIP_FS})


class NtfsExfatBackend(PosixBackend):
    """NTFS/exFAT/FAT-on-Linux :class:`~fathom.backends.base.StorageBackend` (flag annotator).

    Subclasses the POSIX backend: same walk, same ``size_on_disk`` from cluster allocation. It
    overrides only ``supports`` (fs-type match) and the per-entry seams to substitute a synthetic
    owner for ownership-less filesystems and to flag NTFS ADS/compression.

    ``fs_type`` is resolved once per walk root and cached for the entry annotator, since a single
    walk never crosses a mount (``one_filesystem`` defaults on). ``fuseblk`` (how ntfs-3g shows in
    ``/proc/mounts``) is accepted but treated as NTFS-with-ownership unless probed otherwise.
    """

    def __init__(self, *, walk_concurrency: int = DEFAULT_WALK_CONCURRENCY) -> None:
        super().__init__(walk_concurrency=walk_concurrency)
        self._fs_type: str = "unknown"

    def supports(self, mountpoint: str) -> bool:
        """True when ``mountpoint`` is an NTFS/exFAT/FAT filesystem (``/proc/mounts`` fs type)."""
        real = os.path.realpath(mountpoint)
        if not Path(real).is_dir():
            return False
        _device, fs_type = self._resolve_mount(real)
        return fs_type.lower() in _SUPPORTED_FS

    async def walk(
        self,
        root: str,
        *,
        follow_symlinks: bool = False,
        one_filesystem: bool = True,
        exclude: Collection[str] = (),
    ) -> AsyncIterator[FsEntry]:
        """Resolve the root's fs type once, then delegate to the inherited POSIX walk.

        The fs type drives whether entries get a synthetic owner; resolving it per-entry would
        re-read ``/proc/mounts`` for every file. A walk never crosses a mount when
        ``one_filesystem`` is on (the default), so one resolution is correct for the whole tree.
        """
        real = await asyncio.to_thread(os.path.realpath, root)
        _device, fs_type = await asyncio.to_thread(self._resolve_mount, real)
        self._fs_type = fs_type.lower()
        async for entry in super().walk(
            root, follow_symlinks=follow_symlinks, one_filesystem=one_filesystem, exclude=exclude
        ):
            yield entry

    def _entry(
        self,
        path: str,
        name: str,
        stat: os.stat_result,
        *,
        is_dir: bool | None = None,
        is_symlink: bool | None = None,
    ) -> FsEntry:
        """Build the POSIX entry, then synthesise an owner for ownership-less FS (AR-027)."""
        entry = super()._entry(path, name, stat, is_dir=is_dir, is_symlink=is_symlink)
        if self._fs_type in _NO_OWNERSHIP_FS:
            # FAT/exFAT have no ownership model — the driver's uid/gid is the mounter's, an
            # artefact. Replace with the sentinel and flag it so the UI never implies a permission.
            return entry.model_copy(
                update={
                    "uid": SYNTHETIC_UID,
                    "gid": SYNTHETIC_GID,
                    "flags": {**entry.flags, "synthetic_owner": True},
                }
            )
        return entry

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
        """Flag NTFS alternate data streams and compression where the mount exposes them.

        ntfs-3g surfaces named streams as ``user.*`` xattrs and compresses files such that the
        on-disk allocation is below the logical size. We probe xattrs (cheap, off-loop is the
        caller's concern — this runs in the scandir thread) for ADS and compare sizes for
        compression. exFAT/FAT have neither, so this is a no-op there.
        """
        if self._fs_type not in {"ntfs", "ntfs3", "fuseblk"}:
            return
        if not is_dir and not is_symlink:
            size_on_disk = stat.st_blocks * 512
            if 0 < size_on_disk < stat.st_size:
                flags["compressed"] = True
            if self._has_ads(path):
                flags["ads"] = True

    @staticmethod
    def _has_ads(path: str) -> bool:
        """Best-effort: does ``path`` carry an NTFS alternate data stream (``user.*`` xattr)?

        Returns ``False`` on any platform/driver that does not expose stream xattrs (the common
        case on a non-ntfs-3g mount or a non-Linux host), so a missing capability is honest
        absence, never a false positive.
        """
        listxattr = getattr(os, "listxattr", None)
        if listxattr is None:  # pragma: no cover - platform without xattr support
            return False
        try:
            names = listxattr(path, follow_symlinks=False)
        except OSError:
            return False
        return any(n.startswith("user.") for n in names)
