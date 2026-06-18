"""Generic read-only POSIX backend (ADD 02).

Serves any local POSIX-visible path: ext4/XFS today, and a safe fallback for anything
without a specialised plugin. It is *metadata-only* — :meth:`walk` never opens file
contents, and :meth:`open_for_hash` is intentionally unimplemented in Stage 1 (full-bit
mode is a later, separately reviewed stage). On-disk size is ``st_blocks * 512``.

Directory traversal runs ``os.scandir`` in a bounded thread pool so the asyncio event
loop is never blocked (standards/18 §7, async-patterns). Host-load throttling and the
RAID-resync guard live one layer up, in the reader's supervisor — this backend only
reads the tree.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Collection
from pathlib import Path
from typing import BinaryIO

from fathom.backends.base import AsyncReader, FsEntry, VolumeInfo
from fathom.logging import get_logger

_log = get_logger("fathom.backends.posix")

# Default bounded concurrency for the scandir thread pool (ADD 02 throttle: walk_concurrency).
DEFAULT_WALK_CONCURRENCY = 4

# Upper bound on entries buffered between the parallel walk and the consumer. The walk
# produces far faster than the consumer can stage to SQLite, so an *unbounded* results queue
# accumulates every FsEntry in RAM and OOM-kills the agent on an estate-scale scan (observed
# on a live TrueNAS run over two large pools). Bounding it applies backpressure: workers
# block on a full queue and the walk self-throttles to the staging rate, keeping memory flat
# regardless of tree size (ADD 05 §memory; the non-impact contract must hold at 50M entries).
RESULTS_QUEUE_MAXSIZE = 20000

_RESYNC_MARKERS = ("resync", "recovery", "rebuild", "reshape", "check")


def normalise_excludes(exclude: Collection[str]) -> frozenset[str]:
    """Normalise exclude prefixes once per walk (ADR-034): absolute, no trailing sep, deduped."""
    return frozenset(os.path.normpath(e) for e in exclude if e)


def is_excluded_path(path: str, excluded: frozenset[str]) -> bool:
    """Whether ``path`` is at or under any excluded prefix. Prefix match on path components, so
    ``/a/b`` excludes ``/a/b`` and ``/a/b/c`` but NOT a sibling like ``/a/bc`` (ADR-034)."""
    if not excluded:
        return False
    p = os.path.normpath(path)
    return any(p == e or p.startswith(e + os.sep) for e in excluded)


_U64 = 1 << 64
_I64_MAX = (1 << 63) - 1


def _to_signed64(value: int) -> int:
    """Reinterpret an unsigned 64-bit identity as a signed 64-bit value (bijective on [0, 2**64)).

    Windows NTFS file IDs (``st_ino``), and some ``st_dev`` values, are *unsigned* 64-bit and can
    exceed the signed-64 max that SQLite (agent staging) and Postgres ``bigint`` (the catalogue)
    store — which raised ``OverflowError`` mid-scan and aborted the whole run. Wrapping the high
    half into the negative range preserves uniqueness, so the ``(dev, inode)`` identity is the
    same; the value is only ever an identity key, never arithmetic.
    """
    return value - _U64 if value > _I64_MAX else value


class PosixBackend:
    """A ``StorageBackend`` for local POSIX filesystems (structural conformance)."""

    def __init__(self, walk_concurrency: int = DEFAULT_WALK_CONCURRENCY) -> None:
        if walk_concurrency < 1:
            raise ValueError("walk_concurrency must be >= 1")
        self._walk_concurrency = walk_concurrency

    def supports(self, mountpoint: str) -> bool:
        """True for any existing local directory — this is the fallback backend."""
        return Path(mountpoint).is_dir()

    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        """Report capacity (``statvfs``) and best-effort topology for ``mountpoint``.

        Full transport/RAID topology resolution is ADD 04's job; Stage 1 reports the
        reliably-cheap facts (capacity, device, fs type, NVMe-by-name) and leaves the
        rest ``unknown`` rather than guessing.
        """
        real = await asyncio.to_thread(os.path.realpath, mountpoint)
        stat = await asyncio.to_thread(os.statvfs, real)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize

        device, fs_type = await asyncio.to_thread(self._resolve_mount, real)
        transport = self._classify_transport(device)
        return VolumeInfo(
            mountpoint=real,
            fs_type=fs_type,
            total=total,
            used=used,
            free=free,
            device=device,
            transport=transport,
            raid_role=None,
            dataset=None,
        )

    async def walk(
        self,
        root: str,
        *,
        follow_symlinks: bool = False,
        one_filesystem: bool = True,
        exclude: Collection[str] = (),
    ) -> AsyncIterator[FsEntry]:
        """Yield every entry under ``root`` as a metadata-only ``FsEntry`` stream.

        ``one_filesystem`` (default on) refuses to cross into other mounted filesystems,
        keeping a scan inside its volume. Symlinks are reported but never traversed unless
        ``follow_symlinks`` is set. Unreadable directories are logged and skipped, not
        fatal — a single ``EACCES`` must not abort a 50M-entry scan.

        ``exclude`` (ADR-034) prunes subtrees: any path at or under an excluded prefix is neither
        reported nor descended into — so excluding e.g. ``/var/lib/docker`` skips it entirely
        (the walk never pays the cost of traversing it).
        """
        root_real = await asyncio.to_thread(os.path.realpath, root)
        excluded = normalise_excludes(exclude)
        if is_excluded_path(root_real, excluded):
            # The whole root is excluded — nothing to emit.
            return
        try:
            root_stat = await asyncio.to_thread(os.lstat, root_real)
        except OSError as exc:
            _log.warning("walk root unreadable", extra={"path": root_real, "error": str(exc)})
            return
        root_dev = root_stat.st_dev

        # Emit the root node itself; the worker loop emits every descendant as a child.
        yield self._entry(root_real, Path(root_real).name or root_real, root_stat)

        # work is unbounded (a worker both produces and consumes it, so bounding it could
        # deadlock); results is BOUNDED so the walk can never outrun the consumer into OOM.
        work: asyncio.Queue[str] = asyncio.Queue()
        results: asyncio.Queue[FsEntry | None] = asyncio.Queue(maxsize=RESULTS_QUEUE_MAXSIZE)
        work.put_nowait(root_real)

        async def worker() -> None:
            while True:
                path = await work.get()
                try:
                    entries, subdirs = await asyncio.to_thread(
                        self._scan_dir, path, root_dev, follow_symlinks, one_filesystem, excluded
                    )
                    for entry in entries:
                        await results.put(entry)  # blocks when full → backpressure (no OOM)
                    for subdir in subdirs:
                        work.put_nowait(subdir)
                finally:
                    work.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self._walk_concurrency)]

        async def closer() -> None:
            await work.join()
            await results.put(None)  # may block until the consumer drains; never QueueFull

        closer_task = asyncio.create_task(closer())
        try:
            while True:
                item = await results.get()
                if item is None:
                    break
                yield item
        finally:
            for w in workers:
                w.cancel()
            closer_task.cancel()
            await asyncio.gather(*workers, closer_task, return_exceptions=True)

    async def open_for_hash(self, path: str) -> AsyncReader:
        """Open ``path`` for content hashing (full-bit mode). Refuses symlinks (no follow)."""
        fh = await asyncio.to_thread(self._open_nofollow, path)
        return _FileReader(fh)

    @staticmethod
    def _open_nofollow(path: str) -> BinaryIO:
        # O_NOFOLLOW on the final component: never open through a symlink for hashing.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        return os.fdopen(fd, "rb", buffering=0)

    async def is_busy(self) -> bool:
        """Conservative resync check via ``/proc/mdstat`` (the supervisor is authoritative)."""
        return await asyncio.to_thread(self._mdstat_resyncing)

    # ----------------------------------------------------------------- internals

    def _scan_dir(
        self,
        path: str,
        root_dev: int,
        follow_symlinks: bool,
        one_filesystem: bool,
        excluded: frozenset[str] = frozenset(),
    ) -> tuple[list[FsEntry], list[str]]:
        """Scan one directory (runs in a thread). Returns (child entries, subdirs to visit)."""
        entries: list[FsEntry] = []
        subdirs: list[str] = []
        try:
            with os.scandir(path) as it:
                for de in it:
                    # ADR-034: an excluded subtree is neither reported nor descended into.
                    if is_excluded_path(de.path, excluded):
                        continue
                    entry = self._entry_from_dirent(de)
                    if entry is None:
                        continue
                    entries.append(entry)
                    if self._skip_subdir(de.path, de.name):
                        # A filesystem-specific control directory (e.g. ZFS ``.zfs/snapshot``):
                        # reported once but never walked into (storage-backends §snapshot skip).
                        continue
                    if self._should_descend(de, root_dev, follow_symlinks, one_filesystem):
                        subdirs.append(de.path)
        except OSError as exc:
            _log.warning("directory skipped", extra={"path": path, "error": str(exc)})
        return entries, subdirs

    def _skip_subdir(self, path: str, name: str) -> bool:
        """Hook: refuse to descend into ``path`` regardless of mount/symlink rules (default off).

        The generic POSIX backend descends into every real directory. Subclasses override this to
        prune filesystem-specific control trees — e.g. :class:`~fathom.backends.zfs.ZfsBackend`
        prunes ``.zfs/snapshot`` so a walk never expands every snapshot of every dataset.
        """
        return False

    def _entry_from_dirent(self, de: os.DirEntry[str]) -> FsEntry | None:
        try:
            stat = de.stat(follow_symlinks=False)
            is_symlink = de.is_symlink()
            is_dir = de.is_dir(follow_symlinks=False)
        except OSError as exc:
            _log.warning("entry skipped", extra={"path": de.path, "error": str(exc)})
            return None
        return self._entry(de.path, de.name, stat, is_dir=is_dir, is_symlink=is_symlink)

    def _entry(
        self,
        path: str,
        name: str,
        stat: os.stat_result,
        *,
        is_dir: bool | None = None,
        is_symlink: bool | None = None,
    ) -> FsEntry:
        import stat as stat_mod

        if is_symlink is None:
            is_symlink = stat_mod.S_ISLNK(stat.st_mode)
        if is_dir is None:
            is_dir = stat_mod.S_ISDIR(stat.st_mode)
        size_logical = stat.st_size
        # st_blocks does not exist on Windows stat results; fall back to the logical size
        # there (true allocated size is a W2 refinement — GetCompressedFileSize, ADR-027).
        blocks = getattr(stat, "st_blocks", None)
        size_on_disk = blocks * 512 if blocks is not None else size_logical
        flags: dict[str, bool] = {}
        if not is_dir and not is_symlink and size_on_disk < size_logical:
            flags["sparse"] = True
        self._annotate_flags(flags, path, name, stat, is_dir=is_dir, is_symlink=is_symlink)
        return FsEntry(
            path=path,
            name=name,
            is_dir=is_dir,
            is_symlink=is_symlink,
            size_logical=size_logical,
            size_on_disk=size_on_disk,
            mtime=stat.st_mtime,
            ctime=stat.st_ctime,
            uid=stat.st_uid,
            gid=stat.st_gid,
            inode=_to_signed64(stat.st_ino),
            # st_dev distinguishes files across filesystems within one logical volume: a
            # cross_mounts walk descends into ZFS child datasets that each reuse low inode
            # numbers, so the catalogue identity is (host_id, volume_id, dev, inode), not inode.
            # Both are normalised to signed-64 — Windows NTFS file IDs overflow SQLite otherwise.
            dev=_to_signed64(stat.st_dev),
            flags=flags,
        )

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
        """Hook: add filesystem-specific :class:`FsEntry` flags in place (default no-op).

        The base POSIX backend sets only ``sparse`` (above). Subclasses add their own dialect —
        e.g. ZFS ``reflink``/``compressed``/``snapshot_skipped``, NTFS ``ads`` — without touching
        the shared walk machinery (storage-backends §flags vocabulary).
        """
        return None

    @staticmethod
    def _should_descend(
        de: os.DirEntry[str],
        root_dev: int,
        follow_symlinks: bool,
        one_filesystem: bool,
    ) -> bool:
        try:
            if not de.is_dir(follow_symlinks=follow_symlinks):
                return False
            if de.is_symlink() and not follow_symlinks:
                return False
            if one_filesystem:
                return de.stat(follow_symlinks=follow_symlinks).st_dev == root_dev
        except OSError:
            return False
        return True

    @staticmethod
    def _resolve_mount(real_path: str) -> tuple[str, str]:
        """Return (device, fs_type) for the mount backing ``real_path`` via /proc/mounts."""
        best_mount = ""
        best_device = "unknown"
        best_fstype = "unknown"
        try:
            mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return best_device, best_fstype
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mountpoint, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
            under_mount = real_path == mountpoint or real_path.startswith(
                mountpoint.rstrip("/") + "/"
            )
            if under_mount and len(mountpoint) >= len(best_mount):
                best_mount, best_device, best_fstype = mountpoint, device, fstype
        return best_device, best_fstype

    @staticmethod
    def _classify_transport(device: str) -> str:
        """Cheap, reliable-only transport hint; full topology is ADD 04."""
        base = Path(device).name
        if base.startswith("nvme"):
            return "nvme"
        return "unknown"

    @staticmethod
    def _mdstat_resyncing() -> bool:
        try:
            text = Path("/proc/mdstat").read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            return False
        return any(marker in text for marker in _RESYNC_MARKERS)


class _FileReader:
    """A seekable async byte source over a blocking file handle (offloaded to threads)."""

    def __init__(self, fh: BinaryIO) -> None:
        self._fh = fh

    async def read(self, size: int) -> bytes:
        return await asyncio.to_thread(self._fh.read, size)

    async def seek(self, offset: int) -> int:
        return await asyncio.to_thread(self._fh.seek, offset)

    async def close(self) -> None:
        await asyncio.to_thread(self._fh.close)
