"""The ``StorageBackend`` protocol and its shared data frames (ADD 02).

A backend presents a uniform walk/stat/usage interface while hiding filesystem-specific
truths (ZFS logical-vs-allocated size, snapshot dirs to skip, reflinks, NTFS ADS,
FAT/exFAT lacking ownership). Structural typing (``typing.Protocol``) is used per
code-quality rule #9 — a class is a valid backend if it has the right shape, no
inheritance required.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Collection
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

# Sentinel ids for filesystems with no real ownership model (FAT/exFAT). Flagged in
# ``FsEntry.flags["synthetic_owner"]`` so the UI never implies a permission it cannot
# enforce (ADD 02 Review Readiness, AR-027).
SYNTHETIC_UID = -1
SYNTHETIC_GID = -1

# The open ``FsEntry.flags`` key vocabulary, documented in one place so every backend speaks
# the same dialect and the catalogue/UI can special-case each consistently (data_model_changes
# §flags). ``flags`` stays an open ``dict[str, bool]`` — adding a key needs no model change.
#   "sparse"           — size_on_disk < size_logical because of holes (POSIX/ZFS).
#   "reflink"          — block-shared / CoW extent; on-disk bytes are shared, not unique (ZFS).
#   "compressed"       — stored compressed (ZFS dataset compression, NTFS compression).
#   "ads"              — NTFS alternate data stream(s) present (extra, normally hidden, bytes).
#   "synthetic_owner"  — uid/gid are SYNTHETIC_*; the filesystem has no ownership model
#                        (FAT/exFAT) so the UI must not render or enforce a permission (AR-027).
#   "snapshot_skipped" — a ``.zfs/snapshot`` control directory was encountered and not walked
#                        into (ZFS); recorded on the control dir entry so the skip is observable.
#   "reparse_point"    — a Windows reparse point (symlink, junction, mount point, cloud
#                        placeholder anchor); reported but never descended into (ADR-027 W1).
#   "placeholder"      — a dehydrated cloud-placeholder file (OneDrive et al.); metadata only,
#                        content is never opened so the walk can never trigger hydration.
FLAG_KEYS: frozenset[str] = frozenset(
    {
        "sparse",
        "reflink",
        "compressed",
        "ads",
        "synthetic_owner",
        "snapshot_skipped",
        "reparse_point",
        "placeholder",
    }
)


class FullBitUnsupportedError(RuntimeError):
    """Full-bit (content) hashing was attempted on a backend that forbids it (ADD 02 §Mode 2).

    Full-bit scans read file *contents* and MUST only ever run on the host that owns the data —
    "never over SFTP/SMB/NFS" (ADD 02 line 63). The remote backends therefore do not implement
    content reads at all: their :meth:`StorageBackend.open_for_hash` *raises* this rather than
    returning a reader, so the prohibition is a hard, regression-tested refusal — not a config
    flag that could be flipped (security_constraints: read != write, full-bit boundary).
    """


class PlaceholderNotHydratedError(OSError):
    """A full-bit open was refused for ONE file because reading it would hydrate it (ADR-027 W2).

    Unlike :class:`FullBitUnsupportedError` (a *backend-wide* refusal), this is per-file: a cloud
    placeholder (OneDrive et al. — offline / recall-on-open / recall-on-data-access) or a reparse
    point must never be *opened* for content hashing, because the open is exactly what pulls the
    bytes down from the cloud (the drvfs hang we saw on the Docker agent). It subclasses ``OSError``
    so the full-bit funnel treats it like any other unreadable file — skip its content, keep its
    metadata, never abort the scope — rather than failing the whole pass.
    """


class FsEntry(BaseModel):
    """One filesystem entry as captured by a metadata (``stat``) walk.

    ``size_on_disk`` is the allocated size (``st_blocks * 512`` on POSIX), which differs
    from ``size_logical`` under compression, sparse files, and tail packing. Both are
    carried so the catalogue and UI can show — and label — each (ADD 01, ADD 04).
    """

    path: str
    name: str
    is_dir: bool
    is_symlink: bool
    size_logical: int = Field(ge=0)
    size_on_disk: int = Field(ge=0)
    mtime: float
    ctime: float
    uid: int
    gid: int
    inode: int
    # The device id (``st_dev``) the entry lives on. It distinguishes files across *filesystems*
    # within one logical volume: a ``cross_mounts`` walk descends into ZFS child datasets, each of
    # which has its OWN inode space and reuses low inode numbers — so ``inode`` alone collides
    # across datasets and the catalogue identity must include ``dev`` (host_id, volume_id, dev,
    # inode). Defaults to 0 so a single-filesystem scan (where inode is already unique) is
    # behaviour-preserving. Remote backends with no device concept leave it 0.
    dev: int = 0
    flags: dict[str, bool] = Field(default_factory=dict)
    # Provider-attested content hash (ADR-028 phase 2): set ONLY by backends that obtain a hash
    # the *provider* already computed without the agent reading file bytes — today the rclone
    # backend via ``lsjson --hash`` (MD5/SHA-1/QuickXorHash, per remote). It is a DISTINCT trust
    # class from ``full_hash`` (which is BLAKE3 and only ever set by a real content read), so it
    # lives in its own field, is never conflated with ``full_hash``, and is report-only — it can
    # surface "these look duplicated per the provider" groups but MUST NEVER drive remediation
    # (which keys on the content-verified ``full_hash``). ``provider_hash_algo`` names the
    # algorithm so groups only ever compare like-with-like. Both unset on a normal metadata walk.
    provider_hash: str | None = None
    provider_hash_algo: str | None = None


class VolumeInfo(BaseModel):
    """A mounted volume's identity, capacity, and storage topology (ADD 04).

    ``transport`` and ``raid_role`` make "this is on a slow USB RAID5" first-class so the
    UI can label it and the supervisor can enforce the resync guard.
    """

    mountpoint: str
    fs_type: str
    total: int = Field(ge=0)
    used: int = Field(ge=0)
    free: int = Field(ge=0)
    device: str
    transport: str  # nvme | sata | usb | network | unknown
    raid_role: str | None = None
    dataset: str | None = None
    # Human label when ``mountpoint`` is a synthetic path (remote backends — ADR-029): e.g.
    # mountpoint ``/rclone/gdrive/Backups`` displays as ``rclone://gdrive/Backups``. None for
    # local volumes, where the mountpoint is already the natural display.
    display_name: str | None = None


@runtime_checkable
class AsyncReader(Protocol):
    """A bounded, seekable async byte source for progressive hashing (full-bit mode)."""

    async def read(self, size: int) -> bytes: ...

    async def seek(self, offset: int) -> int: ...

    async def close(self) -> None: ...


@runtime_checkable
class StorageBackend(Protocol):
    """Any class implementing these methods is a valid backend (structural typing)."""

    def supports(self, mountpoint: str) -> bool:
        """Return whether this backend can serve ``mountpoint``."""
        ...

    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        """Report capacity and storage topology for ``mountpoint``."""
        ...

    def walk(
        self,
        root: str,
        *,
        follow_symlinks: bool = False,
        one_filesystem: bool = True,
        exclude: Collection[str] = (),
    ) -> AsyncIterator[FsEntry]:
        """Yield every entry under ``root`` as a metadata-only ``FsEntry`` stream.

        Implementations must not open file contents and must not traverse symlinks unless
        explicitly opted in. ``one_filesystem`` (default on) keeps the walk inside the
        root's filesystem; set it off to descend into nested mounts — e.g. ZFS child
        datasets under a pool root, which each have their own device id.

        ``exclude`` (ADR-034) is a set of absolute directory prefixes to PRUNE: the walk neither
        reports nor descends into any path at or under an excluded prefix. Local backends honour
        it; remote backends (SMB/SFTP/rclone) accept it but ignore it (exclude is local-FS only).
        """
        ...

    async def open_for_hash(self, path: str) -> AsyncReader:
        """Open ``path`` for content hashing — full-bit mode only (later stage)."""
        ...

    async def is_busy(self) -> bool:
        """Return whether the backing array is resyncing/resilvering (ADD 02 §throttle)."""
        ...
