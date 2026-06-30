"""Native Windows backend — ADR-027: read-only local scanning (metadata W1 + full-bit W2).

Subclasses the POSIX walk machinery (``os.scandir`` maps to Win32 underneath, and CPython
fills ``st_ino`` with the NTFS file reference number and ``st_dev`` with the volume serial,
so the catalogue identity model holds unchanged — ADR-015) and overrides exactly the
Windows-specific behaviours:

- scan roots are validated by the strict Windows path rules (:mod:`fathom.security.winpaths`);
- **reparse points are never descended into** and **cloud placeholders are never opened**
  (:mod:`fathom.backends.winattrs` — the skip-don't-follow / never-hydrate rules);
- ownership is reported as synthetic: NTFS has SIDs, not uid/gid, so the UI must not render
  a POSIX permission that does not exist (same contract as FAT/exFAT, AR-027 flag);
- :meth:`open_for_hash` (phase W2) hashes LOCAL content, but ``stat``s + classifies each file
  first and **refuses to open a reparse point or a cloud placeholder** (raising
  :class:`PlaceholderNotHydratedError`, an ``OSError`` the full-bit funnel skips per-file) —
  because the open is exactly what would hydrate a placeholder from the cloud.

The backend registers only on Windows (``os.name == "nt"``); on every other platform its
``supports()`` is False and only its pure logic is exercised by tests.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from collections.abc import AsyncIterator, Collection
from pathlib import Path
from typing import BinaryIO

from fathom.backends.base import (
    SYNTHETIC_GID,
    SYNTHETIC_UID,
    AsyncReader,
    FsEntry,
    PlaceholderNotHydratedError,
    VolumeInfo,
)
from fathom.backends.posix import DEFAULT_WALK_CONCURRENCY, PosixBackend, _FileReader
from fathom.backends.winattrs import classify_attributes, entry_attributes
from fathom.logging import get_logger
from fathom.security.winpaths import validate_windows_config_path

_log = get_logger("fathom.backends.windows")


class WindowsBackend(PosixBackend):
    """A read-only ``StorageBackend`` for local Windows volumes (NTFS-first; ADR-027 W1)."""

    def __init__(self, walk_concurrency: int = DEFAULT_WALK_CONCURRENCY) -> None:
        super().__init__(walk_concurrency=walk_concurrency)

    def supports(self, mountpoint: str) -> bool:
        """True on Windows for a valid, existing local directory path."""
        if os.name != "nt":
            return False
        try:
            validated = validate_windows_config_path(mountpoint)
        except ValueError:
            return False
        return Path(str(validated)).is_dir()

    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        """Capacity via ``shutil.disk_usage``; identity from the volume serial (= st_dev)."""
        validated = str(validate_windows_config_path(mountpoint))
        usage = await asyncio.to_thread(shutil.disk_usage, validated)
        st = await asyncio.to_thread(os.stat, validated)
        return VolumeInfo(
            mountpoint=validated,
            fs_type="ntfs",  # W1 assumes the supported matrix's primary fs (ADR-027)
            total=usage.total,
            used=usage.total - usage.free,
            free=usage.free,
            device=f"volume-serial-{st.st_dev:08x}",
            transport="unknown",
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
        """The POSIX walk machinery behind the strict Windows root validation (fail-closed)."""
        validated = str(validate_windows_config_path(root))
        async for entry in super().walk(
            validated,
            follow_symlinks=follow_symlinks,
            one_filesystem=one_filesystem,
            exclude=exclude,
        ):
            yield entry

    async def open_for_hash(self, path: str) -> AsyncReader:
        """Open a LOCAL Windows file for content hashing (ADR-027 phase W2) — never hydrating.

        Full-bit only ever runs on the host that owns the data, so a local NTFS read is allowed.
        But the open itself is what would pull a *cloud placeholder* down from the network, so this
        first ``stat``s the file (no open, no follow) and classifies its attributes: a reparse point
        or a cloud placeholder (offline / recall-on-open / recall-on-data-access) is refused with
        :class:`PlaceholderNotHydratedError` (an ``OSError``) so the full-bit funnel skips just that
        one file — metadata kept, bytes never touched — instead of hydrating it (the drvfs hang the
        Docker agent hit). There is no ``O_NOFOLLOW`` on Windows; this pre-open reparse check is the
        equivalent symlink/junction guard. A plain local file is opened read-only and streamed.
        """
        st = await asyncio.to_thread(os.stat, path, follow_symlinks=False)
        cls = classify_attributes(entry_attributes(st))
        if not cls.hash_ok:
            kind = "reparse point" if cls.is_reparse else "cloud placeholder"
            raise PlaceholderNotHydratedError(
                f"refusing to open a {kind} for hashing (never hydrated): {path!r}"
            )
        fh = await asyncio.to_thread(self._open_for_read, path)
        return _FileReader(fh)

    @staticmethod
    def _open_for_read(path: str) -> BinaryIO:
        # Read-only, binary, unbuffered (the hasher streams). No O_NOFOLLOW on Windows — the
        # reparse-point refusal in open_for_hash is the symlink/junction guard instead.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        return os.fdopen(fd, "rb", buffering=0)

    async def is_busy(self) -> bool:
        """No /proc/mdstat on Windows; storage-pool resync awareness is a later refinement."""
        return False

    # ----------------------------------------------------------------- walk overrides

    def _should_descend(  # type: ignore[override]
        self,
        de: os.DirEntry[str],
        root_dev: int,
        follow_symlinks: bool,
        one_filesystem: bool,
    ) -> bool:
        """Skip-don't-follow: a reparse directory (junction/mount point) is never walked into."""
        try:
            if classify_attributes(entry_attributes(de.stat(follow_symlinks=False))).is_reparse:
                return False
        except OSError:
            return False
        return PosixBackend._should_descend(de, root_dev, follow_symlinks, one_filesystem)

    def _entry_from_dirent(self, de: os.DirEntry[str]) -> FsEntry | None:
        entry = super()._entry_from_dirent(de)
        if entry is None:
            return None
        try:
            attrs = entry_attributes(de.stat(follow_symlinks=False))
        except OSError:
            attrs = 0
        cls = classify_attributes(attrs)
        if cls.is_reparse:
            entry.flags["reparse_point"] = True
        if cls.is_placeholder:
            # Catalogued from metadata only; content is never opened (never hydrated).
            entry.flags["placeholder"] = True
        # NTFS ownership is SIDs, not uid/gid — mark synthetic so the UI never renders a
        # POSIX permission that does not exist (same contract as FAT/exFAT).
        entry.uid = SYNTHETIC_UID
        entry.gid = SYNTHETIC_GID
        entry.flags["synthetic_owner"] = True
        return entry
