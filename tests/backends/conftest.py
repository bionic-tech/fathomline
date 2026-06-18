"""Shared fixtures for the specialised storage backends (storage-backends test_plan).

Three fixture families, mirroring the conformance pattern ``tests/conftest.py`` establishes for
POSIX:

* ``zfs_like_tree`` — an on-disk tree with a ``.zfs/snapshot`` control dir (to assert the skip)
  and a real sparse file (to assert allocated < logical and the compression/reflink labelling).
* ``fake_remote_transport`` — an in-memory :class:`~fathom.backends.remote.RemoteTransport` built
  from a recorded directory transcript, so the SMB/SFTP walk/mapping runs with no live server and
  no optional client library (parity with the adapter conformance fixtures).
* ``exfat_like_tree`` — a plain tree the NTFS/exFAT backend walks while its resolved fs type is
  forced to ``exfat`` (via the ``exfat_backend`` fixture), exercising the synthetic-owner path.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from fathom.backends.remote import RemoteStat


@pytest.fixture
def zfs_like_tree(tmp_path: Path) -> Path:
    """A tree with a ``.zfs/snapshot`` control dir and a sparse file (ZFS-specific edge cases).

    Layout::

        pool/
          data.txt              (12 bytes, regular)
          sparse.dat            (logical 1 MiB, ~0 on disk → compressed/reflink labelling)
          child/                (a normal subdir, walked)
            nested.bin          (64 bytes)
          .zfs/
            snapshot/
              auto-2026/
                old.txt         (MUST never be walked into)
    """
    pool = tmp_path / "pool"
    (pool / "child").mkdir(parents=True)
    snap = pool / ".zfs" / "snapshot" / "auto-2026"
    snap.mkdir(parents=True)

    (pool / "data.txt").write_bytes(b"hello world!")
    (pool / "child" / "nested.bin").write_bytes(b"\x00" * 64)
    (snap / "old.txt").write_bytes(b"historical copy")

    sparse = pool / "sparse.dat"
    with sparse.open("wb") as fh:
        fh.seek(1024 * 1024 - 1)
        fh.write(b"\x00")
    return pool


@pytest.fixture
def exfat_like_tree(tmp_path: Path) -> Path:
    """A plain tree the NTFS/exFAT backend walks (fs type is forced by the backend fixture)."""
    root = tmp_path / "exfat"
    (root / "sub").mkdir(parents=True)
    (root / "file.txt").write_bytes(b"data")
    (root / "sub" / "more.txt").write_bytes(b"more data")
    return root


@dataclass
class FakeStat:
    """A concrete :class:`~fathom.backends.remote.RemoteStat` for the in-memory transport."""

    name: str
    path: str
    is_dir: bool
    is_symlink: bool
    size: int
    mtime: float
    uid: int
    gid: int


@dataclass
class FakeRemoteTransport:
    """An in-memory :class:`~fathom.backends.remote.RemoteTransport` from a recorded transcript.

    ``tree`` maps a directory path to the list of its children; ``vfs`` is the statvfs tuple.
    ``listdir_calls`` records every path listed so a test can assert the re-stat walk path was
    taken (and that no content read occurred — there is no read method to call).
    """

    tree: dict[str, list[FakeStat]]
    vfs: tuple[int, int, int] = (1000, 400, 600)
    listdir_calls: list[str] = field(default_factory=list)
    closed: bool = False

    async def listdir(self, path: str) -> list[RemoteStat]:
        self.listdir_calls.append(path)
        return list(self.tree.get(path, []))

    async def statvfs(self, path: str) -> tuple[int, int, int]:
        return self.vfs

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_remote_transport() -> FakeRemoteTransport:
    """A two-level remote share: ``/share`` → a file, a subdir, and a symlink (not traversed)."""
    tree: dict[str, list[FakeStat]] = {
        "/share": [
            FakeStat("readme.txt", "/share/readme.txt", False, False, 20, 111.0, 1000, 1000),
            FakeStat("docs", "/share/docs", True, False, 0, 112.0, 1000, 1000),
            FakeStat("link", "/share/link", True, True, 0, 113.0, 1000, 1000),
        ],
        "/share/docs": [
            FakeStat("guide.pdf", "/share/docs/guide.pdf", False, False, 4096, 120.0, 1000, 1000),
        ],
        # The symlink target — must NOT be listed unless follow_symlinks is set.
        "/share/link": [
            FakeStat("secret.txt", "/share/link/secret.txt", False, False, 9, 99.0, 0, 0),
        ],
    }
    return FakeRemoteTransport(tree=tree)


def stat_of(path: Path) -> os.stat_result:
    """Convenience: ``os.lstat`` a fixture path (used by direct ``_entry``/``_annotate`` tests)."""
    return os.lstat(path)
