"""Shared test fixtures — a small on-disk tree exercising the metadata-walk edge cases."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def fixture_tree(tmp_path: Path) -> Path:
    """Build a tree with nested dirs, a symlink, an empty file, and a sparse file.

    Layout::

        root/
          a.txt                 (12 bytes)
          sub/
            b.bin               (4096 bytes)
            empty.txt           (0 bytes)
          link -> sub           (symlink, not traversed by default)
          sparse.dat            (sparse: logical 1 MiB, ~0 on disk)
    """
    root = tmp_path / "root"
    sub = root / "sub"
    sub.mkdir(parents=True)

    (root / "a.txt").write_bytes(b"hello world!")
    (sub / "b.bin").write_bytes(b"\x00" * 4096)
    (sub / "empty.txt").write_bytes(b"")

    # A symlink that points at a real directory; walk must report it but not descend.
    (root / "link").symlink_to(sub, target_is_directory=True)

    # A sparse file: seek past the end and write one byte → large logical, tiny on-disk.
    sparse = root / "sparse.dat"
    with sparse.open("wb") as fh:
        fh.seek(1024 * 1024 - 1)
        fh.write(b"\x00")
    # Best-effort: punch a hole so st_blocks stays small even on filesystems that would
    # otherwise allocate. Not all platforms support this; the test tolerates either.
    try:
        os.posix_fallocate  # noqa: B018 — attribute probe
    except AttributeError:  # pragma: no cover
        pass

    return root
