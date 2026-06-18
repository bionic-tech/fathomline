"""Tests for the NTFS/exFAT backend (storage-backends test_plan: synthetic owner, ADS flag)."""

from __future__ import annotations

from pathlib import Path

import pytest

from fathom.backends import NtfsExfatBackend, StorageBackend
from fathom.backends.base import SYNTHETIC_GID, SYNTHETIC_UID


def _force_fs(backend: NtfsExfatBackend, fs_type: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the backend resolve any mount to ``fs_type`` (no real NTFS/exFAT mount in CI)."""
    monkeypatch.setattr(backend, "_resolve_mount", lambda real: (f"/dev/fake-{fs_type}", fs_type))


def test_ntfs_satisfies_protocol() -> None:
    assert isinstance(NtfsExfatBackend(), StorageBackend)


async def _collect(backend: NtfsExfatBackend, root: Path) -> dict[str, object]:
    return {e.path: e async for e in backend.walk(str(root))}


async def test_exfat_synthesises_owner_and_flags(
    exfat_like_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = NtfsExfatBackend(walk_concurrency=2)
    _force_fs(backend, "exfat", monkeypatch)
    entries = await _collect(backend, exfat_like_tree)

    file_entry = entries[str(exfat_like_tree / "file.txt")]
    # FAT/exFAT have no ownership model → sentinel uid/gid, flagged so the UI never implies a perm.
    assert file_entry.uid == SYNTHETIC_UID
    assert file_entry.gid == SYNTHETIC_GID
    assert file_entry.flags.get("synthetic_owner") is True


async def test_vfat_also_synthesises_owner(
    exfat_like_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = NtfsExfatBackend()
    _force_fs(backend, "vfat", monkeypatch)
    entries = await _collect(backend, exfat_like_tree)
    sub = entries[str(exfat_like_tree / "sub" / "more.txt")]
    assert sub.uid == SYNTHETIC_UID
    assert sub.flags.get("synthetic_owner") is True


async def test_ntfs_keeps_real_ownership_no_synthetic_flag(
    exfat_like_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = NtfsExfatBackend()
    _force_fs(backend, "ntfs", monkeypatch)
    entries = await _collect(backend, exfat_like_tree)
    file_entry = entries[str(exfat_like_tree / "file.txt")]
    # NTFS preserves ownership — the synthetic-owner substitution must NOT fire.
    assert file_entry.uid != SYNTHETIC_UID
    assert "synthetic_owner" not in file_entry.flags


async def test_ntfs_ads_flag_when_xattr_present(
    exfat_like_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = NtfsExfatBackend()
    _force_fs(backend, "ntfs", monkeypatch)
    # Simulate ntfs-3g surfacing a named stream as a ``user.*`` xattr on file.txt.
    target = str(exfat_like_tree / "file.txt")
    monkeypatch.setattr(
        NtfsExfatBackend,
        "_has_ads",
        staticmethod(lambda path: path == target),
    )
    entries = await _collect(backend, exfat_like_tree)
    assert entries[target].flags.get("ads") is True
    # A file without the stream must not be flagged.
    other = entries[str(exfat_like_tree / "sub" / "more.txt")]
    assert "ads" not in other.flags


async def test_ntfs_compressed_flag_when_on_disk_below_logical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A sparse file stands in for NTFS compression (on-disk < logical) in the conformance fixture.
    root = tmp_path / "ntfs"
    root.mkdir()
    sparse = root / "big.dat"
    with sparse.open("wb") as fh:
        fh.seek(1024 * 1024 - 1)
        fh.write(b"\x00")

    backend = NtfsExfatBackend()
    _force_fs(backend, "ntfs", monkeypatch)
    entries = await _collect(backend, root)
    entry = entries[str(sparse)]
    if entry.size_on_disk < entry.size_logical:
        assert entry.flags.get("compressed") is True


def test_supports_rejects_non_ntfs_fs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    backend = NtfsExfatBackend()
    monkeypatch.setattr(backend, "_resolve_mount", lambda real: ("/dev/sda1", "ext4"))
    assert backend.supports(str(tmp_path)) is False
    monkeypatch.setattr(backend, "_resolve_mount", lambda real: ("/dev/sda1", "exfat"))
    assert backend.supports(str(tmp_path)) is True
