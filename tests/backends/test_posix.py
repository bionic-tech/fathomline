"""Tests for the generic read-only POSIX backend (ADD 02)."""

from __future__ import annotations

from pathlib import Path

import pytest

from fathom.agent.config import RemoteBackendConfig
from fathom.backends import (
    BackendRegistry,
    NoBackendError,
    NtfsExfatBackend,
    PosixBackend,
    SftpBackend,
    SmbBackend,
    StorageBackend,
    ZfsBackend,
    build_default_registry,
)


def test_posix_satisfies_protocol() -> None:
    assert isinstance(PosixBackend(), StorageBackend)


async def _collect(backend: PosixBackend, root: str) -> dict[str, object]:
    return {e.path: e async for e in backend.walk(root)}


async def test_walk_reports_all_entries(fixture_tree: Path) -> None:
    backend = PosixBackend(walk_concurrency=2)
    entries = await _collect(backend, str(fixture_tree))

    names = {Path(p).name for p in entries}
    assert {"root", "a.txt", "sub", "b.bin", "empty.txt", "link", "sparse.dat"} <= names


async def test_walk_prunes_excluded_subtree(fixture_tree: Path) -> None:
    # ADR-034: an excluded directory is neither reported nor descended into — its children vanish.
    backend = PosixBackend(walk_concurrency=2)
    sub = str(fixture_tree / "sub")
    entries = {e.path async for e in backend.walk(str(fixture_tree), exclude=[sub])}
    names = {Path(p).name for p in entries}
    assert "sub" not in names  # the excluded dir itself is not reported
    assert "b.bin" not in names and "empty.txt" not in names  # nor its contents (not descended)
    assert {"a.txt", "sparse.dat", "link"} <= names  # siblings still scanned


async def test_walk_excluded_root_yields_nothing(fixture_tree: Path) -> None:
    # Excluding the scan root itself prunes the whole walk (ADR-034).
    backend = PosixBackend(walk_concurrency=2)
    entries = [e async for e in backend.walk(str(fixture_tree), exclude=[str(fixture_tree)])]
    assert entries == []


async def test_walk_is_complete_under_tiny_bounded_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: the results queue is bounded for backpressure (no OOM at estate scale).
    # Force the bound to 1 and walk a tree far larger than it — every entry must still be
    # reported, with no deadlock or dropped entries (a slow consumer must not lose data).
    import fathom.backends.posix as posix_mod

    monkeypatch.setattr(posix_mod, "RESULTS_QUEUE_MAXSIZE", 1)
    big = tmp_path / "big"
    big.mkdir()
    expected = {str(big)}
    for i in range(60):
        d = big / f"d{i}"
        d.mkdir()
        f = d / "f.txt"
        f.write_text(str(i))
        expected.update({str(d), str(f)})

    backend = PosixBackend(walk_concurrency=3)
    seen = {e.path async for e in backend.walk(str(big))}
    assert seen == expected


async def test_walk_does_not_descend_symlink(fixture_tree: Path) -> None:
    backend = PosixBackend()
    entries = await _collect(backend, str(fixture_tree))

    link = entries[str(fixture_tree / "link")]
    assert link.is_symlink is True
    # The symlink target's contents must not be re-walked through the link path.
    assert not any(p.startswith(str(fixture_tree / "link") + "/") for p in entries)


async def test_walk_sizes(fixture_tree: Path) -> None:
    backend = PosixBackend()
    entries = await _collect(backend, str(fixture_tree))

    a = entries[str(fixture_tree / "a.txt")]
    assert a.size_logical == 12
    assert a.is_dir is False

    sparse = entries[str(fixture_tree / "sparse.dat")]
    assert sparse.size_logical == 1024 * 1024
    # On a hole-supporting FS the sparse flag is set; tolerate filesystems that allocate.
    assert sparse.size_on_disk <= sparse.size_logical


async def test_walk_missing_root_is_empty(tmp_path: Path) -> None:
    backend = PosixBackend()
    entries = await _collect(backend, str(tmp_path / "does-not-exist"))
    assert entries == {}


async def test_volume_info(fixture_tree: Path) -> None:
    backend = PosixBackend()
    info = await backend.volume_info(str(fixture_tree))
    assert info.total > 0
    assert info.used >= 0
    assert info.free >= 0
    assert info.mountpoint  # resolved


async def test_open_for_hash_reads_content(fixture_tree: Path) -> None:
    backend = PosixBackend()
    reader = await backend.open_for_hash(str(fixture_tree / "a.txt"))
    try:
        assert await reader.read(5) == b"hello"
        assert await reader.seek(0) == 0
        assert await reader.read(12) == b"hello world!"
    finally:
        await reader.close()


async def test_open_for_hash_refuses_symlink(fixture_tree: Path) -> None:
    backend = PosixBackend()
    # `link` is a symlink; O_NOFOLLOW must refuse to open through it.
    with pytest.raises(OSError):
        await backend.open_for_hash(str(fixture_tree / "link"))


def test_registry_first_match_wins() -> None:
    reg = BackendRegistry()
    posix = PosixBackend()
    reg.register(posix)
    assert reg.resolve("/") is posix


def test_registry_no_backend() -> None:
    reg = BackendRegistry()
    with pytest.raises(NoBackendError):
        reg.resolve("/definitely/not/a/dir/xyz")


def test_default_registry_orders_specialised_before_posix() -> None:
    # The whole subsystem is load-bearing on POSIX being LAST: specialised plugins must register
    # ahead of it so the most filesystem-aware backend wins (first-match-wins, ADR-004).
    reg = build_default_registry()
    types = [type(b) for b in reg.backends]
    assert types[0] is ZfsBackend
    assert types[1] is NtfsExfatBackend
    assert types[-1] is PosixBackend
    assert types.index(PosixBackend) == len(types) - 1


def test_default_registry_includes_remote_backends_ahead_of_posix() -> None:
    targets = [
        RemoteBackendConfig(protocol="smb", host="nas", share="media", remote_path="/m"),
        RemoteBackendConfig(protocol="sftp", host="nas", remote_path="/s"),
    ]
    reg = build_default_registry(remote_targets=targets)
    types = [type(b) for b in reg.backends]
    assert SmbBackend in types
    assert SftpBackend in types
    # POSIX is still the final fallback after every specialised + remote backend.
    assert types[-1] is PosixBackend


def test_default_registry_resolves_remote_target_to_its_backend() -> None:
    target = RemoteBackendConfig(protocol="smb", host="nas", share="media", remote_path="/m")
    reg = build_default_registry(remote_targets=[target])
    resolved = reg.resolve(target.mount_key)
    assert isinstance(resolved, SmbBackend)


def test_default_registry_falls_through_to_posix_for_plain_dir(tmp_path: Path) -> None:
    reg = build_default_registry()
    # A plain local dir on a non-ZFS/NTFS fs matches no specialised backend → POSIX fallback.
    resolved = reg.resolve(str(tmp_path))
    assert isinstance(resolved, PosixBackend)


def test_to_signed64_wraps_large_windows_file_ids() -> None:
    # Windows NTFS file IDs (st_ino) are unsigned 64-bit and can exceed the signed-64 max that
    # SQLite/Postgres store; _to_signed64 wraps them bijectively so staging never OverflowErrors.
    from fathom.backends.posix import _to_signed64

    assert _to_signed64(0) == 0
    assert _to_signed64((1 << 63) - 1) == (1 << 63) - 1
    big = (1 << 63) + 12345  # a real Windows file ID above the signed-64 boundary
    assert _to_signed64(big) == big - (1 << 64)
    assert -(1 << 63) <= _to_signed64((1 << 64) - 1) <= (1 << 63) - 1  # always fits signed-64
    assert _to_signed64(big) != _to_signed64(big + 1)  # distinct ids stay distinct
