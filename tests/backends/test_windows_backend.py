"""WindowsBackend (ADR-027 W1) — fail-closed contracts everywhere; walk on real Windows.

The pure contracts (root validation, the W1 full-bit refusal, platform gating, registry
ordering) run on every platform. The walk/volume integration tests need a real Windows
filesystem and run in the windows-latest CI lane (they skip elsewhere).
"""

from __future__ import annotations

import os

import pytest

from fathom.backends.base import SYNTHETIC_UID, FullBitUnsupportedError
from fathom.backends.registry import build_default_registry
from fathom.backends.windows import WindowsBackend
from fathom.security.paths import PathSafetyError

windows_only = pytest.mark.skipif(os.name != "nt", reason="needs a real Windows filesystem")


# ----------------------------------------------------------------- portable contracts


async def test_open_for_hash_refuses_in_w1() -> None:
    # A hard, regression-tested refusal (like the remote backends) — not a config flag.
    with pytest.raises(FullBitUnsupportedError):
        await WindowsBackend().open_for_hash("C:\\data\\file.bin")


async def test_walk_rejects_invalid_roots_fail_closed() -> None:
    backend = WindowsBackend()
    for bad_root in ("relative\\path", "C:data", "C:\\report.txt:ads"):
        with pytest.raises(PathSafetyError):
            async for _ in backend.walk(bad_root):  # pragma: no cover - must raise first
                raise AssertionError("walk yielded from an invalid root")


def test_supports_is_false_off_windows() -> None:
    if os.name != "nt":
        assert WindowsBackend().supports("C:\\Data") is False


def test_registry_includes_windows_backend_only_on_windows() -> None:
    names = [type(b).__name__ for b in build_default_registry().backends]
    if os.name == "nt":
        assert names[0] == "WindowsBackend"  # first match wins on local Windows paths
    else:
        assert "WindowsBackend" not in names
    assert names[-1] == "PosixBackend"  # the documented always-last invariant


async def test_is_busy_is_false() -> None:
    assert await WindowsBackend().is_busy() is False


# ----------------------------------------------------------- Windows-only integration


@windows_only
async def test_walk_yields_entries_with_identity_and_synthetic_owner(tmp_path) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "file.txt").write_bytes(b"fathomline")
    backend = WindowsBackend()

    entries = {e.name: e async for e in backend.walk(str(tmp_path))}
    assert "sub" in entries and "file.txt" in entries
    f = entries["file.txt"]
    assert f.size_logical == len(b"fathomline")
    assert f.inode != 0 and f.dev != 0  # NTFS file id + volume serial → identity holds
    assert f.uid == SYNTHETIC_UID and f.flags.get("synthetic_owner") is True


@windows_only
async def test_volume_info_reports_capacity(tmp_path) -> None:  # type: ignore[no-untyped-def]
    info = await WindowsBackend().volume_info(str(tmp_path))
    assert info.total > 0 and info.free >= 0
    assert info.device.startswith("volume-serial-")
