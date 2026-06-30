"""WindowsBackend (ADR-027) — fail-closed contracts everywhere; walk on real Windows.

The pure contracts (root validation, the W2 full-bit never-hydrate rule, platform gating,
registry ordering) run on every platform. The walk/volume integration tests need a real
Windows filesystem and run in the windows-latest CI lane (they skip elsewhere).
"""

from __future__ import annotations

import os

import pytest

from fathom.backends.base import SYNTHETIC_UID, PlaceholderNotHydratedError
from fathom.backends.registry import build_default_registry
from fathom.backends.winattrs import ATTR_RECALL_ON_DATA_ACCESS, ATTR_REPARSE_POINT
from fathom.backends.windows import WindowsBackend
from fathom.security.paths import PathSafetyError

windows_only = pytest.mark.skipif(os.name != "nt", reason="needs a real Windows filesystem")


# ----------------------------------------------------------------- portable contracts


async def test_open_for_hash_reads_a_plain_local_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # W2: a plain local file (no placeholder/reparse attributes — 0 on POSIX) is opened + streamed.
    f = tmp_path / "data.bin"
    f.write_bytes(b"fathomline-bytes")
    reader = await WindowsBackend().open_for_hash(str(f))
    try:
        assert await reader.read(1024) == b"fathomline-bytes"
    finally:
        await reader.close()


@pytest.mark.parametrize(
    ("attrs", "what"),
    [(ATTR_RECALL_ON_DATA_ACCESS, "cloud placeholder"), (ATTR_REPARSE_POINT, "reparse point")],
)
async def test_open_for_hash_refuses_placeholder_or_reparse_without_opening(
    tmp_path,  # type: ignore[no-untyped-def]
    monkeypatch,  # type: ignore[no-untyped-def]
    attrs: int,
    what: str,
) -> None:
    # The open is what hydrates a cloud placeholder, so open_for_hash must refuse on the stat
    # classification BEFORE opening. Force the attributes; assert it raises (and never opens).
    f = tmp_path / "ghost.bin"
    f.write_bytes(b"x")
    monkeypatch.setattr("fathom.backends.windows.entry_attributes", lambda _st: attrs)
    opened: list[str] = []
    monkeypatch.setattr(
        WindowsBackend, "_open_for_read", staticmethod(lambda p: opened.append(p))  # type: ignore[arg-type]
    )
    with pytest.raises(PlaceholderNotHydratedError):
        await WindowsBackend().open_for_hash(str(f))
    assert opened == []  # never opened → never hydrated


def test_placeholder_error_is_oserror_so_the_funnel_skips_it() -> None:
    # The full-bit funnel skips per-file OSErrors (metadata kept, scope not aborted); the
    # placeholder refusal MUST be an OSError so one cloud file never kills content-hashing.
    assert issubclass(PlaceholderNotHydratedError, OSError)


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
