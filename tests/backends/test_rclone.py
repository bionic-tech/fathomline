"""rclone backend (ADR-028) — walk/mapping logic against a fake runner; live error mapping.

No real rclone binary or network: a fake :class:`RcloneRunner` returns canned ``lsjson`` output,
so the FsEntry mapping, mount-key matching, and the inherited full-bit refusal are all exercised
hermetically. The live subprocess runner's "rclone not installed" mapping is checked with a bogus
binary path (real ``create_subprocess_exec`` raising ``FileNotFoundError``).
"""

from __future__ import annotations

import pytest

from fathom.agent.config import RemoteBackendConfig
from fathom.backends.base import SYNTHETIC_UID, FullBitUnsupportedError
from fathom.backends.rclone import (
    RcloneBackend,
    RcloneEntry,
    RcloneRunner,
    _parse_modtime,
    _SubprocessRcloneRunner,
)
from fathom.backends.remote import MissingClientLibraryError


def _cfg(remote_path: str = "/Backups") -> RemoteBackendConfig:
    return RemoteBackendConfig(protocol="rclone", host="gdrive", remote_path=remote_path)


class _FakeRunner(RcloneRunner):
    def __init__(self, entries: list[RcloneEntry], about: tuple[int, int, int] = (0, 0, 0)) -> None:
        self._entries = entries
        self._about = about
        self.seen_remote: str | None = None

    async def lsjson(self, remote: str) -> list[RcloneEntry]:
        self.seen_remote = remote
        return self._entries

    async def about(self, remote: str) -> tuple[int, int, int]:
        self.seen_remote = remote
        return self._about


# ------------------------------------------------------------------ config / mount key


def test_mount_key_and_remote_composition() -> None:
    cfg = _cfg("/Backups")
    assert cfg.mount_key == "rclone://gdrive/Backups"
    backend = RcloneBackend(cfg, runner=_FakeRunner([]))
    assert backend.supports("rclone://gdrive/Backups") is True
    assert backend.supports("rclone://gdrive/Other") is False
    assert backend._remote() == "gdrive:Backups"


def test_root_remote_path_targets_remote_root() -> None:
    assert RcloneBackend(_cfg("/"), runner=_FakeRunner([]))._remote() == "gdrive:"


def test_rclone_config_rejects_credentials() -> None:
    # rclone auth is in rclone.conf, never in the agent config.
    with pytest.raises(ValueError, match="no credential references"):
        RemoteBackendConfig(protocol="rclone", host="gdrive", password_ref="SECRET")


# ------------------------------------------------------------------ walk / mapping


async def test_walk_maps_entries_under_remote_path() -> None:
    runner = _FakeRunner(
        [
            RcloneEntry(path="sub", name="sub", is_dir=True, size=0, mtime=0.0),
            RcloneEntry(path="sub/a.bin", name="a.bin", is_dir=False, size=4096, mtime=1700.0),
        ]
    )
    backend = RcloneBackend(_cfg("/Backups"), runner=runner)
    entries = {e.name: e async for e in backend.walk("rclone://gdrive/Backups")}

    assert runner.seen_remote == "gdrive:Backups"
    f = entries["a.bin"]
    # Anchored under the synthetic catalogue_mount (ADR-029): /rclone/<host>/<subpath>.
    assert f.path == "/rclone/gdrive/Backups/sub/a.bin"
    assert f.size_logical == 4096 and f.size_on_disk == 4096  # no allocation info → equal
    assert f.inode != 0  # stable path-derived synthetic inode (no collisions; ADR-029)
    # Cloud objects have no POSIX ownership → synthetic + flagged so the UI never implies a perm.
    assert f.uid == SYNTHETIC_UID and f.flags.get("synthetic_owner") is True
    assert entries["sub"].is_dir is True


def test_entry_from_json_clamps_unknown_size() -> None:
    e = RcloneEntry.from_json({"Path": "x", "Name": "x", "IsDir": False, "Size": -1})
    assert e.size == 0  # rclone uses -1 for unknown; never negative


async def test_volume_info_reports_about_capacity() -> None:
    backend = RcloneBackend(_cfg("/"), runner=_FakeRunner([], about=(1000, 400, 600)))
    info = await backend.volume_info("rclone://gdrive/")
    assert (info.total, info.used, info.free) == (1000, 400, 600)
    assert info.fs_type == "rclone" and info.transport == "network"
    # Synthetic mountpoint + pretty display label (ADR-029).
    assert info.mountpoint == "/rclone/gdrive" and info.display_name == "rclone://gdrive/"


# ------------------------------------------------------------------ inherited refusal


async def test_open_for_hash_refuses() -> None:
    # Full-bit content hashing never runs over rclone (would download the file).
    with pytest.raises(FullBitUnsupportedError):
        await RcloneBackend(_cfg(), runner=_FakeRunner([])).open_for_hash("/Backups/a.bin")


async def test_is_busy_is_false() -> None:
    assert await RcloneBackend(_cfg(), runner=_FakeRunner([])).is_busy() is False


# ------------------------------------------------------------------ ModTime parsing


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("2021-01-02T15:04:05Z", True),
        ("2021-01-02T15:04:05.123456789Z", True),  # nanoseconds trimmed to micros
        ("2021-01-02T15:04:05.5+00:00", True),
        ("", False),
        ("not-a-date", False),
        (None, False),
    ],
)
def test_parse_modtime(value: object, ok: bool) -> None:
    out = _parse_modtime(value)
    assert (out > 0) is ok


# ------------------------------------------------------------------ live runner error mapping


async def test_subprocess_runner_maps_missing_binary() -> None:
    runner = _SubprocessRcloneRunner("/nonexistent/rclone-binary-xyz")
    with pytest.raises(MissingClientLibraryError):
        await runner.lsjson("gdrive:Backups")


# ----------------------------------------- subprocess robustness (timeout, output cap)
# These drive a tiny real subprocess (python itself) — hermetic, no rclone needed.

import sys  # noqa: E402

from fathom.backends.remote import RemoteBackendError  # noqa: E402


async def test_subprocess_runner_times_out_on_hung_process() -> None:
    # A hung `rclone` must not block the agent forever (review HIGH).
    runner = _SubprocessRcloneRunner(sys.executable, timeout=0.2)
    with pytest.raises(RemoteBackendError, match="timed out"):
        await runner._run("-c", "import time; time.sleep(30)")


async def test_subprocess_runner_fails_loud_over_output_cap() -> None:
    # A huge listing fails LOUD at the byte ceiling instead of OOM-ing (review HIGH).
    runner = _SubprocessRcloneRunner(sys.executable, max_output_bytes=64)
    with pytest.raises(RemoteBackendError, match="exceeded"):
        await runner._run("-c", "print('x' * 100000)")


async def test_subprocess_runner_surfaces_nonzero_exit_with_stderr() -> None:
    runner = _SubprocessRcloneRunner(sys.executable)
    with pytest.raises(RemoteBackendError, match=r"failed \(exit 3"):
        await runner._run("-c", "import sys; sys.stderr.write('boom'); sys.exit(3)")


# ----------------------------------------- JSON parsing guards (override _run; no subprocess)


async def test_lsjson_rejects_invalid_json() -> None:
    runner = _SubprocessRcloneRunner("rclone")

    async def fake(*_a: str) -> bytes:
        return b"{not json"

    runner._run = fake  # type: ignore[method-assign]
    with pytest.raises(RemoteBackendError, match="invalid JSON"):
        await runner.lsjson("gdrive:")


async def test_lsjson_rejects_non_array_root() -> None:
    runner = _SubprocessRcloneRunner("rclone")

    async def fake(*_a: str) -> bytes:
        return b'{"entries": []}'

    runner._run = fake  # type: ignore[method-assign]
    with pytest.raises(RemoteBackendError, match="did not return a JSON array"):
        await runner.lsjson("gdrive:")


async def test_lsjson_skips_non_dict_elements_and_empty_output() -> None:
    runner = _SubprocessRcloneRunner("rclone")

    async def one_bad(*_a: str) -> bytes:
        return b'[{"Path":"a","Name":"a","IsDir":false,"Size":1}, "junk", 42]'

    runner._run = one_bad  # type: ignore[method-assign]
    entries = await runner.lsjson("gdrive:")
    assert [e.name for e in entries] == ["a"]  # non-dict elements silently skipped

    async def empty(*_a: str) -> bytes:
        return b""

    runner._run = empty  # type: ignore[method-assign]
    assert await runner.lsjson("gdrive:") == []


@pytest.mark.parametrize("payload", [b"null", b"[1,2,3]", b'"a string"'])
async def test_about_degrades_to_zero_on_non_dict_json(payload: bytes) -> None:
    runner = _SubprocessRcloneRunner("rclone")

    async def fake(*_a: str) -> bytes:
        return payload

    runner._run = fake  # type: ignore[method-assign]
    assert await runner.about("gdrive:") == (0, 0, 0)


def test_entry_from_json_saturates_oversized_size() -> None:
    # Corrupted/hostile remote metadata must not overflow the catalogue's int64 size column.
    huge = RcloneEntry.from_json({"Path": "x", "Name": "x", "Size": 10**30})
    assert huge.size == 2**63 - 1


# ----------------------------------------- provider hashes (ADR-028 phase 2)

from fathom.backends.rclone import _pick_provider_hash  # noqa: E402


def test_pick_provider_hash_prefers_stronger_algo() -> None:
    algo, value = _pick_provider_hash({"md5": "a" * 32, "sha256": "b" * 64})
    assert (algo, value) == ("sha256", "b" * 64)  # sha256 outranks md5 in the preference order


def test_pick_provider_hash_skips_malformed_values() -> None:
    # A value that fails the bounds/charset guard is skipped, not truncated (can't break the push).
    algo, value = _pick_provider_hash({"sha1": "has spaces!", "md5": "c" * 32})
    assert (algo, value) == ("md5", "c" * 32)
    assert _pick_provider_hash({}) == (None, None)
    assert _pick_provider_hash({"unknownalgo": "d" * 32}) == (None, None)


def test_entry_from_json_extracts_provider_hash() -> None:
    e = RcloneEntry.from_json(
        {"Path": "a.bin", "Name": "a.bin", "Size": 10, "Hashes": {"md5": "f" * 32}}
    )
    assert e.provider_hash == "f" * 32 and e.provider_hash_algo == "md5"


async def test_walk_carries_provider_hash_on_files_not_dirs() -> None:
    runner = _FakeRunner(
        [
            RcloneEntry(path="d", name="d", is_dir=True, size=0, mtime=0.0),
            RcloneEntry(
                path="d/a.bin",
                name="a.bin",
                is_dir=False,
                size=10,
                mtime=0.0,
                provider_hash="a" * 32,
                provider_hash_algo="md5",
            ),
        ]
    )
    backend = RcloneBackend(_cfg("/Backups"), runner=runner)
    entries = {e.name: e async for e in backend.walk("rclone://gdrive/Backups")}
    assert entries["a.bin"].provider_hash == "a" * 32
    assert entries["a.bin"].provider_hash_algo == "md5"
    # A directory never carries a content hash.
    assert entries["d"].provider_hash is None
