"""FullBitScanner tests — ack gating, resync block, load pause, progressive funnel.

Covers the fullbit-dedup test_plan: ack required, resync blocks full-bit, load pauses between
hash batches, and the funnel only fully-hashes size+partial colliders (never opens a unique
size, never fully-hashes a unique partial). Uses real bytes through ``PosixBackend`` + BLAKE3
and a real SQLite staging store so the staged hashes are asserted end-to-end.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from fathom.agent.config import ThrottleProfile
from fathom.agent.reader import (
    AcknowledgementRequired,
    FullBitBlocked,
    FullBitScanner,
    LoadSupervisor,
    MetadataScanner,
    WarningAck,
)
from fathom.agent.reader.hasher import BackendHasher
from fathom.agent.staging.store import StagingStore
from fathom.backends import PosixBackend
from fathom.core.dedup import Candidate

HOST = "nas-1"


def _throttle(*, block_fullbit: bool = True) -> ThrottleProfile:
    return ThrottleProfile.model_validate(
        {
            "pause_when": {"load1_above": 6.0, "iowait_above_percent": 25},
            "resume_when": {"load1_below": 3.0},
            "hard_rules": {"block_fullbit_during_raid_resync": block_fullbit},
        }
    )


def _fullbit_ack(target: str) -> WarningAck:
    return WarningAck(
        operator="mo",
        acknowledged_at=datetime.now(tz=UTC),
        target=f"{target} (backing device class: usb RAID5)",
        mode="fullbit",
    )


async def _stage_metadata(tree: Path, staging: StagingStore, backend: PosixBackend) -> str:
    """Stage the tree metadata so the full-bit pass has staged rows to update with hashes."""
    sup = LoadSupervisor(_throttle(), load1_provider=lambda: 0.0, resync_provider=lambda: False)
    scanner = MetadataScanner(backend=backend, staging=staging, supervisor=sup, host_id=HOST)
    ack = WarningAck(
        operator="mo", acknowledged_at=datetime.now(tz=UTC), target=str(tree), mode="metadata"
    )
    result = await scanner.scan(str(tree), warning_ack=ack)
    return result.volume.mountpoint


def _candidates(staging: StagingStore, volume_id: str, root: str) -> list[Candidate]:
    rows = staging.iter_candidates(host_id=HOST, volume_id=volume_id, scope_prefix=root)
    return [
        Candidate(id=r["inode"], path=r["path"], size=r["size_logical"], dev=r["dev"]) for r in rows
    ]


def _scanner(backend: PosixBackend, staging: StagingStore, sup: LoadSupervisor) -> FullBitScanner:
    return FullBitScanner(
        backend=backend,
        hasher=BackendHasher(backend),
        staging=staging,
        supervisor=sup,
        host_id=HOST,
    )


async def test_fullbit_requires_ack(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"A" * 100)
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        sup = LoadSupervisor(_throttle(), resync_provider=lambda: False)
        scanner = _scanner(backend, staging, sup)
        with pytest.raises(AcknowledgementRequired):
            await scanner.scan(str(tmp_path), [], volume_id=volume_id, warning_ack=None)


async def test_fullbit_rejects_metadata_ack(tmp_path: Path) -> None:
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        sup = LoadSupervisor(_throttle(), resync_provider=lambda: False)
        scanner = _scanner(backend, staging, sup)
        metadata_ack = WarningAck(
            operator="mo",
            acknowledged_at=datetime.now(tz=UTC),
            target=str(tmp_path),
            mode="metadata",
        )
        with pytest.raises(AcknowledgementRequired):
            await scanner.scan(str(tmp_path), [], volume_id=volume_id, warning_ack=metadata_ack)


async def test_fullbit_blocked_during_raid_resync(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"A" * 100)
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        # Resync provider reports an array resyncing → full-bit must refuse.
        sup = LoadSupervisor(_throttle(), resync_provider=lambda: True)
        scanner = _scanner(backend, staging, sup)
        cands = _candidates(staging, volume_id, str(tmp_path))
        with pytest.raises(FullBitBlocked):
            await scanner.scan(
                str(tmp_path), cands, volume_id=volume_id, warning_ack=_fullbit_ack(str(tmp_path))
            )


async def test_fullbit_pauses_on_load(tmp_path: Path) -> None:
    # Two identical files → at least one full-hash batch → wait_if_paused holds while load high.
    (tmp_path / "a.bin").write_bytes(b"A" * 5000)
    (tmp_path / "b.bin").write_bytes(b"A" * 5000)
    backend = PosixBackend()
    sleeps: list[float] = []
    state = {"load": 9.0}

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        state["load"] = 0.0  # recover after one sample

    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        sup = LoadSupervisor(
            _throttle(),
            load1_provider=lambda: state["load"],
            resync_provider=lambda: False,
            sleeper=fake_sleep,
        )
        scanner = _scanner(backend, staging, sup)
        cands = _candidates(staging, volume_id, str(tmp_path))
        await scanner.scan(
            str(tmp_path), cands, volume_id=volume_id, warning_ack=_fullbit_ack(str(tmp_path))
        )
    assert sleeps, "rising load must pause hashing between batches"


async def test_fullbit_funnel_skips_unique_sizes(tmp_path: Path) -> None:
    # Unique size → never opened/hashed; two same-size+identical → fully hashed and staged.
    (tmp_path / "dup1.bin").write_bytes(b"X" * 4000)
    (tmp_path / "dup2.bin").write_bytes(b"X" * 4000)  # identical to dup1
    (tmp_path / "unique.bin").write_bytes(b"Y" * 7777)  # unique size
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        sup = LoadSupervisor(_throttle(), load1_provider=lambda: 0.0, resync_provider=lambda: False)
        scanner = _scanner(backend, staging, sup)
        cands = _candidates(staging, volume_id, str(tmp_path))
        result = await scanner.scan(
            str(tmp_path), cands, volume_id=volume_id, warning_ack=_fullbit_ack(str(tmp_path))
        )
        # Only the two same-size colliders are fully hashed; the unique-size file is never opened.
        assert result.full_hashed == 2
        names = {Path(r["path"]).name for r in staging.iter_unpushed_hashes()}
        assert names == {"dup1.bin", "dup2.bin"}
        assert "unique.bin" not in names


async def test_fullbit_funnel_skips_unique_partials(tmp_path: Path) -> None:
    # Same size, different head/tail → partials differ → never fully hashed (funnel correctness).
    (tmp_path / "a.bin").write_bytes(b"A" + b"\x00" * 4998 + b"A")
    (tmp_path / "b.bin").write_bytes(b"B" + b"\x00" * 4998 + b"B")  # same size, different ends
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        sup = LoadSupervisor(_throttle(), load1_provider=lambda: 0.0, resync_provider=lambda: False)
        scanner = _scanner(backend, staging, sup)
        cands = _candidates(staging, volume_id, str(tmp_path))
        result = await scanner.scan(
            str(tmp_path), cands, volume_id=volume_id, warning_ack=_fullbit_ack(str(tmp_path))
        )
        assert result.partial_hashed == 2
        assert result.full_hashed == 0  # partials differ → short-circuited before full hash
        assert list(staging.iter_unpushed_hashes()) == []


async def test_fullbit_stages_hashes_resumably(tmp_path: Path) -> None:
    # The staged hashes carry on the same (host, volume, inode) row, unpushed, ready to drain.
    (tmp_path / "x.bin").write_bytes(b"Z" * 6000)
    (tmp_path / "y.bin").write_bytes(b"Z" * 6000)
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        sup = LoadSupervisor(_throttle(), load1_provider=lambda: 0.0, resync_provider=lambda: False)
        scanner = _scanner(backend, staging, sup)
        cands = _candidates(staging, volume_id, str(tmp_path))
        result = await scanner.scan(
            str(tmp_path), cands, volume_id=volume_id, warning_ack=_fullbit_ack(str(tmp_path))
        )
        rows = staging.iter_unpushed_hashes()
        assert len(rows) == 2
        full_hashes = {r["full_hash"] for r in rows}
        assert len(full_hashes) == 1  # identical bytes → identical full hash
        assert all(len(h) == 64 for h in full_hashes)  # BLAKE3 hexdigest
        assert len(result.hashed_keys) == 2


async def test_streaming_path_finds_dups_without_materialising_all(tmp_path: Path) -> None:
    # The PRODUCTION path (ADR-025 scan-fix): collision_sizes + candidates_of_size feed
    # scan_grouped one size-bucket at a time. Only sizes shared by >=2 files are ever streamed —
    # a unique size is never even loaded — and the dup is still found end-to-end.
    (tmp_path / "dup1.bin").write_bytes(b"Q" * 4096)
    (tmp_path / "dup2.bin").write_bytes(b"Q" * 4096)  # identical → collision size
    (tmp_path / "lonely.bin").write_bytes(b"W" * 12345)  # unique size → never streamed
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        root = str(tmp_path)

        # collision_sizes includes the shared size (4096) but NEVER the unique one (12345) — a
        # unique size can have no content duplicate, so it is never even loaded/streamed.
        sizes = staging.collision_sizes(host_id=HOST, volume_id=volume_id, scope_prefix=root)
        assert 4096 in sizes
        assert 12345 not in sizes

        async def _groups() -> object:
            for size in sizes:
                rows = staging.candidates_of_size(
                    host_id=HOST, volume_id=volume_id, scope_prefix=root, size=size
                )
                yield [
                    Candidate(id=r["inode"], path=r["path"], size=r["size_logical"], dev=r["dev"])
                    for r in rows
                ]

        sup = LoadSupervisor(_throttle(), load1_provider=lambda: 0.0, resync_provider=lambda: False)
        scanner = _scanner(backend, staging, sup)
        result = await scanner.scan_grouped(
            root, _groups(), volume_id=volume_id, warning_ack=_fullbit_ack(root)
        )
        # The two identical 4096-byte colliders are fully hashed + staged; lonely.bin (unique size)
        # is never opened, so it never reaches a hash.
        assert result.full_hashed == 2
        names = {Path(r["path"]).name for r in staging.iter_unpushed_hashes()}
        assert names == {"dup1.bin", "dup2.bin"}
        assert "lonely.bin" not in names


async def test_open_for_hash_nofollow(tmp_path: Path) -> None:
    # The reader refuses to traverse a symlink for content hashing (O_NOFOLLOW; read != write).
    real = tmp_path / "real.bin"
    real.write_bytes(b"secret")
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    backend = PosixBackend()
    with pytest.raises(OSError):
        await backend.open_for_hash(str(link))


class _FlakyFullHasher(BackendHasher):
    """A real BackendHasher that raises OSError on full() for one path (a file that vanished)."""

    def __init__(self, backend: PosixBackend, fail_path: str) -> None:
        super().__init__(backend)
        self._fail_path = fail_path

    async def full(self, path: str) -> str:
        if path == self._fail_path:
            raise FileNotFoundError(path)
        return await super().full(path)


async def test_fullbit_skips_vanished_file_without_aborting_scope(tmp_path: Path) -> None:
    # TOCTOU: a file vanishes / loses read access between the metadata walk and the full-bit pass.
    # The funnel must skip just that file and still hash + stage the rest — one transient file must
    # never abort content-hashing for the whole scope (regression).
    for name in ("a.bin", "b.bin", "c.bin"):
        (tmp_path / name).write_bytes(b"DUP" * 1000)  # identical → one dup group, fully hashed
    backend = PosixBackend()
    with StagingStore(tmp_path / "stage.db") as staging:
        volume_id = await _stage_metadata(tmp_path, staging, backend)
        sup = LoadSupervisor(_throttle(), resync_provider=lambda: False)
        gone = str(tmp_path / "b.bin")
        scanner = FullBitScanner(
            backend=backend,
            hasher=_FlakyFullHasher(backend, gone),
            staging=staging,
            supervisor=sup,
            host_id=HOST,
        )
        candidates = _candidates(staging, volume_id, str(tmp_path))
        result = await scanner.scan(
            str(tmp_path), candidates, volume_id=volume_id, warning_ack=_fullbit_ack(str(tmp_path))
        )
        # a.bin + c.bin fully hashed + staged; the vanished b.bin skipped, not fatal.
        assert result.full_hashed == 2
