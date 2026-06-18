"""Tests for the SQLite staging store — idempotency & change-guard (ADD 02 §7.2, ADD 09)."""

from __future__ import annotations

import time
from pathlib import Path

from fathom.agent.staging import StagingStore
from fathom.backends.base import FsEntry


def _entry(
    inode: int, *, size: int = 100, mtime: float = 1000.0, name: str = "f", dev: int = 0
) -> FsEntry:
    return FsEntry(
        path=f"/vol/{name}",
        name=name,
        is_dir=False,
        is_symlink=False,
        size_logical=size,
        size_on_disk=size,
        mtime=mtime,
        ctime=mtime,
        uid=568,
        gid=568,
        inode=inode,
        dev=dev,
        flags={},
    )


def _store(tmp_path: Path) -> StagingStore:
    return StagingStore(tmp_path / "staging.sqlite")


def _run(store: StagingStore) -> int:
    return store.start_run(
        host_id="h", volume_id="/vol", mode="metadata", root="/vol", started_at=time.time()
    )


def test_first_stage_counts_all(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run = _run(store)
        changed = store.stage_batch(
            run_id=run, host_id="h", volume_id="/vol", entries=[_entry(1), _entry(2)]
        )
        assert changed == 2
        assert store.count_unpushed() == 2


def test_restage_unchanged_is_noop(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run = _run(store)
        store.stage_batch(run_id=run, host_id="h", volume_id="/vol", entries=[_entry(1)])
        # Same inode, same (mtime, size) → change guard suppresses the write.
        changed = store.stage_batch(run_id=run, host_id="h", volume_id="/vol", entries=[_entry(1)])
        assert changed == 0


def test_restage_changed_updates(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run = _run(store)
        store.stage_batch(run_id=run, host_id="h", volume_id="/vol", entries=[_entry(1, size=100)])
        changed = store.stage_batch(
            run_id=run, host_id="h", volume_id="/vol", entries=[_entry(1, size=200)]
        )
        assert changed == 1
        rows = list(store.iter_unpushed())
        assert len(rows) == 1
        assert rows[0]["size_logical"] == 200


def test_same_inode_different_dev_are_distinct_rows(tmp_path: Path) -> None:
    # The cross-dataset bug: a cross_mounts walk spans ZFS child datasets that each reuse low
    # inode numbers, so two DIFFERENT files share one inode. With dev in the staging key they
    # stage as two distinct rows instead of one clobbering the other (the live data loss).
    with _store(tmp_path) as store:
        run = _run(store)
        changed = store.stage_batch(
            run_id=run,
            host_id="h",
            volume_id="/vol",
            entries=[
                _entry(1, size=100, name="dataset_a_file", dev=64769),
                _entry(1, size=200, name="dataset_b_file", dev=64770),
            ],
        )
        assert changed == 2
        assert store.count_unpushed() == 2
        rows = sorted(store.iter_unpushed(), key=lambda r: r["dev"])
        assert [(r["dev"], r["inode"], r["size_logical"]) for r in rows] == [
            (64769, 1, 100),
            (64770, 1, 200),
        ]


def test_finish_run_records_count(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        run = _run(store)
        store.stage_batch(run_id=run, host_id="h", volume_id="/vol", entries=[_entry(1)])
        store.finish_run(run, finished_at=time.time(), entry_count=1)
        row = store._conn.execute(
            "SELECT finished_at, entry_count FROM scan_run WHERE id = ?", (run,)
        ).fetchone()
        assert row["entry_count"] == 1
        assert row["finished_at"] is not None
