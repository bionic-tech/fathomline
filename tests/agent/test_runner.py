"""Tests for the agent runner — scan→stage→(injected)drain wiring (ADD 02)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from fathom.agent.config import AgentConfig, RemoteBackendConfig
from fathom.agent.reader.feed import ChangeEvent, ChangeFeed
from fathom.agent.runner import run_agent, scan_one_root_now
from fathom.agent.staging.store import StagingStore
from fathom.backends import BackendRegistry, PosixBackend, SftpBackend
from fathom.backends.base import FsEntry, StorageBackend, VolumeInfo


def _config(tmp_path: Path, scopes: list[str]) -> AgentConfig:
    return AgentConfig.model_validate(
        {
            "host_id": "nas-1",
            "ingest_url": "https://proxy:8443/api/v1/agents/ingest",
            "client_cert_path": "/certs/client.crt",
            "client_key_path": "/certs/client.key",
            "server_ca_path": "/certs/fathom-ca.crt",
            "scan_scope": scopes,
            "throttle": {
                "walk_concurrency": 2,
                "hash_concurrency": 1,
                "pause_when": {"load1_above": 1000.0, "iowait_above_percent": 100},
                "resume_when": {"load1_below": 1.0},
            },
        }
    )


def _make_tree(root: Path) -> None:
    (root / "a").mkdir()
    (root / "a" / "f1.txt").write_text("hello")
    (root / "a" / "f2.txt").write_text("world!!")
    (root / "b").mkdir()
    (root / "b" / "f3.bin").write_bytes(b"\x00" * 64)


async def _drain_all(staging: StagingStore) -> int:
    """Stand-in for the mTLS push: count, mark every staged row pushed, return the count."""
    rows = list(staging.iter_unpushed(limit=100_000))
    n = staging.mark_pushed([(r["host_id"], r["volume_id"], r["dev"], r["inode"]) for r in rows])
    return n


async def _finalize_noop() -> int:
    """Stand-in for the mTLS finalize: pretend the server recomputed zero volumes."""
    return 0


@pytest.mark.asyncio
async def test_run_agent_scans_stages_and_drains(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)
    config = _config(tmp_path, [str(data)])

    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        batch_size=2,
        drain=_drain_all,
        finalize=_finalize_noop,
    )

    # root + a + a/f1 + a/f2 + b + b/f3 = 6 entries
    assert summary.entries_seen == 6
    assert summary.pushed == 6
    assert summary.failed_scopes == []
    assert summary.host_id == "nas-1"


@pytest.mark.asyncio
async def test_run_agent_isolates_a_failing_scope(tmp_path: Path) -> None:
    good = tmp_path / "good"
    good.mkdir()
    (good / "only.txt").write_text("x")
    missing = tmp_path / "does-not-exist"
    config = _config(tmp_path, [str(good), str(missing)])

    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
    )

    assert str(missing) in summary.failed_scopes
    # The good scope still scanned + pushed despite the bad one.
    assert summary.entries_seen == 2  # good/ + good/only.txt
    assert summary.pushed == 2


@pytest.mark.asyncio
async def test_run_agent_isolates_a_staging_sqlite_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A staging-DB failure (sqlite3.Error: lock / disk-full / I/O) on ONE scope must be isolated
    # like any other scope failure. sqlite3.Error subclasses Exception, not OSError/RuntimeError —
    # before the fix it propagated and aborted the whole run (every scope + drain + finalize).
    import sqlite3

    from fathom.agent import runner as runner_mod

    good = tmp_path / "good"
    good.mkdir()
    (good / "only.txt").write_text("x")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "f.txt").write_text("y")
    config = _config(tmp_path, [str(good), str(bad)])

    real_scan = runner_mod._scan_one_scope

    async def flaky(**kwargs: object) -> object:
        if kwargs["root"] == str(bad):
            raise sqlite3.OperationalError("database is locked")
        return await real_scan(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(runner_mod, "_scan_one_scope", flaky)

    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
    )

    assert str(bad) in summary.failed_scopes  # sqlite3.Error isolated, not fatal
    assert summary.entries_seen == 2  # good/ + good/only.txt still scanned + pushed
    assert summary.pushed == 2


@pytest.mark.asyncio
async def test_run_agent_resolves_backend_via_registry_for_local_scope(tmp_path: Path) -> None:
    # The runner must resolve the backend through the registry (not hardcode POSIX). A plain local
    # dir resolves to PosixBackend via the default registry — proving the wiring is reached.
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)
    config = _config(tmp_path, [str(data)])

    reg = BackendRegistry()
    reg.register(PosixBackend(walk_concurrency=2))
    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
        registry=reg,
    )
    assert summary.entries_seen == 6
    assert summary.failed_scopes == []


@pytest.mark.asyncio
async def test_run_agent_scans_remote_sftp_target(tmp_path: Path) -> None:
    # A configured SMB/SFTP target is scanned as an additional root keyed by its mount_key, via the
    # remote backend resolved from the registry — full-bit never runs (metadata-only walk).
    from tests.backends.conftest import FakeRemoteTransport, FakeStat

    target = RemoteBackendConfig(protocol="sftp", host="nas", remote_path="/share")
    transcript = {
        "/share": [
            FakeStat("a.txt", "/share/a.txt", False, False, 10, 1.0, 1000, 1000),
            FakeStat("d", "/share/d", True, False, 0, 2.0, 1000, 1000),
        ],
        "/share/d": [
            FakeStat("b.txt", "/share/d/b.txt", False, False, 20, 3.0, 1000, 1000),
        ],
    }
    transport = FakeRemoteTransport(tree=transcript)

    config = AgentConfig.model_validate(
        {
            "host_id": "nas-1",
            "ingest_url": "https://proxy:8443/api/v1/agents/ingest",
            "client_cert_path": "/certs/client.crt",
            "client_key_path": "/certs/client.key",
            "server_ca_path": "/certs/fathom-ca.crt",
            "scan_scope": ["/data"],
            "remote_targets": [target.model_dump()],
            "throttle": {
                "walk_concurrency": 2,
                "hash_concurrency": 1,
                "pause_when": {"load1_above": 1000.0, "iowait_above_percent": 100},
                "resume_when": {"load1_below": 1.0},
            },
        }
    )

    reg = BackendRegistry()
    reg.register(SftpBackend(target, transport=transport))
    reg.register(PosixBackend(walk_concurrency=2))

    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
        registry=reg,
    )

    remote_outcome = next(s for s in summary.scopes if s.root == target.mount_key)
    # 3 remote entries (a.txt, d, d/b.txt); the local /data scope is missing → its own failure.
    assert remote_outcome.entries_seen == 3
    assert remote_outcome.error is None
    assert transport.listdir_calls  # re-stat walk was used (no content read)


@pytest.mark.asyncio
async def test_scan_one_root_now_scans_only_that_root(tmp_path: Path) -> None:
    # Scan Now (P3): scan_one_root_now restricts the run to the single requested root even though
    # the config has two scan_scope roots — reusing the full scan->stage->push pipeline.
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)  # 6 entries
    other = tmp_path / "other"
    other.mkdir()
    (other / "x.txt").write_text("z")
    config = _config(tmp_path, [str(data), str(other)])

    summary = await scan_one_root_now(
        config,
        root=str(data),
        mode="metadata",
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
    )

    assert [s.root for s in summary.scopes] == [str(data)]  # only the requested root
    assert summary.entries_seen == 6
    assert summary.failed_scopes == []
    assert all(s.fullbit_hashed == 0 for s in summary.scopes)  # metadata mode → no full-bit


@pytest.mark.asyncio
async def test_scan_one_root_now_fullbit_mode_honours_fullbit_scope(tmp_path: Path) -> None:
    # mode='fullbit' content-hashes when the root is in fullbit_scope; mode='metadata' never does,
    # even for the same root (the mode gates the full-bit pass without widening the standing scope).
    data = tmp_path / "data"
    data.mkdir()
    (data / "dup1.bin").write_bytes(b"D" * 4096)
    (data / "dup2.bin").write_bytes(b"D" * 4096)  # identical → a same-size collision pair
    config = AgentConfig.model_validate(
        {
            "host_id": "nas-1",
            "ingest_url": "https://proxy:8443/api/v1/agents/ingest",
            "client_cert_path": "/certs/client.crt",
            "client_key_path": "/certs/client.key",
            "server_ca_path": "/certs/fathom-ca.crt",
            "scan_scope": [str(data)],
            "fullbit_scope": [str(data)],
            "throttle": {
                "walk_concurrency": 2,
                "hash_concurrency": 1,
                "pause_when": {"load1_above": 1000.0, "iowait_above_percent": 100},
                "resume_when": {"load1_below": 1.0},
            },
        }
    )

    fullbit = await scan_one_root_now(
        config,
        root=str(data),
        mode="fullbit",
        staging_path=str(tmp_path / "fb.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
    )
    fb_scope = next(s for s in fullbit.scopes if s.root == str(data))
    assert fb_scope.fullbit_hashed == 2  # the two identical files were content-hashed

    meta = await scan_one_root_now(
        config,
        root=str(data),
        mode="metadata",
        staging_path=str(tmp_path / "meta.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
    )
    meta_scope = next(s for s in meta.scopes if s.root == str(data))
    assert meta_scope.fullbit_hashed == 0  # metadata mode suppresses full-bit despite fullbit_scope


@pytest.mark.asyncio
async def test_run_agent_runs_fullbit_pass_in_scope(tmp_path: Path) -> None:
    # A scope inside fullbit_scope gets a full-bit pass after the metadata scan: identical files
    # are fully hashed and their hashes staged (fullbit-dedup runner wiring).
    data = tmp_path / "data"
    data.mkdir()
    (data / "dup1.bin").write_bytes(b"D" * 4096)
    (data / "dup2.bin").write_bytes(b"D" * 4096)  # identical to dup1
    (data / "uniq.bin").write_bytes(b"U" * 9000)  # unique size → never opened
    config = AgentConfig.model_validate(
        {
            "host_id": "nas-1",
            "ingest_url": "https://proxy:8443/api/v1/agents/ingest",
            "client_cert_path": "/certs/client.crt",
            "client_key_path": "/certs/client.key",
            "server_ca_path": "/certs/fathom-ca.crt",
            "scan_scope": [str(data)],
            "fullbit_scope": [str(data)],
            "throttle": {
                "walk_concurrency": 2,
                "hash_concurrency": 1,
                "pause_when": {"load1_above": 1000.0, "iowait_above_percent": 100},
                "resume_when": {"load1_below": 1.0},
            },
        }
    )
    staging_path = str(tmp_path / "staging.sqlite")
    summary = await run_agent(
        config,
        staging_path=staging_path,
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
    )
    outcome = next(s for s in summary.scopes if s.root == str(data))
    assert outcome.fullbit_error is None
    assert outcome.fullbit_hashed == 2  # the two identical files; the unique-size one is skipped

    # The staged hashes are present and identical for the two copies (drain marks them pushed).
    with StagingStore(staging_path) as staging:
        rows = staging._conn.execute(
            "SELECT full_hash FROM staged_entry WHERE full_hash IS NOT NULL"
        ).fetchall()
        assert len(rows) == 2
        assert len({r["full_hash"] for r in rows}) == 1


@pytest.mark.asyncio
async def test_run_agent_skips_fullbit_outside_scope(tmp_path: Path) -> None:
    # With no fullbit_scope, the full-bit pass never runs even though the metadata scan does.
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.bin").write_bytes(b"A" * 4096)
    (data / "b.bin").write_bytes(b"A" * 4096)
    config = _config(tmp_path, [str(data)])  # no fullbit_scope
    staging_path = str(tmp_path / "staging.sqlite")
    summary = await run_agent(
        config,
        staging_path=staging_path,
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
    )
    outcome = next(s for s in summary.scopes if s.root == str(data))
    assert outcome.fullbit_hashed == 0
    assert outcome.fullbit_error is None
    with StagingStore(staging_path) as staging:
        assert list(staging.iter_unpushed_hashes()) == []


@pytest.mark.asyncio
async def test_run_agent_fullbit_blocked_during_resync(tmp_path: Path) -> None:
    # When the supervisor blocks full-bit (array resyncing via the adapter), the metadata scan
    # still succeeds but the full-bit pass is refused and recorded — never crashing the run.
    data = tmp_path / "data"
    data.mkdir()
    (data / "x.bin").write_bytes(b"X" * 4096)
    (data / "y.bin").write_bytes(b"X" * 4096)
    config = AgentConfig.model_validate(
        {
            "host_id": "nas-1",
            "ingest_url": "https://proxy:8443/api/v1/agents/ingest",
            "client_cert_path": "/certs/client.crt",
            "client_key_path": "/certs/client.key",
            "server_ca_path": "/certs/fathom-ca.crt",
            "scan_scope": [str(data)],
            "fullbit_scope": [str(data)],
            "throttle": {
                "walk_concurrency": 2,
                "hash_concurrency": 1,
                "pause_when": {"load1_above": 1000.0, "iowait_above_percent": 100},
                "resume_when": {"load1_below": 1.0},
            },
        }
    )

    class _ResyncingAdapter:
        # Only is_array_healthy + close are exercised by the resync provider / teardown.
        async def is_array_healthy(self, pool: str) -> bool:
            return False  # unhealthy → resyncing → full-bit blocked

        async def close(self) -> None:
            return None

    reg = BackendRegistry()
    reg.register(PosixBackend(walk_concurrency=2))
    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_finalize_noop,
        registry=reg,
        adapter=_ResyncingAdapter(),  # type: ignore[arg-type]
        adapter_pool="tank",
    )
    outcome = next(s for s in summary.scopes if s.root == str(data))
    assert outcome.entries_seen > 0  # metadata scan still ran
    assert outcome.fullbit_hashed == 0
    assert outcome.fullbit_error is not None
    assert "block" in outcome.fullbit_error.lower()


@pytest.mark.asyncio
async def test_run_agent_reports_pushed_zero_when_nothing_changes(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "f.txt").write_text("v1")
    config = _config(tmp_path, [str(data)])
    staging = str(tmp_path / "staging.sqlite")

    first = await run_agent(
        config, staging_path=staging, operator="t", drain=_drain_all, finalize=_finalize_noop
    )
    assert first.pushed == 2
    # Second run with no FS changes: the change-guarded staging upsert is a no-op → nothing to push.
    second = await run_agent(
        config, staging_path=staging, operator="t", drain=_drain_all, finalize=_finalize_noop
    )
    assert second.pushed == 0


@pytest.mark.asyncio
async def test_run_agent_calls_finalize_after_drain(tmp_path: Path) -> None:
    # The runner must call finalize exactly once, AFTER the drain completes, and surface the
    # server's recomputed-volume count on the summary (rollups are wired to the scan loop).
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)
    config = _config(tmp_path, [str(data)])

    calls: list[str] = []

    async def _recording_drain(staging: StagingStore) -> int:
        calls.append("drain")
        return await _drain_all(staging)

    async def _recording_finalize() -> int:
        calls.append("finalize")
        return 1  # the server recomputed one volume

    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_recording_drain,
        finalize=_recording_finalize,
    )

    assert calls == ["drain", "finalize"]  # finalize runs once, after the drain
    assert summary.finalized == 1


@pytest.mark.asyncio
async def test_run_agent_finalize_failure_never_aborts_the_run(tmp_path: Path) -> None:
    # Finalize is best-effort: the deltas are already ingested, so a finalize failure must leave
    # the run successful (pushed intact) with summary.finalized == None.
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)
    config = _config(tmp_path, [str(data)])

    async def _boom_finalize() -> int:
        raise RuntimeError("server unreachable for finalize")

    summary = await run_agent(
        config,
        staging_path=str(tmp_path / "staging.sqlite"),
        operator="tester",
        drain=_drain_all,
        finalize=_boom_finalize,
    )

    assert summary.pushed == 6  # the run still succeeded
    assert summary.finalized is None  # finalize failed, swallowed


# --- incremental change-feed wiring (ADR-006) ---------------------------------------------


async def _drain_entries_and_removals(staging: StagingStore) -> int:
    """Drain helper that also clears staged removals, so a delete-only cycle is fully drained."""
    pushed = 0
    for run in staging.pending_runs():
        rows = staging.unpushed_for_run(run["id"], limit=100_000)
        pushed += staging.mark_pushed(
            [(r["host_id"], r["volume_id"], r["dev"], r["inode"]) for r in rows]
        )
        removals = staging.unpushed_removals_for_run(run["id"], limit=100_000)
        staging.mark_removals_pushed(
            [(r["host_id"], r["volume_id"], r["dev"], r["inode"]) for r in removals]
        )
    return pushed


def _staged_paths(staging_path: str) -> set[str]:
    """Return the paths staged by the most recent scan run (for asserting an incremental delta)."""
    with StagingStore(staging_path) as store:
        last = store._conn.execute("SELECT MAX(id) AS m FROM scan_run").fetchone()["m"]
        rows = store._conn.execute(
            "SELECT path FROM staged_entry WHERE scan_run_id = ?", (last,)
        ).fetchall()
    return {r["path"] for r in rows}


def _fs_entry(path: str, inode: int, *, mtime: float = 9.0) -> FsEntry:
    return FsEntry(
        path=path,
        name=path.rsplit("/", 1)[-1],
        is_dir=False,
        is_symlink=False,
        size_logical=3,
        size_on_disk=3,
        mtime=mtime,
        ctime=mtime,
        uid=0,
        gid=0,
        inode=inode,
    )


class _ScriptedFeed:
    """A fake :class:`ChangeFeed` yielding a fixed list of events (one created + one deleted)."""

    def __init__(self, events: list[ChangeEvent]) -> None:
        self._events = events

    async def changes(self, root: str) -> AsyncIterator[ChangeEvent]:
        for ev in self._events:
            yield ev


@pytest.mark.asyncio
async def test_second_run_uses_feed_and_pushes_only_changes(tmp_path: Path) -> None:
    # First run baselines via a full walk; the second run uses the injected change feed and stages
    # only the delta (one create + one delete), never re-walking the whole tree (ADR-006).
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)
    config = _config(tmp_path, [str(data)])
    staging = str(tmp_path / "staging.sqlite")

    first = await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
    )
    assert first.pushed == 6  # full walk baselines the whole tree

    events = [
        ChangeEvent(
            "create",
            path=f"{data}/a/new.txt",
            inode=99_001,
            entry=_fs_entry(f"{data}/a/new.txt", 99_001),
        ),
        ChangeEvent("delete", path=f"{data}/b/f3.bin", inode=99_002),
    ]
    captured: list[ChangeFeed] = []

    def _factory(
        backend: StorageBackend,
        volume: VolumeInfo,
        root: str,
        store: StagingStore,
        cfg: AgentConfig,
    ) -> ChangeFeed | None:
        feed = _ScriptedFeed(events)
        captured.append(feed)
        return feed

    second = await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
        feed_factory=_factory,
    )

    assert captured  # the feed was actually consulted on the second run
    assert second.pushed == 1  # only the created entry is an upsert (the delete rides as a removal)
    outcome = next(s for s in second.scopes if s.root == str(data))
    assert outcome.error is None
    assert outcome.entries_seen == 1  # delta only — NOT the 6-entry full tree


async def test_force_full_walk_skips_the_feed_and_rewalks(tmp_path: Path) -> None:
    # The freshness lever: with force_full_walk a host that WOULD go incremental instead re-walks
    # fully (so full-bit re-runs), the feed is never consulted, and the whole tree is re-seen.
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)
    config = _config(tmp_path, [str(data)])
    staging = str(tmp_path / "staging.sqlite")

    first = await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
    )
    assert first.pushed == 6  # baseline full walk

    captured: list[ChangeFeed] = []

    def _factory(
        backend: StorageBackend,
        volume: VolumeInfo,
        root: str,
        store: StagingStore,
        cfg: AgentConfig,
    ) -> ChangeFeed | None:
        feed = _ScriptedFeed([])
        captured.append(feed)
        return feed

    second = await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
        feed_factory=_factory,
        force_full_walk=True,
    )
    assert not captured  # the feed was NOT consulted — force_full_walk skipped it
    outcome = next(s for s in second.scopes if s.root == str(data))
    assert outcome.error is None
    assert outcome.entries_seen == 6  # full re-walk of the whole tree, not an incremental delta


@pytest.mark.asyncio
async def test_second_run_falls_back_to_full_walk_when_feed_unavailable(tmp_path: Path) -> None:
    # When no feed can run (factory returns None), the second run conservatively full-walks rather
    # than miss changes — so it re-sees every entry in the tree (ADR-006 fallback).
    data = tmp_path / "data"
    data.mkdir()
    _make_tree(data)
    config = _config(tmp_path, [str(data)])
    staging = str(tmp_path / "staging.sqlite")

    await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
    )

    def _no_feed(
        backend: StorageBackend,
        volume: VolumeInfo,
        root: str,
        store: StagingStore,
        cfg: AgentConfig,
    ) -> ChangeFeed | None:
        return None  # feed unavailable (e.g. ZFS without snapshots) → full-walk fallback

    second = await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
        feed_factory=_no_feed,
    )
    outcome = next(s for s in second.scopes if s.root == str(data))
    assert outcome.error is None
    assert outcome.entries_seen == 6  # full walk re-saw the whole tree, not a delta


@pytest.mark.asyncio
async def test_default_restat_feed_detects_real_change_on_second_run(tmp_path: Path) -> None:
    # End-to-end with the DEFAULT feed factory (no injection): a POSIX scope baselines on the first
    # run, then the second run drives the real RestatFeed off the persisted baseline and stages only
    # the genuinely-changed file — proving the default _default_feed_for/load_baseline wiring works.
    data = tmp_path / "data"
    data.mkdir()
    (data / "keep.txt").write_text("same")
    changing = data / "edit.txt"
    changing.write_text("v1")
    config = _config(tmp_path, [str(data)])
    staging = str(tmp_path / "staging.sqlite")

    first = await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
    )
    assert first.entries_seen == 3  # data/ + keep.txt + edit.txt

    # Bump mtime on exactly one file; RestatFeed should emit a single MODIFY and nothing else.
    changing.write_text("v2-longer")
    os.utime(changing, (1_000_000.0, 1_000_000.0))

    second = await run_agent(
        config,
        staging_path=staging,
        operator="t",
        drain=_drain_entries_and_removals,
        finalize=_finalize_noop,
    )
    outcome = next(s for s in second.scopes if s.root == str(data))
    assert outcome.error is None
    # entries_seen is the FEED DELTA (not the full 3-entry tree): the edited file, possibly plus its
    # parent dir whose mtime the write bumped — but never the untouched keep.txt. This is the proof
    # the second run took the incremental path, not a full re-walk.
    assert 0 < outcome.entries_seen < first.entries_seen
    staged_paths = _staged_paths(staging)
    assert str(changing) in staged_paths
    assert str(data / "keep.txt") not in staged_paths  # untouched file never re-staged
