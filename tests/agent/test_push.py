"""Tests for the agent push transport — drain/resume and backoff (ADR-002, AR-0024)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from fathom.agent.staging import StagingStore
from fathom.agent.transport import PushClient, RetryPolicy
from fathom.backends.base import FsEntry

_VOLUME = {
    "mountpoint": "/mnt/pool",
    "fs_type": "zfs",
    "device": "tank",
    "transport": "sata",
    "raid_role": None,
    "dataset": None,
    "total": 100,
    "used": 10,
    "free": 90,
}


def _entry(inode: int) -> FsEntry:
    return FsEntry(
        path=f"/mnt/pool/f{inode}",
        name=f"f{inode}",
        is_dir=False,
        is_symlink=False,
        size_logical=10,
        size_on_disk=10,
        mtime=1.0,
        ctime=1.0,
        uid=568,
        gid=568,
        inode=inode,
        flags={},
    )


def _staging_with_entries(tmp_path: Path, n: int) -> StagingStore:
    store = StagingStore(tmp_path / "staging.sqlite")
    run = store.start_run(
        host_id="nas-1",
        volume_id="/mnt/pool",
        mode="metadata",
        root="/mnt/pool",
        started_at=1.0,
        volume=_VOLUME,
    )
    store.stage_batch(
        run_id=run, host_id="nas-1", volume_id="/mnt/pool", entries=[_entry(i) for i in range(n)]
    )
    return store


def _ok_handler(received: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "snapshot_id": 1,
                "host_id": 1,
                "volume_id": 1,
                "entries_received": len(body["entries"]),
                "entries_rejected": 0,
            },
        )

    return handler


async def _noop_sleep(_: float) -> None:
    return None


async def test_drain_pushes_and_marks(tmp_path: Path) -> None:
    with _staging_with_entries(tmp_path, 5) as store:
        received: list[httpx.Request] = []
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(_ok_handler(received)), base_url="https://core"
        )
        pusher = PushClient(client, chunk_size=2, sleeper=_noop_sleep)
        total = await pusher.drain(store)
        await client.aclose()

        assert total == 5
        assert store.count_unpushed() == 0
        assert len(received) == 3  # 2 + 2 + 1


async def test_drain_is_resumable(tmp_path: Path) -> None:
    # Re-draining after everything is pushed is a no-op (idempotent).
    with _staging_with_entries(tmp_path, 3) as store:
        received: list[httpx.Request] = []
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(_ok_handler(received)), base_url="https://core"
        )
        pusher = PushClient(client, sleeper=_noop_sleep)
        assert await pusher.drain(store) == 3
        assert await pusher.drain(store) == 0
        await client.aclose()


async def test_push_retries_then_succeeds(tmp_path: Path) -> None:
    attempts = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx.ConnectError("boom", request=request)
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "snapshot_id": 1,
                "host_id": 1,
                "volume_id": 1,
                "entries_received": len(body["entries"]),
                "entries_rejected": 0,
            },
        )

    delays: list[float] = []

    async def record_sleep(d: float) -> None:
        delays.append(d)

    with _staging_with_entries(tmp_path, 2) as store:
        client = httpx.AsyncClient(transport=httpx.MockTransport(flaky), base_url="https://core")
        pusher = PushClient(
            client, retry=RetryPolicy(max_attempts=5, base_delay=0.1), sleeper=record_sleep
        )
        assert await pusher.drain(store) == 2
        await client.aclose()

    assert attempts["n"] == 3
    assert len(delays) == 2  # two backoffs before the third attempt won


async def test_push_gives_up_after_max_attempts(tmp_path: Path) -> None:
    def always_fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    from fathom.agent.transport.push import PushError

    with _staging_with_entries(tmp_path, 1) as store:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(always_fail), base_url="https://core"
        )
        pusher = PushClient(
            client, retry=RetryPolicy(max_attempts=3, base_delay=0.01), sleeper=_noop_sleep
        )
        with pytest.raises(PushError):
            await pusher.drain(store)
        await client.aclose()
        assert store.count_unpushed() == 1  # nothing marked pushed on failure


async def test_fullbit_hashes_carried_on_push(tmp_path: Path) -> None:
    # A full-bit run stages content hashes; the push must carry them on the EntryFrame so the
    # server can persist them (fullbit-dedup transport mapping).
    _FULL = "a" * 64
    _PARTIAL = "b" * 64
    with _staging_with_entries(tmp_path, 2) as store:
        store.stage_hash(
            host_id="nas-1",
            volume_id="/mnt/pool",
            inode=0,
            partial_hash=_PARTIAL,
            full_hash=_FULL,
            scan_run_id=1,
        )
        received: list[httpx.Request] = []
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(_ok_handler(received)), base_url="https://core"
        )
        await PushClient(client, sleeper=_noop_sleep).drain(store)
        await client.aclose()

        bodies = [json.loads(r.content) for r in received]
        entries = [e for b in bodies for e in b["entries"]]
        hashed = next(e for e in entries if e["inode"] == 0)
        assert hashed["full_hash"] == _FULL
        assert hashed["partial_hash"] == _PARTIAL
        # The un-hashed sibling carries None — a metadata row keeps NULL hashes.
        unhashed = next(e for e in entries if e["inode"] == 1)
        assert unhashed["full_hash"] is None


async def test_fullbit_hash_push_resumable(tmp_path: Path) -> None:
    # Kill mid-drain of a full-bit run → no lost/duplicate hashes (resumable-push property).
    _FULL = "c" * 64
    with _staging_with_entries(tmp_path, 4) as store:
        for inode in range(4):
            store.stage_hash(
                host_id="nas-1",
                volume_id="/mnt/pool",
                inode=inode,
                partial_hash="d" * 64,
                full_hash=_FULL,
                scan_run_id=1,
            )

        # First drain fails after the first chunk is acknowledged (simulate a crash mid-run).
        sent: list[httpx.Request] = []

        def crash_after_one(request: httpx.Request) -> httpx.Response:
            if len(sent) >= 1:
                raise httpx.ConnectError("crash", request=request)
            sent.append(request)
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "snapshot_id": 1,
                    "host_id": 1,
                    "volume_id": 1,
                    "entries_received": len(body["entries"]),
                    "entries_rejected": 0,
                },
            )

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(crash_after_one), base_url="https://core"
        )
        from fathom.agent.transport.push import PushError

        with pytest.raises(PushError):
            await PushClient(
                client, chunk_size=2, retry=RetryPolicy(max_attempts=1), sleeper=_noop_sleep
            ).drain(store)
        await client.aclose()
        # Two pushed (first chunk), two still pending — nothing lost or double-counted.
        assert store.count_unpushed() == 2

        # Resume: the rest drains cleanly with no duplicate of the already-pushed rows.
        received: list[httpx.Request] = []
        client2 = httpx.AsyncClient(
            transport=httpx.MockTransport(_ok_handler(received)), base_url="https://core"
        )
        pushed = await PushClient(client2, chunk_size=2, sleeper=_noop_sleep).drain(store)
        await client2.aclose()
        assert pushed == 2
        assert store.count_unpushed() == 0
