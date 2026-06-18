"""Staging + push of incremental removals (incremental test_plan).

Covers the agent staging/transport half of the incremental change feed:
- ``stage_removals`` records explicit deletions keyed on (host, volume, inode), idempotently;
- a delete-only cycle (no entries, only removals) still drains via ``pending_runs``;
- ``PushClient.drain`` pushes the removals as a metadata batch carrying ``removed_inodes`` and
  no entries, and marks them pushed only after acknowledgement (resumable, idempotent);
- ``IncrementalScanner`` drives a feed into staging (upserts + removals), throttle-aware.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Collection
from datetime import UTC, datetime
from pathlib import Path

import httpx

from fathom.agent.config import ThrottleProfile
from fathom.agent.reader.feed import ChangeEvent
from fathom.agent.reader.incremental import IncrementalScanner
from fathom.agent.reader.supervisor import LoadSupervisor
from fathom.agent.reader.walker import WarningAck
from fathom.agent.staging import StagingStore
from fathom.agent.transport import PushClient
from fathom.backends.base import FsEntry, VolumeInfo

HOST = "nas-1"
VOL = "/mnt/pool"
_VOLUME = {
    "mountpoint": VOL,
    "fs_type": "zfs",
    "device": "tank",
    "transport": "sata",
    "raid_role": None,
    "dataset": None,
    "total": 100,
    "used": 10,
    "free": 90,
}


def _entry(path: str, inode: int) -> FsEntry:
    return FsEntry(
        path=path,
        name=path.rsplit("/", 1)[-1],
        is_dir=False,
        is_symlink=False,
        size_logical=10,
        size_on_disk=10,
        mtime=1.0,
        ctime=1.0,
        uid=0,
        gid=0,
        inode=inode,
        flags={},
    )


def _handler(received: list[dict]):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        received.append(body)
        return httpx.Response(
            200,
            json={
                "snapshot_id": 1,
                "host_id": 1,
                "volume_id": 1,
                "entries_received": len(body["entries"]),
                "entries_rejected": 0,
                "entries_removed": len(body.get("removed_inodes", [])),
                "changes_logged": 0,
            },
        )

    return handler


async def _noop_sleep(_: float) -> None:
    return None


def test_stage_removals_is_idempotent(tmp_path: Path) -> None:
    with StagingStore(tmp_path / "s.sqlite") as store:
        run = store.start_run(
            host_id=HOST, volume_id=VOL, mode="metadata", root=VOL, started_at=1.0, volume=_VOLUME
        )
        first = store.stage_removals(
            run_id=run, host_id=HOST, volume_id=VOL, removals=[(3, f"{VOL}/a"), (4, f"{VOL}/b")]
        )
        assert first == 2
        # Re-staging the same inode re-attaches it (idempotent on the business key), not a 3rd row.
        store.stage_removals(run_id=run, host_id=HOST, volume_id=VOL, removals=[(3, f"{VOL}/a")])
        rows = store.unpushed_removals_for_run(run, limit=10)
        assert sorted(r["inode"] for r in rows) == [3, 4]


async def test_delete_only_cycle_drains(tmp_path: Path) -> None:
    with StagingStore(tmp_path / "s.sqlite") as store:
        run = store.start_run(
            host_id=HOST, volume_id=VOL, mode="metadata", root=VOL, started_at=1.0, volume=_VOLUME
        )
        store.stage_removals(run_id=run, host_id=HOST, volume_id=VOL, removals=[(7, f"{VOL}/gone")])
        # No entries staged — only a removal. pending_runs must still surface this run.
        assert [r["id"] for r in store.pending_runs()] == [run]

        received: list[dict] = []
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(_handler(received)), base_url="https://core"
        )
        pusher = PushClient(client, sleeper=_noop_sleep)
        await pusher.drain(store)
        await client.aclose()

        assert len(received) == 1
        assert received[0]["entries"] == []
        assert received[0]["removed_inodes"] == [7]
        assert received[0]["mode"] == "metadata"
        # Marked pushed → a re-drain is a no-op (resumable/idempotent).
        assert store.unpushed_removals_for_run(run, limit=10) == []


async def test_drain_pushes_entries_then_removals(tmp_path: Path) -> None:
    with StagingStore(tmp_path / "s.sqlite") as store:
        run = store.start_run(
            host_id=HOST, volume_id=VOL, mode="metadata", root=VOL, started_at=1.0, volume=_VOLUME
        )
        store.stage_batch(
            run_id=run, host_id=HOST, volume_id=VOL, entries=[_entry(f"{VOL}/keep", 1)]
        )
        store.stage_removals(run_id=run, host_id=HOST, volume_id=VOL, removals=[(2, f"{VOL}/gone")])
        received: list[dict] = []
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(_handler(received)), base_url="https://core"
        )
        await PushClient(client, sleeper=_noop_sleep).drain(store)
        await client.aclose()

        # Two pushes: the entry upsert batch, then the removal batch.
        assert len(received) == 2
        assert received[0]["entries"] and received[0]["removed_inodes"] == []
        assert received[1]["entries"] == [] and received[1]["removed_inodes"] == [2]


class _FakeBackend:
    async def volume_info(self, mountpoint: str) -> VolumeInfo:
        return VolumeInfo(
            mountpoint=mountpoint,
            fs_type="zfs",
            total=0,
            used=0,
            free=0,
            device="tank",
            transport="sata",
        )

    async def walk(  # pragma: no cover - IncrementalScanner uses the feed, not walk
        self,
        root: str,
        *,
        follow_symlinks: bool = False,
        one_filesystem: bool = True,
        exclude: Collection[str] = (),
    ) -> AsyncIterator[FsEntry]:
        if False:
            yield _entry(root, 0)


class _Feed:
    def __init__(self, events: list[ChangeEvent]) -> None:
        self._events = events

    async def changes(self, root: str) -> AsyncIterator[ChangeEvent]:
        for ev in self._events:
            yield ev


def _supervisor() -> LoadSupervisor:
    throttle = ThrottleProfile.model_validate(
        {
            "pause_when": {"load1_above": 6.0, "iowait_above_percent": 25},
            "resume_when": {"load1_below": 3.0},
        }
    )
    return LoadSupervisor(throttle, load1_provider=lambda: 0.0, resync_provider=lambda: False)


async def test_incremental_scanner_stages_upserts_and_removals(tmp_path: Path) -> None:
    with StagingStore(tmp_path / "s.sqlite") as store:
        scanner = IncrementalScanner(
            backend=_FakeBackend(), staging=store, supervisor=_supervisor(), host_id=HOST
        )
        events = [
            ChangeEvent("create", path=f"{VOL}/a", inode=1, entry=_entry(f"{VOL}/a", 1)),
            ChangeEvent("delete", path=f"{VOL}/b", inode=2),
        ]
        ack = WarningAck(
            operator="mo", acknowledged_at=datetime.now(tz=UTC), target=VOL, mode="metadata"
        )
        result = await scanner.scan(VOL, _Feed(events), warning_ack=ack)
        assert result.upserts_staged == 1
        assert result.removals_staged == 1
        removals = store.unpushed_removals_for_run(result.run_id, limit=10)
        assert [r["inode"] for r in removals] == [2]
        assert removals[0]["path"] == f"{VOL}/b"  # baseline path carried on the removal
