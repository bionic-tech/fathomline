"""Local dev seeder — populate a Fathom catalogue from REAL scans of this machine.

No fleet, no mTLS proxy: this walks local directories with the real ``PosixBackend`` and pushes
them through the real ingest → finalize HTTP path (the same code the UI reads), attributing each
scan to a configurable (host, volume) so every UI page has real, non-mocked data:

* multiple hosts → the Agents/fleet page,
* multiple volumes with real subtree sizes → Dashboard + Explorer (tree/treemap/top-n),
* a full-bit pass that BLAKE3-hashes a small scope → real duplicate groups on the Duplicates page,
* the snapshot rows ingest opens → the Scans page.

The fingerprint is just a header here (no proxy secret configured locally, so the API trusts it
directly — deps.require_client_fingerprint). Re-running is idempotent (change-guarded upserts).

Usage:  uv run python scripts/localdev/seed.py [--api URL] [--max-entries N]
Config: edit HOSTS below, or drop in a USB drive's mountpoint as a new volume/host.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from dataclasses import dataclass, field

import blake3
import httpx

from fathom.backends.posix import PosixBackend

BATCH = 2000
FULLBIT_MAX = int(os.environ.get("SEED_FULLBIT_MAX", "8000"))  # cap content-hashed files (speed)


@dataclass(slots=True)
class VolumeSpec:
    path: str  # a real local directory to scan; becomes the volume mountpoint
    transport: str = "nvme"


@dataclass(slots=True)
class HostSpec:
    name: str
    fingerprint: str
    os: str
    agent_version: str = "0.1.0-local"
    volumes: list[VolumeSpec] = field(default_factory=list)
    fullbit: list[str] = field(default_factory=list)  # sub-paths to content-hash for dedup


# Default simulation: two "hosts" carved from this workstation's real filesystem. Each volume is a
# real directory; the data is genuine (sizes, counts, duplicates), only the host labels are a sim.
# Add a USB NVMe drive by appending VolumeSpec("/media/you/usb-nvme") to any host.
HOSTS: list[HostSpec] = [
    HostSpec(
        name="workstation-amd",
        fingerprint="local-workstation-amd-0001",
        os="Ubuntu 22.04",
        volumes=[VolumeSpec("/usr"), VolumeSpec("/opt")],
        fullbit=["/usr/share/icons", "/usr/share/doc"],
    ),
    HostSpec(
        name="build-runner",
        fingerprint="local-build-runner-0002",
        os="Ubuntu 22.04",
        volumes=[VolumeSpec("/var/lib")],
        fullbit=[],
    ),
]

# Attached test media: any directory mounted under this root (e.g. a USB NVMe/xfs/BSD disk mounted
# READ-ONLY at /mnt/fathom-test/<name>) is auto-scanned as its own volume on a "usb-archive" host —
# so plugging a drive in is zero-config: mount it ro, re-run the seed, and it appears on the Agents
# page + dashboard. Override the root with FATHOM_TEST_MOUNTS.
TEST_MOUNT_ROOT = os.environ.get("FATHOM_TEST_MOUNTS", "/mnt/fathom-test")


def _discover_test_mounts() -> HostSpec | None:
    """Build a 'usb-archive' host from whatever is mounted under TEST_MOUNT_ROOT (or None)."""
    if not os.path.isdir(TEST_MOUNT_ROOT):
        return None
    vols = [
        VolumeSpec(os.path.join(TEST_MOUNT_ROOT, name), transport="usb")
        for name in sorted(os.listdir(TEST_MOUNT_ROOT))
        if os.path.isdir(os.path.join(TEST_MOUNT_ROOT, name))
        and os.path.ismount(os.path.join(TEST_MOUNT_ROOT, name))
    ]
    if not vols:
        return None
    # Full-bit the first attached volume for a cross-device duplicate demo.
    return HostSpec(
        name="usb-archive",
        fingerprint="local-usb-archive-0003",
        os="removable",
        volumes=vols,
        fullbit=[vols[0].path],
    )


def _hdr(fp: str) -> dict[str, str]:
    return {"X-Client-Cert-Fingerprint": fp}


def _entry_frame(e: object) -> dict[str, object]:
    """Map a backends.FsEntry to an EntryFrame dict (1:1; metadata batch leaves hashes None)."""
    d = e.model_dump()  # type: ignore[attr-defined]
    return {
        "path": d["path"],
        "name": d["name"][:1024],
        "is_dir": d["is_dir"],
        "is_symlink": d["is_symlink"],
        "size_logical": d["size_logical"],
        "size_on_disk": d["size_on_disk"],
        "mtime": d["mtime"],
        "ctime": d["ctime"],
        "uid": d["uid"],
        "gid": d["gid"],
        "inode": d["inode"],
        "dev": d["dev"],
        "flags": d["flags"],
    }


async def _post_batch(
    client: httpx.AsyncClient,
    host: HostSpec,
    vol: dict[str, object],
    mode: str,
    entries: list[dict],
    snapshot_id: int | None,
) -> dict:
    """POST one batch. ``snapshot_id`` threads the open scan so all batches of one volume scan
    land on a SINGLE snapshot row (the agent does the same — None opens a new one)."""
    body: dict[str, object] = {
        "host": {"name": host.name, "os": host.os, "agent_version": host.agent_version},
        "volume": vol,
        "mode": mode,
        "entries": entries,
    }
    if snapshot_id is not None:
        body["snapshot_id"] = snapshot_id
    r = await client.post("/api/v1/agents/ingest", json=body, headers=_hdr(host.fingerprint))
    r.raise_for_status()
    return r.json()


async def _scan_volume(
    client: httpx.AsyncClient, backend: PosixBackend, host: HostSpec, spec: VolumeSpec, cap: int
) -> int:
    info = await backend.volume_info(spec.path)
    vframe = {
        "mountpoint": info.mountpoint,
        "fs_type": info.fs_type,
        "device": info.device,
        "transport": spec.transport,
        "total": info.total,
        "used": info.used,
        "free": info.free,
    }
    sent = 0
    snapshot_id: int | None = None
    buf: list[dict] = []
    async for entry in backend.walk(info.mountpoint, one_filesystem=True):
        buf.append(_entry_frame(entry))
        if len(buf) >= BATCH:
            res = await _post_batch(client, host, vframe, "metadata", buf, snapshot_id)
            snapshot_id = res["snapshot_id"]
            sent += len(buf)
            buf = []
            if cap and sent >= cap:
                break
    if buf and (not cap or sent < cap):
        await _post_batch(client, host, vframe, "metadata", buf, snapshot_id)
        sent += len(buf)
    print(f"    [{host.name}] {info.mountpoint} ({info.fs_type}): {sent} entries")
    return sent


def _blake3_file(path: str) -> str | None:
    try:
        h = blake3.blake3()
        with open(path, "rb") as fh:
            while True:
                block = fh.read(1 << 20)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


async def _fullbit_scope(
    client: httpx.AsyncClient, backend: PosixBackend, host: HostSpec, vframe: dict, root: str
) -> int:
    """Content-hash regular files under ``root`` and push a fullbit batch (populates dedup)."""
    sent = 0
    snapshot_id: int | None = None
    buf: list[dict] = []
    async for entry in backend.walk(root, one_filesystem=True):
        if entry.is_dir or entry.is_symlink or entry.size_logical == 0:
            continue
        digest = await asyncio.to_thread(_blake3_file, entry.path)
        if digest is None:
            continue
        frame = _entry_frame(entry)
        frame["full_hash"] = digest
        buf.append(frame)
        if len(buf) >= BATCH:
            res = await _post_batch(client, host, vframe, "fullbit", buf, snapshot_id)
            snapshot_id = res["snapshot_id"]
            sent += len(buf)
            buf = []
            if sent >= FULLBIT_MAX:
                break
    if buf and sent < FULLBIT_MAX:
        await _post_batch(client, host, vframe, "fullbit", buf, snapshot_id)
        sent += len(buf)
    print(f"    [{host.name}] full-bit {root}: {sent} files hashed")
    return sent


async def _seed_history(weeks: int) -> None:
    """Insert backdated weekly size_history points per volume so the Dashboard growth chart shows
    a real trend. A DEV FIXTURE: finalize only writes one point per run, so without this the chart
    is a single dot. Each point scales the volume's current totals down ~1.5%/week into the past
    (a plausible upward curve ending at today's real value). Connects directly (busy_timeout 30s)
    so it co-exists with the running API on SQLite.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from fathom.core.catalogue.models import SizeHistory, SubtreeRollup, Volume
    from fathom.core.settings import get_settings

    engine = create_async_engine(get_settings().database_url, connect_args={"timeout": 30})
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            volumes = (await s.execute(select(Volume))).scalars().all()
            now = datetime.now(tz=UTC)
            added = 0
            for v in volumes:
                root = (
                    await s.execute(
                        select(SubtreeRollup).where(
                            SubtreeRollup.volume_id == v.id, SubtreeRollup.path == v.mountpoint
                        )
                    )
                ).scalar_one_or_none()
                if root is None:
                    continue
                for i in range(weeks, 0, -1):
                    frac = max(0.0, 1.0 - i * 0.015)
                    s.add(
                        SizeHistory(
                            volume_id=v.id,
                            path=v.mountpoint,
                            ts=now - timedelta(days=7 * i),
                            total_size_logical=int(root.total_size_logical * frac),
                            total_size_on_disk=int(root.total_size_on_disk * frac),
                            file_count=int(root.file_count * frac),
                        )
                    )
                    added += 1
            await s.commit()
            print(f"  seeded {added} backdated history points across {len(volumes)} volumes")
    finally:
        await engine.dispose()


async def _seed_changes(per_volume: int) -> None:
    """Insert plausible change_log rows so the Changes (churn) page renders with data. A DEV
    FIXTURE: real churn comes from incremental re-scans (removed_inodes / size deltas), which the
    one-shot seed does not perform. Each row reuses a REAL catalogued path + size for a volume and
    a created/modified/removed type spread over the past week, so the feed looks authentic.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from fathom.core.catalogue.models import ChangeLog, FsEntryRow, Volume
    from fathom.core.settings import get_settings

    engine = create_async_engine(get_settings().database_url, connect_args={"timeout": 30})
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            volumes = (await s.execute(select(Volume))).scalars().all()
            now = datetime.now(tz=UTC)
            added = 0
            for v in volumes:
                rows = (
                    await s.execute(
                        select(FsEntryRow.path, FsEntryRow.size_on_disk)
                        .where(
                            FsEntryRow.volume_id == v.id,
                            FsEntryRow.is_dir.is_(False),
                            FsEntryRow.size_on_disk > 0,
                        )
                        .limit(per_volume)
                    )
                ).all()
                for i, (path, size) in enumerate(rows):
                    # Cycle created (+full) / modified (+/- a slice) / removed (-full).
                    kind = ("created", "modified", "removed")[i % 3]
                    delta = size if kind == "created" else -size if kind == "removed" else size // 5
                    if kind == "modified" and i % 2:
                        delta = -delta
                    s.add(
                        ChangeLog(
                            volume_id=v.id,
                            path=path,
                            change_type=kind,
                            size_delta=delta,
                            ts=now - timedelta(hours=(i % 168)),  # spread over the past week
                        )
                    )
                    added += 1
            await s.commit()
            print(f"  seeded {added} change_log rows across {len(volumes)} volumes")
    finally:
        await engine.dispose()


async def _seed_audit(rows: int) -> None:
    """Append a few hash-chained audit records via the REAL chain so the Audit page renders with a
    valid, continuity-checkable log. A DEV FIXTURE (actor 'localdev-seed') — the chain is genuine
    (build_persistent_chain does the real BLAKE-linked append), only the events are illustrative;
    in production these rows are written by the remediation executor (ADR-011).
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from fathom.core.audit_store import build_persistent_chain
    from fathom.core.settings import get_settings

    engine = create_async_engine(get_settings().database_url, connect_args={"timeout": 30})
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            chain = await build_persistent_chain(s)
            for i in range(rows):
                action, result = ("quarantine", "quarantined") if i % 3 else ("dry_run", "ok")
                chain.append(
                    actor="localdev-seed",
                    action=action,
                    target=f"/usr/share/doc/dup-sample-{i:03d}.txt",
                    before_state={"inode": 100000 + i, "size": 4096 + i, "demo": True},
                    result=result,
                )
            await s.commit()
            print(f"  seeded {rows} demo audit records (actor=localdev-seed)")
    finally:
        await engine.dispose()


async def _report_run(
    client: httpx.AsyncClient, fingerprint: str, scopes: list[dict], agent_version: str | None
) -> None:
    """POST an end-of-run report so the Agents page shows last-run health locally.

    The real agent does this at the end of every scan (POST /api/v1/agents/runs); the
    ingest/finalize path alone does not write an AgentRun row, so without this the Agents page
    shows a null last-run outcome for a freshly-seeded host.
    """
    from datetime import UTC, datetime, timedelta

    if not scopes:
        return
    now = datetime.now(tz=UTC)
    body = {
        "started_at": (now - timedelta(seconds=5)).isoformat(),
        "finished_at": now.isoformat(),
        "pushed": sum(s["entries_seen"] for s in scopes),
        "finalized": len(scopes),
        "agent_version": agent_version,
        "scopes": scopes,
    }
    r = await client.post("/api/v1/agents/runs", json=body, headers=_hdr(fingerprint))
    r.raise_for_status()


async def _seed_cloud_dups(client: httpx.AsyncClient) -> None:
    """Seed two simulated cloud remotes so the Duplicates 'Cross-cloud' section shows real,
    zero-egress provider-hash duplicate groups end-to-end (ADR-028/029).

    No rclone binary or credentials needed: the md5 provider hashes are GENUINE (computed over
    synthetic file contents); only the 'cloud' is simulated. Two files are shared across both
    remotes (identical content → identical md5) so a cross-cloud duplicate group appears, plus a
    unique file per remote. Pushed through the REAL ingest path as remote volumes (synthetic
    POSIX mountpoint + pretty display_name + path-derived synthetic inode — ADR-029).
    """
    import hashlib

    from fathom.backends.remote import synthetic_inode

    fp = "local-cloud-archive-0009"
    host = {"name": "cloud-archive", "os": "rclone-remotes", "agent_version": "0.1.0-local"}

    def _file(mount: str, name: str, content: bytes) -> dict:
        path = f"{mount}/{name}"
        return {
            "path": path,
            "name": name,
            "is_dir": False,
            "is_symlink": False,
            "size_logical": len(content),
            "size_on_disk": len(content),
            "mtime": 1700000.0,
            "ctime": 1700000.0,
            "uid": -1,
            "gid": -1,
            "inode": synthetic_inode(path),
            "flags": {"synthetic_owner": True},
            # md5 is genuine (computed over real bytes); only the "cloud" is simulated.
            "provider_hash": hashlib.md5(content).hexdigest(),
            "provider_hash_algo": "md5",
        }

    def _dir(mount: str) -> dict:
        return {
            "path": mount,
            "name": mount.rsplit("/", 1)[-1],
            "is_dir": True,
            "is_symlink": False,
            "size_logical": 0,
            "size_on_disk": 0,
            "mtime": 1700000.0,
            "ctime": 1700000.0,
            "uid": -1,
            "gid": -1,
            "inode": synthetic_inode(mount),
            "flags": {"synthetic_owner": True},
        }

    # Shared across BOTH remotes → cross-cloud duplicate groups (same content = same md5).
    shared = [("vacation-2024.jpg", b"JPEGDATA" * 4096), ("taxes-2023.pdf", b"PDFDATA" * 9000)]
    remotes = [
        ("rclone://gdrive/Backups", "/rclone/gdrive/Backups", b"gdrive-unique-payload" * 500),
        ("rclone://dropbox/Sync", "/rclone/dropbox/Sync", b"dropbox-unique-payload" * 500),
    ]
    cloud_scopes: list[dict] = []
    for display, mount, unique in remotes:
        entries = [_dir(mount)]
        entries += [_file(mount, name, content) for name, content in shared]
        entries.append(_file(mount, "only-here.bin", unique))  # unique → not a duplicate
        cloud_scopes.append(
            {"root": mount, "entries_seen": len(entries), "rows_changed": len(entries)}
        )
        body = {
            "host": host,
            "volume": {
                "mountpoint": mount,
                "display_name": display,
                "fs_type": "rclone",
                "device": display,
                "transport": "network",
                "total": 0,
                "used": 0,
                "free": 0,
            },
            "mode": "metadata",
            "entries": entries,
        }
        r = await client.post("/api/v1/agents/ingest", json=body, headers=_hdr(fp))
        r.raise_for_status()
    (await client.post("/api/v1/agents/finalize", headers=_hdr(fp))).raise_for_status()
    await _report_run(client, fp, cloud_scopes, host["agent_version"])
    print("  seeded 2 simulated cloud remotes (gdrive + dropbox) with cross-cloud duplicates")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("FATHOM_LOCAL_API", "http://127.0.0.1:8099"))
    ap.add_argument(
        "--max-entries",
        type=int,
        default=int(os.environ.get("SEED_MAX_ENTRIES", "0")),
        help="cap entries per volume (0 = no cap)",
    )
    ap.add_argument(
        "--history-weeks",
        type=int,
        default=int(os.environ.get("SEED_HISTORY_WEEKS", "10")),
        help="backdated weekly history points per volume for the growth chart (0=off)",
    )
    ap.add_argument(
        "--audit-rows",
        type=int,
        default=int(os.environ.get("SEED_AUDIT_ROWS", "12")),
        help="demo hash-chained audit records so the Audit page renders (0=off)",
    )
    ap.add_argument(
        "--changes-per-volume",
        type=int,
        default=int(os.environ.get("SEED_CHANGES", "60")),
        help="demo change_log rows per volume so the Changes page renders (0=off)",
    )
    ap.add_argument(
        "--fixtures-only",
        action="store_true",
        help="skip scanning; only (re)seed the history + audit + changes demo fixtures",
    )
    ap.add_argument(
        "--no-cloud-dups",
        action="store_true",
        help="skip seeding the two simulated cloud remotes (cross-cloud provider-hash duplicates)",
    )
    args = ap.parse_args()
    backend = PosixBackend(walk_concurrency=4)

    async with httpx.AsyncClient(base_url=args.api, timeout=120.0) as client:
        r = await client.get("/healthz")
        r.raise_for_status()
        print(f"seeding {args.api} (cap={args.max_entries or 'none'})")
        hosts = list(HOSTS)
        usb = _discover_test_mounts()
        if usb is not None:
            print(f"  + discovered {len(usb.volumes)} attached test volume(s) in {TEST_MOUNT_ROOT}")
            hosts.append(usb)
        for host in hosts if not args.fixtures_only else []:
            print(f"  host {host.name}:")
            vframes: dict[str, dict] = {}
            scope_frames: list[dict] = []
            for spec in host.volumes:
                if not os.path.isdir(spec.path):
                    print(f"    skip {spec.path} (not a directory)")
                    continue
                sent = await _scan_volume(client, backend, host, spec, args.max_entries)
                info = await backend.volume_info(spec.path)
                scope_frames.append(
                    {"root": info.mountpoint, "entries_seen": sent, "rows_changed": sent}
                )
                vframes[info.mountpoint] = {
                    "mountpoint": info.mountpoint,
                    "fs_type": info.fs_type,
                    "device": info.device,
                    "transport": spec.transport,
                    "total": info.total,
                    "used": info.used,
                    "free": info.free,
                }
            for root in host.fullbit:
                vol_mount = next((m for m in vframes if root.startswith(m)), None)
                if vol_mount is None or not os.path.isdir(root):
                    continue
                await _fullbit_scope(client, backend, host, vframes[vol_mount], root)
            fr = await client.post("/api/v1/agents/finalize", headers=_hdr(host.fingerprint))
            fr.raise_for_status()
            f = fr.json()
            print(
                f"    finalize: volumes={f['volume_ids']} rollup_rows={f['rollup_rows']} "
                f"dup_groups={f['dup_groups']}"
            )
            await _report_run(client, host.fingerprint, scope_frames, host.agent_version)

        if not args.no_cloud_dups:
            # Inside the client block (needs the API): simulated cloud remotes so the Duplicates
            # 'Cross-cloud' section renders zero-egress provider-hash groups end-to-end.
            try:
                await _seed_cloud_dups(client)
            except Exception as exc:
                print(f"  cloud-dups fixture skipped: {exc}")

    if args.history_weeks > 0:
        try:
            await _seed_history(args.history_weeks)
        except Exception as exc:
            print(f"  history fixture skipped: {exc}")
    if args.audit_rows > 0:
        try:
            await _seed_audit(args.audit_rows)
        except Exception as exc:
            print(f"  audit fixture skipped: {exc}")
    if args.changes_per_volume > 0:
        try:
            await _seed_changes(args.changes_per_volume)
        except Exception as exc:
            print(f"  changes fixture skipped: {exc}")
    print("done.")


if __name__ == "__main__":
    asyncio.run(main())
