"""Deterministic synthetic corpus for the E2E feature harness (scripts/e2e/run_e2e.sh).

Unlike scripts/localdev/seed.py (which walks this machine's real filesystem — non-deterministic),
this pushes a SMALL, fully-synthetic catalogue through the REAL ingest -> finalize HTTP path so
every feature has a *known expected tally* the verifier can assert against. The entries are
fabricated (paths, sizes, BLAKE3-style hashes) but travel the exact production code path the UI
reads, so finalize computes real subtree rollups + real duplicate groups — including:

  * a genuine CROSS-HOST duplicate  (same content on nas-1 /data and tiger-1 /raid, both native)
    -> reclaimable = size * (2 - 1)
  * a CROSS-MOUNT ALIAS false-positive (the same physical file seen natively on tiger-1 /raid AND
    through nas-1's NFS mount /nfsmnt) -> the NFS member is flagged is_mount_alias, reclaimable = 0
    (ADR-032).

It also lays down an organize-ready folder (mixed file types), a reconcile-able mirror pair, and
demo change_log / size_history / audit fixtures so the Changes, Dashboard-growth and Audit pages
render. The expected tallies are printed as JSON (and written to --out) for the verifier.

Usage:  uv run python scripts/e2e/seed_e2e.py --api http://127.0.0.1:8099 --out /tmp/fathom-e2e/expected.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os

import httpx

# ---- corpus constants (sizes chosen so every ordering/tally is unambiguous) -------------------
H = {  # synthetic 64-hex content hashes; equal hash == identical content
    "A": "a" * 64,  # cross-host duplicate (1 MB, two native copies)
    "B": "b" * 64,  # cross-mount alias subject (5 MB, native + nfs view)
    "M": "c" * 64,  # clip.mp4 (largest single file)
    "X": "d" * 64,  # reconcile mirror file (identical both sides)
}
SZ = {
    "a_jpg": 1_000_000,
    "movie_bin": 5_000_000,
    "clip_mp4": 9_000_000,
    "unique_png": 300_000,
    "dl_jpg": 500_000,
    "dl_pdf": 220_000,
    "dl_mp3": 4_000_000,
    "dl_txt": 12_000,
    "dl_mkv": 7_000_000,
    "mirror_x": 100,
    "mirror_only": 50,
}

_inode = iter(range(100_001, 200_000))

# The seeded in-app notification's title — asserted verbatim by the verifier and the SPA bell story.
NOTIFICATION_TITLE = "Host nas-1 can run a larger local model"


def _e(path: str, size: int, *, is_dir: bool = False, full_hash: str | None = None) -> dict:
    name = path.rstrip("/").rsplit("/", 1)[-1] or path
    d: dict[str, object] = {
        "path": path,
        "name": name,
        "is_dir": is_dir,
        "is_symlink": False,
        "size_logical": 0 if is_dir else size,
        "size_on_disk": 0 if is_dir else size,
        "mtime": 1_700_000_000.0,
        "ctime": 1_700_000_000.0,
        "uid": 0,
        "gid": 0,
        "inode": next(_inode),
        "dev": 64,
        "flags": {},
    }
    if full_hash is not None:
        d["full_hash"] = full_hash
    return d


def _hdr(fp: str) -> dict[str, str]:
    return {"X-Client-Cert-Fingerprint": fp}


def _vol(mount: str, fs_type: str, transport: str, used: int) -> dict:
    return {
        "mountpoint": mount,
        "fs_type": fs_type,
        "device": f"/dev/{fs_type}-{mount.strip('/').replace('/', '-')}",
        "transport": transport,
        "total": max(used * 4, 10_000_000_000),
        "used": used,
        "free": max(used * 3, 5_000_000_000),
    }


async def _ingest(client, fp, host, vol, mode, entries, snap):
    body: dict[str, object] = {"host": host, "volume": vol, "mode": mode, "entries": entries}
    if snap is not None:
        body["snapshot_id"] = snap
    r = await client.post("/api/v1/agents/ingest", json=body, headers=_hdr(fp))
    r.raise_for_status()
    return r.json()["snapshot_id"]


async def _push_volume(client, fp, host, vol, entries):
    """Ingest a volume's entries as metadata then fullbit (so full_hash + dedup groups land)."""
    snap = await _ingest(client, fp, host, vol, "metadata", entries, None)
    hashed = [e for e in entries if e.get("full_hash")]
    if hashed:
        await _ingest(client, fp, host, vol, "fullbit", hashed, snap)


async def _finalize(client, fp) -> dict:
    r = await client.post("/api/v1/agents/finalize", headers=_hdr(fp))
    r.raise_for_status()
    return r.json()


async def _report_run(client, fp, scopes, version):
    from datetime import UTC, datetime, timedelta

    now = datetime.now(tz=UTC)
    body = {
        "started_at": (now - timedelta(seconds=4)).isoformat(),
        "finished_at": now.isoformat(),
        "pushed": sum(s["entries_seen"] for s in scopes),
        "finalized": len(scopes),
        "agent_version": version,
        "scopes": scopes,
    }
    r = await client.post("/api/v1/agents/runs", json=body, headers=_hdr(fp))
    r.raise_for_status()


async def _seed_changes_and_history(weeks: int, changes_per_volume: int) -> None:
    """DEV FIXTURES (same approach as localdev seed): backdated size_history for the growth chart
    and change_log rows for the Changes feed — derived from the freshly-catalogued entries."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from fathom.core.catalogue.models import ChangeLog, FsEntryRow, SizeHistory, SubtreeRollup, Volume
    from fathom.core.settings import get_settings

    engine = create_async_engine(get_settings().database_url, connect_args={"timeout": 30})
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            vols = (await s.execute(select(Volume))).scalars().all()
            now = datetime.now(tz=UTC)
            for v in vols:
                root = (
                    await s.execute(
                        select(SubtreeRollup).where(
                            SubtreeRollup.volume_id == v.id, SubtreeRollup.path == v.mountpoint
                        )
                    )
                ).scalar_one_or_none()
                if root is not None:
                    for i in range(weeks, 0, -1):
                        frac = max(0.0, 1.0 - i * 0.02)
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
                rows = (
                    await s.execute(
                        select(FsEntryRow.path, FsEntryRow.size_on_disk)
                        .where(
                            FsEntryRow.volume_id == v.id,
                            FsEntryRow.is_dir.is_(False),
                            FsEntryRow.size_on_disk > 0,
                        )
                        .limit(changes_per_volume)
                    )
                ).all()
                for i, (path, size) in enumerate(rows):
                    kind = ("created", "modified", "removed")[i % 3]
                    delta = size if kind == "created" else -size if kind == "removed" else size // 5
                    s.add(
                        ChangeLog(
                            volume_id=v.id,
                            path=path,
                            change_type=kind,
                            size_delta=delta,
                            ts=now - timedelta(hours=(i % 72)),
                        )
                    )
            await s.commit()
    finally:
        await engine.dispose()


async def _seed_audit(rows: int) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from fathom.core.audit_store import build_persistent_chain
    from fathom.core.settings import get_settings

    engine = create_async_engine(get_settings().database_url, connect_args={"timeout": 30})
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            chain = await build_persistent_chain(s)
            for i in range(rows):
                action, result = ("dry_run", "ok") if i % 2 else ("quarantine", "quarantined")
                chain.append(
                    actor="e2e-seed",
                    action=action,
                    target=f"/data/downloads/sample-{i:03d}.bin",
                    before_state={"inode": 150000 + i, "size": 4096 + i, "demo": True},
                    result=result,
                )
            await s.commit()
    finally:
        await engine.dispose()


async def _seed_host_facts() -> None:
    """DEV FIXTURE: stamp ADR-037 hardware facts so the suitability engine returns a CONCRETE
    assessment. nas-1 gets a capable box (32 GB RAM + a 16 GB GPU → the large-local-model option is
    GREEN and the recommendation is an 8B local model); tiger-1 is left fact-less on purpose so the
    'hardware not reported yet' branch is exercised too. No facts ride the synthetic ingest path, so
    this writes them directly (same approach as the change-log / audit fixtures above)."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from fathom.core.catalogue.models import Host
    from fathom.core.settings import get_settings

    engine = create_async_engine(get_settings().database_url, connect_args={"timeout": 30})
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            nas = (
                await s.execute(select(Host).where(Host.name == "nas-1"))
            ).scalar_one_or_none()
            if nas is not None:
                nas.facts = {
                    "cpu_cores": 8,
                    "cpu_model": "AMD Ryzen 7 5800X",
                    "ram_bytes": 32 * 1024**3,
                    "gpu_name": "NVIDIA RTX 4080",
                    "gpu_vram_bytes": 16 * 1024**3,
                    "arch": "x86_64",
                }
            await s.commit()
    finally:
        await engine.dispose()


async def _seed_notifications() -> None:
    """DEV FIXTURE: raise one in-app notification (ADR-031) so the bell read surface has a
    deterministic, assertable row. Estate-wide (no host scope) so the global admin sees it; unread,
    so the unread-count badge is non-zero."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from fathom.core import notifications
    from fathom.core.catalogue.notification_meta import CATEGORY_RECOMMENDATION, SEVERITY_INFO
    from fathom.core.settings import get_settings

    engine = create_async_engine(get_settings().database_url, connect_args={"timeout": 30})
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as s:
            await notifications.emit(
                s,
                category=CATEGORY_RECOMMENDATION,
                title=NOTIFICATION_TITLE,
                body="nas-1 reports 32 GB RAM and a 16 GB GPU — it can run an 8B local model.",
                source="suitability_watch",
                severity=SEVERITY_INFO,
            )
            await s.commit()
    finally:
        await engine.dispose()


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("FATHOM_LOCAL_API", "http://127.0.0.1:8099"))
    ap.add_argument("--out", default="/tmp/fathom-e2e/expected.json")
    args = ap.parse_args()

    nas = {"name": "nas-1", "os": "TrueNAS SCALE", "agent_version": "0.9.0-e2e"}
    tiger = {"name": "tiger-1", "os": "Debian 12", "agent_version": "0.9.0-e2e"}
    nas_fp, tiger_fp = "e2e-nas-1-fp", "e2e-tiger-1-fp"

    # nas-1 /data (zfs): photos, media, an organize-ready downloads/ folder, a reconcile mirror.
    data_entries = [
        _e("/data", 0, is_dir=True),
        _e("/data/photos", 0, is_dir=True),
        _e("/data/photos/a.jpg", SZ["a_jpg"], full_hash=H["A"]),          # cross-host dup copy #1
        _e("/data/photos/unique1.png", SZ["unique_png"], full_hash="e" * 64),
        _e("/data/media", 0, is_dir=True),
        _e("/data/media/clip.mp4", SZ["clip_mp4"], full_hash=H["M"]),     # largest single file
        _e("/data/downloads", 0, is_dir=True),
        _e("/data/downloads/IMG_001.jpg", SZ["dl_jpg"], full_hash="11" * 32),
        _e("/data/downloads/report.pdf", SZ["dl_pdf"], full_hash="22" * 32),
        _e("/data/downloads/song.mp3", SZ["dl_mp3"], full_hash="33" * 32),
        _e("/data/downloads/notes.txt", SZ["dl_txt"], full_hash="44" * 32),
        _e("/data/downloads/movie.mkv", SZ["dl_mkv"], full_hash="55" * 32),
        _e("/data/mirror", 0, is_dir=True),
        _e("/data/mirror/x.txt", SZ["mirror_x"], full_hash=H["X"]),       # reconcile: identical
        _e("/data/mirror/only_nas.txt", SZ["mirror_only"], full_hash="66" * 32),  # missing-on-cmp
    ]
    # nas-1 /nfsmnt (nfs): the network-mounted VIEW of tiger-1's /raid/big/movie.bin (ADR-032).
    nfs_entries = [
        _e("/nfsmnt", 0, is_dir=True),
        _e("/nfsmnt/big", 0, is_dir=True),
        _e("/nfsmnt/big/movie.bin", SZ["movie_bin"], full_hash=H["B"]),   # ALIAS (nfs)
    ]
    # tiger-1 /raid (ext4): native copy of the cross-host dup + the real movie.bin + mirror match.
    raid_entries = [
        _e("/raid", 0, is_dir=True),
        _e("/raid/backup", 0, is_dir=True),
        _e("/raid/backup/a.jpg", SZ["a_jpg"], full_hash=H["A"]),          # cross-host dup copy #2
        _e("/raid/big", 0, is_dir=True),
        _e("/raid/big/movie.bin", SZ["movie_bin"], full_hash=H["B"]),     # NATIVE (real file)
        _e("/raid/mirror", 0, is_dir=True),
        _e("/raid/mirror/x.txt", SZ["mirror_x"], full_hash=H["X"]),       # reconcile: identical
    ]

    async with httpx.AsyncClient(base_url=args.api, timeout=60.0) as client:
        (await client.get("/healthz")).raise_for_status()
        data_vol = _vol("/data", "zfs", "nvme", sum(e["size_on_disk"] for e in data_entries))
        nfs_vol = _vol("/nfsmnt", "nfs", "network", SZ["movie_bin"])
        raid_vol = _vol("/raid", "ext4", "sata", sum(e["size_on_disk"] for e in raid_entries))

        await _push_volume(client, nas_fp, nas, data_vol, data_entries)
        await _push_volume(client, nas_fp, nas, nfs_vol, nfs_entries)
        await _finalize(client, nas_fp)
        await _report_run(
            client,
            nas_fp,
            [
                {"root": "/data", "entries_seen": len(data_entries), "rows_changed": len(data_entries)},
                {"root": "/nfsmnt", "entries_seen": len(nfs_entries), "rows_changed": len(nfs_entries)},
            ],
            nas["agent_version"],
        )

        await _push_volume(client, tiger_fp, tiger, raid_vol, raid_entries)
        f = await _finalize(client, tiger_fp)  # finalize tiger LAST -> cross-host groups complete
        await _report_run(
            client,
            tiger_fp,
            [{"root": "/raid", "entries_seen": len(raid_entries), "rows_changed": len(raid_entries)}],
            tiger["agent_version"],
        )
        print(f"finalize(tiger): {f}")

    await _seed_changes_and_history(weeks=8, changes_per_volume=12)
    await _seed_audit(rows=10)
    await _seed_host_facts()
    await _seed_notifications()

    # ---- expected tallies the verifier asserts against ----
    downloads = [
        ("IMG_001.jpg", SZ["dl_jpg"], "images"),
        ("report.pdf", SZ["dl_pdf"], "documents"),
        ("song.mp3", SZ["dl_mp3"], "audio"),
        ("notes.txt", SZ["dl_txt"], "documents"),
        ("movie.mkv", SZ["dl_mkv"], "videos"),
    ]
    expected = {
        "hosts": {"nas-1": {"volume_count": 2}, "tiger-1": {"volume_count": 1}},
        "duplicates": {
            # 3 groups: H_A (a.jpg, 2 native), H_B (movie.bin, 1 native + 1 nfs alias),
            # H_X (mirror x.txt, 2 native). Reclaimable = H_A + H_X; the alias group reclaims 0.
            "group_count": 3,
            "total_reclaimable_bytes": SZ["a_jpg"] + SZ["mirror_x"],
            "cross_host_group": {"full_hash": H["A"], "reclaimable_bytes": SZ["a_jpg"], "members": 2},
            "alias_group": {
                "full_hash": H["B"],
                "reclaimable_bytes": 0,
                "members": 2,
                "alias_members": 1,
            },
        },
        "largest_under_downloads": [  # top-n(/data/downloads, kind=file, by=on_disk) DESC
            ["movie.mkv", SZ["dl_mkv"]],
            ["song.mp3", SZ["dl_mp3"]],
            ["IMG_001.jpg", SZ["dl_jpg"]],
            ["report.pdf", SZ["dl_pdf"]],
            ["notes.txt", SZ["dl_txt"]],
        ],
        "treemap_data_children": {  # subtree on-disk sizes
            "downloads": sum(s for _, s, _ in downloads),
            "media": SZ["clip_mp4"],
            "photos": SZ["a_jpg"] + SZ["unique_png"],
        },
        "search_movie_count": 3,  # movie.bin (raid) + movie.bin (nfsmnt) + movie.mkv (downloads)
        "organize": {
            "root": "/data/downloads",
            "volume_label": "/data",
            "expected_moves": {name: cat for name, _, cat in downloads},
            "plan_blast_count": 5,
            "plan_reclaimable_bytes": sum(s for _, s, _ in downloads),
        },
        "reconcile": {
            "definitive": "/data/mirror",
            "comparison": "/raid/mirror",
            "identical": 1,
            "missing_on_comparison": 1,
        },
        "suitability": {  # ADR-037 traffic-lights; nas-1 has facts (32 GB + 16 GB GPU), tiger-1 not
            "facts_host": "nas-1",
            "facts_recommended_provider": "ollama",
            "facts_recommended_model": "llama3.1:8b",
            "nofacts_host": "tiger-1",
            "egress_allowed": False,  # FATHOM_INFERENCE_ALLOW_EGRESS unset -> default False
        },
        "notification": {  # ADR-031 bell: the one seeded estate-wide, unread notification
            "title": NOTIFICATION_TITLE,
            "category": "recommendation",
        },
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(expected, fh, indent=2)
    print(json.dumps(expected, indent=2))
    print(f"\nexpected tallies -> {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
