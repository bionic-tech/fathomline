"""Ingest API tests — auth, idempotency, and server-side scope re-enforcement (AR-0012)."""

from __future__ import annotations

from pathlib import Path

import httpx
from asgi_lifespan import LifespanManager
from sqlalchemy import func, select

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.catalogue.models import FsEntryRow
from fathom.core.settings import Settings
from tests.api.conftest import FINGERPRINT_HEADER, _entry, batch, seed_principal


async def test_ingest_requires_client_cert(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post("/api/v1/agents/ingest", json=batch())
    assert resp.status_code == 401


async def test_ingest_requires_proxy_secret_when_configured(tmp_path: Path) -> None:
    # CRITICAL (review): when an ingest proxy secret is configured, a request that bypassed the
    # mTLS proxy (no/forged proxy secret) must be rejected even with a fingerprint header — so a
    # direct call cannot forge an agent identity (AR-0010, STRIDE Spoofing).
    secret = "proxy-shared-secret-xyz"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'c.db'}",
        auto_create_schema=True,
        ingest_proxy_secret=secret,
    )
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # fingerprint present but NO proxy secret → rejected (the forged-header bypass).
            r1 = await client.post(
                "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
            )
            assert r1.status_code == 401
            # wrong proxy secret → rejected (constant-time mismatch).
            r2 = await client.post(
                "/api/v1/agents/ingest",
                json=batch(),
                headers={**FINGERPRINT_HEADER, "X-Fathom-Proxy-Secret": "wrong"},
            )
            assert r2.status_code == 401
            # correct proxy secret (as the trusted proxy would set) → accepted.
            r3 = await client.post(
                "/api/v1/agents/ingest",
                json=batch(),
                headers={**FINGERPRINT_HEADER, "X-Fathom-Proxy-Secret": secret},
            )
            assert r3.status_code == 200
    await db.dispose_engine()


async def test_ingest_accepts_batch(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200
    body = resp.json()
    assert body["entries_received"] == 6
    assert body["entries_rejected"] == 0
    assert body["snapshot_id"] >= 1


async def test_ingest_accepts_windows_volume(api_client: httpx.AsyncClient) -> None:
    # A native Windows agent (ADR-027) sends a drive-letter mountpoint and backslash entry paths.
    # The server-side path re-validation (AR-0012) must accept them through the Windows ruleset
    # (the POSIX validator rejects them as "not absolute" on the Linux server — the original 422),
    # while STILL rejecting an entry outside the volume root, exactly as it does for POSIX.
    mount = "C:\\Users\\boywi\\Documents"

    def win_entry(path: str, name: str, inode: int, *, size: int = 0, is_dir: bool = False) -> dict:
        return {
            "path": path,
            "name": name,
            "is_dir": is_dir,
            "is_symlink": False,
            "size_logical": size,
            "size_on_disk": size,
            "mtime": 1000.0,
            "ctime": 1000.0,
            "uid": 4294967295,
            "gid": 4294967295,
            "inode": inode,
            "flags": {},
        }

    body = {
        "host": {"name": "win11-desktop", "os": "Windows-11", "agent_version": "0.1.0"},
        "volume": {
            "mountpoint": mount,
            "fs_type": "ntfs",
            "device": "volume-serial-deadbeef",
            "transport": "unknown",
            "total": 1000,
            "used": 400,
            "free": 600,
        },
        "mode": "metadata",
        "entries": [
            win_entry(mount, "Documents", 1, is_dir=True),
            win_entry(mount + "\\notes.txt", "notes.txt", 2, size=50),
            win_entry("C:\\Users\\boywi\\Secrets\\x.txt", "x.txt", 3, size=10),  # out of scope
        ],
    }
    resp = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["entries_received"] == 2  # the volume root + notes.txt
    assert out["entries_rejected"] == 1  # the out-of-scope C:\Users\boywi\Secrets entry


async def test_ingest_rejects_cross_flavour_entry_paths(api_client: httpx.AsyncClient) -> None:
    # Hardening (review): both the mountpoint and entry paths are agent-supplied. A Windows-mount
    # batch carrying a POSIX-shaped entry path (a deliberate mix) must be rejected fail-closed — the
    # POSIX path is a different PurePath flavour, so it is never "within" the Windows mount and the
    # server drops it (a mixed-flavour path can never slip past the containment check).
    mount = "C:\\Users\\boywi\\Documents"

    def win_entry(path: str, name: str, inode: int) -> dict:
        return {
            "path": path,
            "name": name,
            "is_dir": False,
            "is_symlink": False,
            "size_logical": 1,
            "size_on_disk": 1,
            "mtime": 1000.0,
            "ctime": 1000.0,
            "uid": 0,
            "gid": 0,
            "inode": inode,
            "flags": {},
        }

    body = {
        "host": {"name": "win-mix", "os": "Windows-11", "agent_version": "0.1.0"},
        "volume": {
            "mountpoint": mount,
            "fs_type": "ntfs",
            "device": "vol-1",
            "transport": "unknown",
            "total": 1000,
            "used": 0,
            "free": 1000,
        },
        "mode": "metadata",
        "entries": [
            win_entry(mount, "Documents", 1),  # valid Windows root
            win_entry("/etc/passwd", "passwd", 2),  # POSIX-shaped → cross-flavour → rejected
        ],
    }
    resp = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["entries_received"] == 1  # only the Windows root
    assert out["entries_rejected"] == 1  # the POSIX-shaped /etc/passwd cross-flavour entry


async def test_ingest_is_idempotent(api_client: httpx.AsyncClient) -> None:
    first = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    snap = first.json()["snapshot_id"]
    again = batch(snapshot_id=snap)
    second = await api_client.post("/api/v1/agents/ingest", json=again, headers=FINGERPRINT_HEADER)
    assert second.status_code == 200
    # Same host/volume → same identities, no duplicate rows surface in the tree.
    auth = await seed_principal()
    tree = await api_client.get(
        "/api/v1/tree",
        params={"volume_id": second.json()["volume_id"], "path": "/mnt/pool"},
        headers=auth,
    )
    paths = [c["path"] for c in tree.json()]
    assert len(paths) == len(set(paths))


async def test_ingest_same_inode_different_dev_are_distinct_rows(
    api_client: httpx.AsyncClient,
) -> None:
    # The cross-dataset bug end-to-end: a cross_mounts scan spans ZFS child datasets that each
    # reuse low inode numbers, so two DIFFERENT files share one inode. With dev in the catalogue
    # identity they ingest as two distinct rows — before the fix, the second clobbered the first
    # (the live data loss: 37 of 38 datasets' subtrees were lost).
    a = _entry("/mnt/pool", "dataset_a/file", 5, size=100)
    a["dev"] = 64769
    b = _entry("/mnt/pool", "dataset_b/file", 5, size=200)
    b["dev"] = 64770
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=[a, b]), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200
    assert resp.json()["entries_received"] == 2
    volume_id = resp.json()["volume_id"]
    async with db.session_scope() as session:
        count = (
            await session.execute(
                select(func.count())
                .select_from(FsEntryRow)
                .where(FsEntryRow.volume_id == volume_id, FsEntryRow.inode == 5)
            )
        ).scalar_one()
        devs = (
            (
                await session.execute(
                    select(FsEntryRow.dev)
                    .where(FsEntryRow.volume_id == volume_id, FsEntryRow.inode == 5)
                    .order_by(FsEntryRow.dev)
                )
            )
            .scalars()
            .all()
        )
    assert count == 2  # both inode-5 files survived; neither clobbered the other
    assert list(devs) == [64769, 64770]


async def test_ingest_persists_provider_hash_on_metadata_batch(
    api_client: httpx.AsyncClient,
) -> None:
    # ADR-028 phase 2: provider-attested hashes ride a METADATA batch (the agent never read the
    # bytes — rclone relayed the provider's hash). Unlike full_hash they are not gated on fullbit.
    entries = [
        _entry("/mnt/pool", "", 1, is_dir=True),
        {
            **_entry("/mnt/pool", "cloud.bin", 2, size=100),
            "provider_hash": "a" * 32,
            "provider_hash_algo": "md5",
        },
    ]
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=entries), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200
    volume_id = resp.json()["volume_id"]
    async with db.session_scope() as session:
        row = (
            await session.execute(
                select(FsEntryRow).where(FsEntryRow.volume_id == volume_id, FsEntryRow.inode == 2)
            )
        ).scalar_one()
    assert row.provider_hash == "a" * 32 and row.provider_hash_algo == "md5"
    # full_hash stays NULL — provider_hash is a distinct trust class, never conflated.
    assert row.full_hash is None


async def test_ingest_rejects_provider_hash_without_algo(api_client: httpx.AsyncClient) -> None:
    # Both-or-neither: a hash without its algorithm can't be safely grouped → 422 at the boundary.
    entries = [
        _entry("/mnt/pool", "", 1, is_dir=True),
        {**_entry("/mnt/pool", "x.bin", 2, size=10), "provider_hash": "a" * 32},
    ]
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=entries), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 422


async def test_ingest_rejects_out_of_scope_paths(api_client: httpx.AsyncClient) -> None:
    bad = batch(
        entries=[
            {
                "path": "/etc/passwd",  # outside the volume mountpoint
                "name": "passwd",
                "is_dir": False,
                "is_symlink": False,
                "size_logical": 1,
                "size_on_disk": 1,
                "mtime": 1.0,
                "ctime": 1.0,
                "uid": 0,
                "gid": 0,
                "inode": 99,
                "flags": {},
            }
        ]
    )
    resp = await api_client.post("/api/v1/agents/ingest", json=bad, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200
    assert resp.json()["entries_rejected"] == 1
    assert resp.json()["entries_received"] == 0


async def test_ingest_rejects_noncanonical_mountpoint(api_client: httpx.AsyncClient) -> None:
    # ADR-029/AR-0012: a `..` (or otherwise non-canonical) volume mountpoint normalises into a real
    # local namespace (/sftp/nas-1/../../etc → /etc) and would alias another volume's entries —
    # because the per-entry containment check uses the *normalised* mount. The server re-vets the
    # mountpoint itself and refuses (422) rather than silently normalising it.
    bad = batch(mountpoint="/sftp/nas-1/../../etc")
    resp = await api_client.post("/api/v1/agents/ingest", json=bad, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 422
    assert "mountpoint" in resp.text


async def test_ingest_batch_too_large(api_client: httpx.AsyncClient, settings) -> None:
    # A batch one over the configured max must be rejected (DoS guard, AR-0012).
    over = settings.ingest_max_batch + 1
    entries = [_entry("/mnt/pool", f"f{i}", i + 10, size=1) for i in range(over)]
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=entries), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 422
