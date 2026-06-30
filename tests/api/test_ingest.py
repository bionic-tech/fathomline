"""Ingest API tests — auth, idempotency, and server-side scope re-enforcement (AR-0012)."""

from __future__ import annotations

from pathlib import Path

import httpx
from asgi_lifespan import LifespanManager
from sqlalchemy import func, select

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.catalogue.models import FsEntryRow, Host
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


async def test_ingest_nonexistent_snapshot_id_is_422(api_client: httpx.AsyncClient) -> None:
    """A snapshot_id that doesn't exist is refused (422) — _resolve_snapshot fails closed."""
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(snapshot_id=999_999), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 422
    assert "snapshot_id" in resp.json()["detail"]


async def test_ingest_snapshot_id_from_other_volume_is_422(api_client: httpx.AsyncClient) -> None:
    """A snapshot_id bound to a DIFFERENT volume (same host) is refused (422).

    _resolve_snapshot ties a reused snapshot to its (host, volume); a batch on volume B that cites
    volume A's snapshot must not graft entries onto A's snapshot (cross-volume confusion, AR-0012).
    """
    first = await api_client.post(
        "/api/v1/agents/ingest", json=batch(mountpoint="/mnt/a"), headers=FINGERPRINT_HEADER
    )
    snap_a = first.json()["snapshot_id"]
    resp = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(mountpoint="/mnt/b", snapshot_id=snap_a),
        headers=FINGERPRINT_HEADER,
    )
    assert resp.status_code == 422
    assert "snapshot_id" in resp.json()["detail"]


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


async def test_ingest_removed_keys_on_dev_inode(api_client: httpx.AsyncClient) -> None:
    # The DELETE path keyed on (dev, inode): two cross-dataset files share inode 5 (each on its own
    # ZFS child dataset, different st_dev). A removal carrying the precise (dev, inode) of one copy
    # must flip ONLY that row — the other device's row stays present. Before the fix the inode-only
    # removal flipped both and emitted a false DELETE for the survivor.
    a = _entry("/mnt/pool", "dataset_a/file", 5, size=100)
    a["dev"] = 64769
    b = _entry("/mnt/pool", "dataset_b/file", 5, size=200)
    b["dev"] = 64770
    first = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=[a, b]), headers=FINGERPRINT_HEADER
    )
    assert first.status_code == 200, first.text
    volume_id = first.json()["volume_id"]
    snap = first.json()["snapshot_id"]
    # Remove only the dev=64769 copy via the precise (dev, inode) wire signal.
    delta = batch(entries=[], removed=[{"dev": 64769, "inode": 5}], snapshot_id=snap)
    result = await api_client.post(
        "/api/v1/agents/ingest", json=delta, headers=FINGERPRINT_HEADER
    )
    assert result.status_code == 200, result.text
    assert result.json()["entries_removed"] == 1  # only the one device's row flipped
    async with db.session_scope() as session:
        rows = (
            await session.execute(
                select(FsEntryRow.dev, FsEntryRow.present)
                .where(FsEntryRow.volume_id == volume_id, FsEntryRow.inode == 5)
                .order_by(FsEntryRow.dev)
            )
        ).all()
    present = {r.dev: r.present for r in rows}
    assert present[64769] is False  # the removed copy
    assert present[64770] is True  # the survivor untouched (the cross-dataset bug is fixed)


async def test_ingest_legacy_removed_inodes_still_applies(api_client: httpx.AsyncClient) -> None:
    # A pre-(dev,inode) agent sends only the legacy removed_inodes (no dev). The server carries
    # those as (None, inode) and falls back to an inode-only match, so the removal still applies —
    # the backward-compatible half of the wire change.
    first = await api_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    assert first.status_code == 200, first.text
    volume_id = first.json()["volume_id"]
    snap = first.json()["snapshot_id"]
    delta = batch(entries=[], removed_inodes=[3], snapshot_id=snap)  # movies/a.mkv, inode 3
    result = await api_client.post(
        "/api/v1/agents/ingest", json=delta, headers=FINGERPRINT_HEADER
    )
    assert result.status_code == 200, result.text
    assert result.json()["entries_removed"] == 1
    async with db.session_scope() as session:
        row = (
            await session.execute(
                select(FsEntryRow).where(FsEntryRow.volume_id == volume_id, FsEntryRow.inode == 3)
            )
        ).scalar_one()
    assert row.present is False


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


async def test_ingest_snapshot_id_from_other_host_is_422(api_client: httpx.AsyncClient) -> None:
    """A snapshot_id owned by a DIFFERENT host is refused (422) — EC-ingest-10.

    ``_resolve_snapshot`` ties a reused snapshot to its (host, volume) by the *mTLS-verified* host
    identity, never the body. Host A citing host B's snapshot_id cannot graft entries onto B's
    snapshot — the host_id mismatch fails closed (cross-host confusion, AR-0012).
    """
    host_b = {"X-Client-Cert-Fingerprint": "99:88:77:66"}
    first = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(host={"name": "host-b", "os": "TrueNAS", "agent_version": "0.1.0"}),
        headers=host_b,
    )
    assert first.status_code == 200, first.text
    snap_b = first.json()["snapshot_id"]
    # Host A (the default fingerprint) cites host B's snapshot → host mismatch → 422.
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(snapshot_id=snap_b), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "snapshot_id does not belong to this host/volume"


async def test_ingest_pre_facts_batch_preserves_facts_and_config(
    api_client: httpx.AsyncClient,
) -> None:
    """A later pre-facts batch must not null previously-known host facts/config (EC-ingest-13).

    ``_upsert_host`` writes ``facts`` only when the agent reports them (ADR-037) and never touches
    ``reported_config`` at all (that is mirrored from the run report, ADR-033). So a pre-facts
    agent re-ingesting on the same fingerprint leaves the stored facts and mirrored config intact.
    """
    facts = {"cpu_cores": 8, "ram_bytes": 16_000_000_000, "gpu_name": "RTX 4090"}
    first = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(
            host={"name": "nas-1", "os": "TrueNAS", "agent_version": "0.1.0", "facts": facts}
        ),
        headers=FINGERPRINT_HEADER,
    )
    assert first.status_code == 200, first.text

    # Establish a previously-mirrored agent config (ADR-033), as a run report would have.
    fp = FINGERPRINT_HEADER["X-Client-Cert-Fingerprint"]
    config = {"cross_mounts": True, "scan_scope": ["/mnt/pool"]}
    async with db.session_scope() as session:
        host = (
            await session.execute(select(Host).where(Host.cert_fingerprint == fp))
        ).scalar_one()
        stored_facts = dict(host.facts)  # the model_dump the server persisted (with null fields)
        host.reported_config = config

    # A pre-facts agent (no facts in the batch) re-ingests on the same fingerprint.
    second = await api_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    assert second.status_code == 200, second.text

    async with db.session_scope() as session:
        host = (
            await session.execute(select(Host).where(Host.cert_fingerprint == fp))
        ).scalar_one()
    assert host.facts == stored_facts  # facts NOT nulled by the pre-facts batch
    assert host.facts["cpu_cores"] == 8 and host.facts["gpu_name"] == "RTX 4090"
    assert host.reported_config == config  # ingest never touches the mirrored config
