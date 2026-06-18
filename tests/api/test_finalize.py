"""Finalize endpoint tests — same mTLS/proxy boundary as ingest, then rollup recompute (ADD 09 §8).

The agent posts ``/api/v1/agents/finalize`` once after its drain; the server recomputes
``subtree_rollup`` for the calling host's freshly-ingested volumes. Carries the SAME
``FingerprintDep`` (mTLS fingerprint + ingest-proxy-secret) boundary as ingest and is NOT on the
human-auth path (AR-0012).
"""

from __future__ import annotations

from pathlib import Path

import httpx
from asgi_lifespan import LifespanManager
from sqlalchemy import func, select

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.catalogue.models import Snapshot, SubtreeRollup
from fathom.core.settings import Settings
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


async def test_finalize_requires_client_cert(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.post("/api/v1/agents/finalize")
    assert resp.status_code == 401


async def test_finalize_requires_proxy_secret_when_configured(tmp_path: Path) -> None:
    # Same boundary as ingest: a request that bypassed the mTLS proxy (no/forged proxy secret) is
    # rejected even with a fingerprint header (AR-0010, STRIDE Spoofing).
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
            r1 = await client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
            assert r1.status_code == 401
            r2 = await client.post(
                "/api/v1/agents/finalize",
                headers={**FINGERPRINT_HEADER, "X-Fathom-Proxy-Secret": secret},
            )
            assert r2.status_code == 200
    await db.dispose_engine()


async def test_finalize_recomputes_rollups_for_ingested_volume(
    api_client: httpx.AsyncClient,
) -> None:
    ingest = await api_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    volume_id = ingest.json()["volume_id"]
    # Before finalize there are no rollup rows → the tree/treemap would show no sizes.
    async with db.session_scope() as session:
        before = (
            await session.execute(
                select(func.count())
                .select_from(SubtreeRollup)
                .where(SubtreeRollup.volume_id == volume_id)
            )
        ).scalar_one()
    assert before == 0

    resp = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200
    body = resp.json()
    assert body["volume_ids"] == [volume_id]
    assert body["rollup_rows"] > 0

    # The subtree size is now readable through the tree endpoint (the bug this wiring fixes).
    auth = await seed_principal()
    tree = await api_client.get(
        "/api/v1/tree",
        params={"volume_id": volume_id, "path": "/mnt/pool"},
        headers=auth,
    )
    movies = next(c for c in tree.json() if c["name"] == "movies")
    assert movies["subtree_size_logical"] == 300  # a.mkv (100) + b.mkv (200)


async def test_finalize_stamps_snapshot_stats(api_client: httpx.AsyncClient) -> None:
    # Ingest opens a snapshot with 0 stats; finalize must stamp it with the volume's real totals
    # and a finish time so the Scans view shows entries/on-disk/finished instead of 0/—.
    ingest = await api_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    snapshot_id = ingest.json()["snapshot_id"]
    async with db.session_scope() as session:
        before = await session.get(Snapshot, snapshot_id)
        assert before is not None
        assert before.file_count == 0 and before.total_size == 0 and before.finished is None

    resp = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200

    async with db.session_scope() as session:
        after = await session.get(Snapshot, snapshot_id)
        assert after is not None
        # batch() = 3 files (a.mkv 100, b.mkv 200, notes.txt 50) → file_count 3, on-disk 350.
        assert after.file_count == 3
        assert after.total_size == 350
        assert after.finished is not None


async def test_finalize_stamps_all_open_snapshots(api_client: httpx.AsyncClient) -> None:
    # Two separate scans → two open snapshots on one volume. A single finalize must close BOTH
    # (e.g. a metadata scan + a full-bit scan finalized together), not just the newest.
    r1 = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    r2 = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    snap_a, snap_b = r1.json()["snapshot_id"], r2.json()["snapshot_id"]
    assert snap_a != snap_b  # each batch without a snapshot_id opens a fresh snapshot

    await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)

    async with db.session_scope() as session:
        for sid in (snap_a, snap_b):
            snap = await session.get(Snapshot, sid)
            assert snap is not None
            assert snap.finished is not None
            assert snap.file_count == 3


async def test_finalize_is_idempotent_with_nothing_new(api_client: httpx.AsyncClient) -> None:
    await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    first = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert len(first.json()["volume_ids"]) == 1
    # No new ingest since → the second finalize recomputes nothing.
    second = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert second.json()["volume_ids"] == []
    assert second.json()["rollup_rows"] == 0


# --- finalize → dedup grouping (fullbit-dedup; the wire that fills the Duplicates view) -----

_FULL = "a" * 64
_PARTIAL = "b" * 64


def _fullbit_entry(mount: str, rel: str, inode: int, *, size: int, full: str | None) -> dict:
    entry = {
        "path": f"{mount}/{rel}",
        "name": rel.rsplit("/", 1)[-1],
        "is_dir": False,
        "is_symlink": False,
        "size_logical": size,
        "size_on_disk": size,
        "mtime": 1000.0,
        "ctime": 1000.0,
        "uid": 0,
        "gid": 0,
        "inode": inode,
        "flags": {},
    }
    if full is not None:
        entry["partial_hash"] = _PARTIAL
        entry["full_hash"] = full
    return entry


async def test_finalize_builds_dedup_groups_for_fullbit_ingest(
    api_client: httpx.AsyncClient,
) -> None:
    # The end-to-end wire: a full-bit ingest of two identical files, then the agent's post-drain
    # finalize, builds a report-only dup group the /duplicates read API surfaces — with NO separate
    # DedupService call (the gap this fixes: the Duplicates view was empty on a live host).
    body = batch(
        mode="fullbit",
        entries=[
            _fullbit_entry("/mnt/pool", "movies/a.mkv", 3, size=100, full=_FULL),
            _fullbit_entry("/mnt/pool", "movies/b.mkv", 4, size=100, full=_FULL),  # identical bytes
            _fullbit_entry("/mnt/pool", "movies/c.mkv", 5, size=100, full="c" * 64),  # unique
        ],
    )
    ingest = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert ingest.status_code == 200

    finalize = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert finalize.status_code == 200
    assert finalize.json()["dup_groups"] == 1  # one confirmed group (a.mkv == b.mkv)

    # The group is now visible through the read surface without any manual grouping step.
    auth = await seed_principal()
    page = (await api_client.get("/api/v1/duplicates", headers=auth)).json()
    assert len(page["items"]) == 1
    group = page["items"][0]
    assert group["full_hash"] == _FULL
    assert group["member_count"] == 2
    assert group["reclaimable_bytes"] == 100  # size * (members - 1)


async def test_finalize_rebuilds_dedup_idempotently(api_client: httpx.AsyncClient) -> None:
    # Re-running finalize over the same hashes rebuilds the same single group (replace=True), not a
    # duplicate-of-a-duplicate — the read API still shows exactly one group.
    body = batch(
        mode="fullbit",
        entries=[
            _fullbit_entry("/mnt/pool", "x", 3, size=100, full=_FULL),
            _fullbit_entry("/mnt/pool", "y", 4, size=100, full=_FULL),
        ],
    )
    await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    first = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert first.json()["dup_groups"] == 1
    second = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert second.json()["dup_groups"] == 1

    auth = await seed_principal()
    page = (await api_client.get("/api/v1/duplicates", headers=auth)).json()
    assert len(page["items"]) == 1  # still exactly one group, not two


async def test_finalize_metadata_only_builds_no_dedup_groups(
    api_client: httpx.AsyncClient,
) -> None:
    # The OFF-by-default invariant: a metadata-only deployment (no full hashes anywhere) rebuilds
    # zero dup groups and the Duplicates view stays empty — existing deployments are unchanged.
    await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    finalize = await api_client.post("/api/v1/agents/finalize", headers=FINGERPRINT_HEADER)
    assert finalize.json()["dup_groups"] == 0

    auth = await seed_principal()
    page = (await api_client.get("/api/v1/duplicates", headers=auth)).json()
    assert page["items"] == []


async def test_finalize_metadata_host_skips_dedup_in_mixed_estate(
    api_client: httpx.AsyncClient,
) -> None:
    # MIXED-estate regression (the win11 cause): a full-bit host builds dup groups; a SEPARATE
    # metadata-only host's routine finalize must NOT trigger an estate-wide rebuild merely because
    # the full-bit host left hashes behind. Before the scope-down the trigger was estate-wide, so
    # the metadata host re-ran the WHOLE estate's dedup on every finalize (the spurious-504 / NAS
    # CPU-spike cause). The dedup grouping stays estate-wide; only its *trigger* is host-scoped.
    fp_fullbit = {"X-Client-Cert-Fingerprint": "aa:aa:aa:aa"}
    fp_metadata = {"X-Client-Cert-Fingerprint": "bb:bb:bb:bb"}

    # Host A — full-bit with a duplicate pair → one estate dup group.
    await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(
            mode="fullbit",
            entries=[
                _fullbit_entry("/mnt/pool", "a", 3, size=100, full=_FULL),
                _fullbit_entry("/mnt/pool", "b", 4, size=100, full=_FULL),
            ],
        ),
        headers=fp_fullbit,
    )
    assert (await api_client.post("/api/v1/agents/finalize", headers=fp_fullbit)).json()[
        "dup_groups"
    ] == 1

    # Host B — metadata-only, distinct name + its own mountpoint. Its finalize must rebuild NOTHING.
    await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(
            mountpoint="/srv/data",
            host={"name": "metadata-host", "os": "Linux", "agent_version": "0.1.0"},
        ),
        headers=fp_metadata,
    )
    b_fin = await api_client.post("/api/v1/agents/finalize", headers=fp_metadata)
    assert b_fin.json()["dup_groups"] == 0  # the fix: a metadata host triggers no estate rebuild

    # Host A's group is untouched by B's finalize — still exactly one group on the read surface.
    auth = await seed_principal()
    page = (await api_client.get("/api/v1/duplicates", headers=auth)).json()
    assert len(page["items"]) == 1
