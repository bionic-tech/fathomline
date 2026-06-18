"""Read API + rollup tests — volumes, drill-down totals, history (scope-filtered, ADD 13)."""

from __future__ import annotations

import httpx

from fathom.core import db
from fathom.core.rollup import RollupService
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


async def _ingest_and_rollup(api_client: httpx.AsyncClient) -> int:
    resp = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    volume_id = resp.json()["volume_id"]
    async with db.session_scope() as session:
        await RollupService(session).recompute_full(volume_id)
    return volume_id


async def test_volumes_requires_auth(api_client: httpx.AsyncClient) -> None:
    await _ingest_and_rollup(api_client)
    resp = await api_client.get("/api/v1/volumes")
    assert resp.status_code == 401


async def test_volumes_listed(api_client: httpx.AsyncClient) -> None:
    await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/volumes", headers=auth)
    assert resp.status_code == 200
    vols = resp.json()
    assert len(vols) == 1
    assert vols[0]["mountpoint"] == "/mnt/pool"
    assert vols[0]["transport"] == "sata"


async def test_tree_children_and_subtree_sizes(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/tree", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 200
    children = {c["name"]: c for c in resp.json()}
    assert set(children) == {"movies", "docs"}
    # movies subtree = a.mkv (100) + b.mkv (200) = 300
    assert children["movies"]["subtree_size_logical"] == 300
    assert children["movies"]["file_count"] == 2
    assert children["docs"]["subtree_size_logical"] == 50


async def test_tree_drill_into_subdir(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/tree",
        params={"volume_id": volume_id, "path": "/mnt/pool/movies"},
        headers=auth,
    )
    names = {c["name"] for c in resp.json()}
    assert names == {"a.mkv", "b.mkv"}


async def test_tree_exposes_entry_metadata(api_client: httpx.AsyncClient) -> None:
    # The detail pane needs per-entry metadata (owner / mtime / inode / flags), surfaced on /tree.
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/tree",
        params={"volume_id": volume_id, "path": "/mnt/pool/movies"},
        headers=auth,
    )
    a = next(c for c in resp.json() if c["name"] == "a.mkv")
    # The conftest batch() entries carry uid/gid 568 and mtime 1000.0.
    assert a["uid"] == 568
    assert a["gid"] == 568
    assert a["mtime"] == 1000.0
    assert a["inode"] > 0
    assert a["flags"] == {}
    assert a["content_hash"] is None  # metadata-only ingest leaves the hash unset


async def test_search_by_name(api_client: httpx.AsyncClient) -> None:
    # Estate find-a-file: case-insensitive name substring, scope-filtered, biggest first.
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/search", params={"q": "mkv"}, headers=auth)
    assert resp.status_code == 200
    hits = resp.json()
    names = {h["name"] for h in hits}
    assert names == {"a.mkv", "b.mkv"}
    # Biggest-first ordering (b.mkv=200 on-disk before a.mkv=100).
    assert [h["name"] for h in hits] == ["b.mkv", "a.mkv"]
    assert all(h["volume_id"] == volume_id for h in hits)

    # A term matching nothing → empty list, not an error.
    miss = await api_client.get("/api/v1/search", params={"q": "zzz-nope"}, headers=auth)
    assert miss.status_code == 200
    assert miss.json() == []


async def test_search_out_of_scope_volume_403(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    scoped = await seed_principal(username="scoped", scope_kind="volume", volume_id=volume_id + 999)
    resp = await api_client.get(
        "/api/v1/search", params={"q": "mkv", "volume_id": volume_id}, headers=scoped
    )
    assert resp.status_code == 403


async def test_history_recorded(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/history", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 200
    points = resp.json()
    assert len(points) == 1
    assert points[0]["total_size_logical"] == 350  # 100 + 200 + 50


async def test_tree_unknown_volume_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/tree", params={"volume_id": 999, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 404
