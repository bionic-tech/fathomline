"""Read API + rollup tests — volumes, drill-down totals, history (scope-filtered, ADD 13)."""

from __future__ import annotations

import httpx
from sqlalchemy import update

from fathom.core import db
from fathom.core.catalogue.models import FsEntryRow
from fathom.core.rollup import RollupService
from tests.api.conftest import FINGERPRINT_HEADER, _entry, batch, seed_principal


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


async def test_search_unknown_volume_404(api_client: httpx.AsyncClient) -> None:
    await _ingest_and_rollup(api_client)
    auth = await seed_principal()  # global admin → in scope; the volume just doesn't exist
    resp = await api_client.get(
        "/api/v1/search", params={"q": "mkv", "volume_id": 999}, headers=auth
    )
    assert resp.status_code == 404  # absent volume hint → 404 (distinct from out-of-scope 403)


async def test_search_escapes_like_wildcards(api_client: httpx.AsyncClient) -> None:
    # AR-0015: a literal '_' in the query must not behave as a single-char LIKE wildcard, so a
    # search for 'a_b' returns the literal 'a_b.txt' and never the decoy 'axb.txt'.
    entries = [
        _entry("/mnt/pool", "", 1, is_dir=True),
        _entry("/mnt/pool", "a_b.txt", 2, size=10),
        _entry("/mnt/pool", "axb.txt", 3, size=20),
    ]
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=entries), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200, resp.text
    auth = await seed_principal()
    hits = await api_client.get("/api/v1/search", params={"q": "a_b.txt"}, headers=auth)
    assert {h["name"] for h in hits.json()} == {"a_b.txt"}  # axb.txt excluded


async def test_tree_excludes_soft_deleted(api_client: httpx.AsyncClient) -> None:
    # A soft-deleted (present=False) entry is retained for history/churn but must never appear in
    # the live drill-down (incremental: present/removed_at markers).
    volume_id = await _ingest_and_rollup(api_client)
    async with db.session_scope() as s:
        await s.execute(
            update(FsEntryRow)
            .where(FsEntryRow.path == "/mnt/pool/movies/a.mkv")
            .values(present=False)
        )
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/tree", params={"volume_id": volume_id, "path": "/mnt/pool/movies"}, headers=auth
    )
    names = {c["name"] for c in resp.json()}
    assert names == {"b.mkv"}  # a.mkv was soft-deleted → excluded from the live tree


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


async def test_tree_out_of_scope_volume_403(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-6: a host/volume-scoped principal drilling an in-existence-but-out-of-scope
    # volume is rejected 403 (scope-checked before any row is read), not silently empty.
    volume_id = await _ingest_and_rollup(api_client)
    scoped = await seed_principal(
        username="scoped", scope_kind="volume", volume_id=volume_id + 999
    )
    resp = await api_client.get(
        "/api/v1/tree", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=scoped
    )
    assert resp.status_code == 403


async def test_history_out_of_scope_volume_403(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-6: same scope gate for the history time-series.
    volume_id = await _ingest_and_rollup(api_client)
    scoped = await seed_principal(
        username="scoped", scope_kind="volume", volume_id=volume_id + 999
    )
    resp = await api_client.get(
        "/api/v1/history", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=scoped
    )
    assert resp.status_code == 403


async def test_tree_rejects_invalid_params(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-11: the query validators reject volume_id < 1 and an empty path (422), before
    # the route body runs (so it is a 422, not a 404/200). Auth is valid so the failure is the
    # parameter validation, not the deny-by-default gate.
    auth = await seed_principal()
    bad_volume = await api_client.get(
        "/api/v1/tree", params={"volume_id": 0, "path": "/mnt/pool"}, headers=auth
    )
    assert bad_volume.status_code == 422
    empty_path = await api_client.get(
        "/api/v1/tree", params={"volume_id": 1, "path": ""}, headers=auth
    )
    assert empty_path.status_code == 422


async def test_search_rejects_invalid_params(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-11: q must be non-empty; limit must be within 1..500.
    auth = await seed_principal()
    empty_q = await api_client.get("/api/v1/search", params={"q": ""}, headers=auth)
    assert empty_q.status_code == 422
    limit_low = await api_client.get(
        "/api/v1/search", params={"q": "x", "limit": 0}, headers=auth
    )
    assert limit_low.status_code == 422
    limit_high = await api_client.get(
        "/api/v1/search", params={"q": "x", "limit": 501}, headers=auth
    )
    assert limit_high.status_code == 422


async def test_history_rejects_bad_datetime(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-11: a malformed since/until is a parameter-validation error (422), not a 500.
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/history",
        params={"volume_id": 1, "path": "/mnt/pool", "since": "not-a-date"},
        headers=auth,
    )
    assert resp.status_code == 422


async def test_volumes_empty_when_none_in_scope(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-1: a principal whose scope covers nothing (a host that owns no catalogued
    # volume) gets an empty 200, not an error — the in-scope listing is just empty.
    await _ingest_and_rollup(api_client)
    scoped = await seed_principal(username="hostuser", scope_kind="host", host_id=9999)
    resp = await api_client.get("/api/v1/volumes", headers=scoped)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_tree_empty_for_leaf_path(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-2: drilling into a leaf (a file) — or any childless path — returns an empty
    # 200, not a 404. The volume exists and is in scope; there are simply no children.
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/tree",
        params={"volume_id": volume_id, "path": "/mnt/pool/movies/a.mkv"},
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_tree_file_count_fallback_without_rollup(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-24: with no SubtreeRollup row (ingest-only, no rollup pass), file_count falls
    # back to 1 for a FILE and 0 for a DIR, and the subtree size falls back to the entry's own
    # size (query.list_children: `file_count = 0 if entry.is_dir else 1`).
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    volume_id = resp.json()["volume_id"]
    auth = await seed_principal()
    top = await api_client.get(
        "/api/v1/tree", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    dirs = {c["name"]: c for c in top.json()}
    # Rollup-less DIR → file_count 0, subtree size == the dir's own (zero) size.
    assert dirs["movies"]["file_count"] == 0
    assert dirs["movies"]["subtree_size_logical"] == 0
    sub = await api_client.get(
        "/api/v1/tree", params={"volume_id": volume_id, "path": "/mnt/pool/movies"}, headers=auth
    )
    files = {c["name"]: c for c in sub.json()}
    # Rollup-less FILE → file_count 1, subtree size == the file's own size.
    assert files["a.mkv"]["file_count"] == 1
    assert files["a.mkv"]["subtree_size_logical"] == 100
    assert files["b.mkv"]["file_count"] == 1
    assert files["b.mkv"]["subtree_size_logical"] == 200


async def test_tree_returns_all_children_no_cap(api_client: httpx.AsyncClient) -> None:
    # EC-explorer-4: the drill-down has no server-side child cap/pagination — every seeded child
    # of a directory is returned in one response.
    mount = "/mnt/pool"
    entries = [_entry(mount, "", 1, is_dir=True), _entry(mount, "big", 2, is_dir=True)]
    for i in range(30):
        entries.append(_entry(mount, f"big/f{i}.dat", 100 + i, size=i))
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=entries), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200, resp.text
    volume_id = resp.json()["volume_id"]
    auth = await seed_principal()
    tree = await api_client.get(
        "/api/v1/tree", params={"volume_id": volume_id, "path": "/mnt/pool/big"}, headers=auth
    )
    assert tree.status_code == 200
    assert len(tree.json()) == 30  # all 30 children, no cap
