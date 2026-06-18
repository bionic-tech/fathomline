"""Incremental ingest API tests — present/removed_at + change_log over the real ingest path.

Covers the incremental test_plan at the API trust boundary:
- a metadata batch carrying ``removed_inodes`` flips the catalogue row to present=False and the
  tree drill-down no longer lists it (a deleted file never inflates the current-state view);
- the reconciliation emits change_log rows the ``/changes`` read surfaces;
- ``removed_inodes`` is bounded by the same per-batch cap (DoS guard, AR-0012);
- a full-bit batch carrying removals does NOT churn the feed / remove rows (full-bit re-hashes
  existing files; removals are an explicit metadata-feed signal only).
"""

from __future__ import annotations

import httpx

from fathom.auth.principal import Role
from tests.api.conftest import FINGERPRINT_HEADER, _entry, batch, seed_principal


async def _ingest(client: httpx.AsyncClient, body: dict) -> dict:
    resp = await client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_removed_inode_marks_not_present_and_drops_from_tree(
    api_client: httpx.AsyncClient,
) -> None:
    # Baseline: /mnt/pool with movies/a.mkv (inode 3) + movies/b.mkv (inode 4).
    first = await _ingest(api_client, batch())
    vol = first["volume_id"]
    # Incremental cycle: a.mkv (inode 3) was deleted on disk.
    delta = batch(entries=[], removed_inodes=[3], snapshot_id=first["snapshot_id"])
    result = await _ingest(api_client, delta)
    assert result["entries_removed"] == 1
    assert result["changes_logged"] == 1

    auth = await seed_principal()
    tree = await api_client.get(
        "/api/v1/tree", params={"volume_id": vol, "path": "/mnt/pool/movies"}, headers=auth
    )
    paths = [c["path"] for c in tree.json()]
    assert "/mnt/pool/movies/a.mkv" not in paths  # removed → excluded from current tree
    assert "/mnt/pool/movies/b.mkv" in paths  # survivor still present


async def test_change_log_emitted_and_readable(api_client: httpx.AsyncClient) -> None:
    first = await _ingest(api_client, batch())
    vol = first["volume_id"]
    # Modify movies/a.mkv (inode 3) grows 100 -> 300; remove docs/notes.txt (inode 6).
    grown = _entry("/mnt/pool", "movies/a.mkv", 3, size=300)
    grown["mtime"] = 5000.0
    await _ingest(
        api_client,
        batch(entries=[grown], removed_inodes=[6], snapshot_id=first["snapshot_id"]),
    )
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/changes", params={"volume_id": vol}, headers=auth)
    assert resp.status_code == 200
    # Newest first: the baseline ingest already emitted a CREATE for every entry, so keep the
    # most-recent change per path (first occurrence in the newest-first list).
    latest: dict[str, dict] = {}
    for c in resp.json():
        latest.setdefault(c["path"], c)
    assert latest["/mnt/pool/movies/a.mkv"]["change_type"] == "modify"
    assert latest["/mnt/pool/movies/a.mkv"]["size_delta"] == 200
    assert latest["/mnt/pool/docs/notes.txt"]["change_type"] == "delete"
    assert latest["/mnt/pool/docs/notes.txt"]["size_delta"] == -50


async def test_removed_inodes_bounded(api_client: httpx.AsyncClient, settings) -> None:
    over = settings.ingest_max_batch + 1
    body = batch(entries=[], removed_inodes=list(range(over)))
    resp = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 422  # removed_inodes over the cap is refused (DoS guard)


async def test_fullbit_batch_ignores_removals(api_client: httpx.AsyncClient) -> None:
    first = await _ingest(api_client, batch())
    vol = first["volume_id"]
    # A full-bit batch that (wrongly) carries removals must NOT remove rows or churn the feed:
    # removals are an explicit metadata-feed signal; full-bit only re-hashes existing files.
    fb = _entry("/mnt/pool", "movies/a.mkv", 3, size=100)
    fb["full_hash"] = "a" * 64
    fb["partial_hash"] = "b" * 64
    result = await _ingest(api_client, batch(mode="fullbit", entries=[fb], removed_inodes=[4]))
    assert result["entries_removed"] == 0
    assert result["changes_logged"] == 0
    auth = await seed_principal()
    tree = await api_client.get(
        "/api/v1/tree", params={"volume_id": vol, "path": "/mnt/pool/movies"}, headers=auth
    )
    paths = [c["path"] for c in tree.json()]
    assert "/mnt/pool/movies/b.mkv" in paths  # inode 4 NOT removed by the full-bit batch


async def test_removed_entry_excluded_from_charts(api_client: httpx.AsyncClient) -> None:
    # A soft-deleted entry must not appear in the current-state treemap / top-N either.
    first = await _ingest(api_client, batch())
    vol = first["volume_id"]
    await _ingest(
        api_client,
        batch(entries=[], removed_inodes=[3], snapshot_id=first["snapshot_id"]),  # a.mkv gone
    )
    auth = await seed_principal()
    params = {"volume_id": vol, "path": "/mnt/pool/movies"}
    treemap = await api_client.get("/api/v1/treemap", params=params, headers=auth)
    assert treemap.status_code == 200
    tm_paths = [n["path"] for n in treemap.json()]
    assert "/mnt/pool/movies/a.mkv" not in tm_paths
    top = await api_client.get("/api/v1/top-n", params={**params, "kind": "file"}, headers=auth)
    assert top.status_code == 200
    top_paths = [i["path"] for i in top.json()]
    assert "/mnt/pool/movies/a.mkv" not in top_paths


async def test_changes_out_of_scope_volume_forbidden(api_client: httpx.AsyncClient) -> None:
    # Seed a volume, then a principal scoped to a DIFFERENT (non-existent) volume id → 403.
    first = await _ingest(api_client, batch())
    vol = first["volume_id"]
    auth = await seed_principal(
        username="narrow",
        role=Role.VIEWER,
        scope_kind="volume",
        host_id=first["host_id"],
        volume_id=vol + 999,  # not the ingested volume
    )
    resp = await api_client.get("/api/v1/changes", params={"volume_id": vol}, headers=auth)
    assert resp.status_code == 403  # churn read of an out-of-scope volume is rejected
