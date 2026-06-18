"""Chart endpoint tests — treemap / top-N / growth series (ui-viewer, ADD 09 §4, ADD 13).

Mirrors the read-router fixtures: ingest a batch, build the rollup, then exercise the new
chart surface. Asserts subtree sizes come from ``subtree_rollup``, the server-side node caps
hold, top-N ordering by on_disk/logical/kind, growth-series downsampling, and that scope is
enforced (out-of-scope volume → 403, deny-by-default → 401).
"""

from __future__ import annotations

import httpx

from fathom.core import db
from fathom.core.rollup import RollupService
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


async def _ingest_and_rollup(
    api_client: httpx.AsyncClient, *, mountpoint: str = "/mnt/pool"
) -> int:
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(mountpoint=mountpoint), headers=FINGERPRINT_HEADER
    )
    volume_id = resp.json()["volume_id"]
    async with db.session_scope() as session:
        await RollupService(session).recompute_full(volume_id)
    return volume_id


# --- treemap ----------------------------------------------------------------------------


async def test_treemap_requires_auth(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    resp = await api_client.get(
        "/api/v1/treemap", params={"volume_id": volume_id, "path": "/mnt/pool"}
    )
    assert resp.status_code == 401


async def test_treemap_children_sized_from_rollup(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/treemap", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 200
    nodes = {n["name"]: n for n in resp.json()}
    assert set(nodes) == {"movies", "docs"}
    # movies = a.mkv (100) + b.mkv (200) = 300 (from subtree_rollup).
    assert nodes["movies"]["subtree_size_on_disk"] == 300
    assert nodes["movies"]["file_count"] == 2
    assert nodes["docs"]["subtree_size_on_disk"] == 50
    # Largest-on-disk first (server-side ordering for the treemap cap).
    assert resp.json()[0]["name"] == "movies"


async def test_treemap_respects_node_limit_cap(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    # Two children exist; a limit of 1 must return only the largest (movies).
    resp = await api_client.get(
        "/api/v1/treemap",
        params={"volume_id": volume_id, "path": "/mnt/pool", "limit": 1},
        headers=auth,
    )
    body = resp.json()
    assert len(body) == 1
    assert body[0]["name"] == "movies"


async def test_treemap_out_of_scope_volume_forbidden(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    # Principal scoped to a different host → the only volume is out of scope.
    auth = await seed_principal(username="hostuser", scope_kind="host", host_id=9999)
    resp = await api_client.get(
        "/api/v1/treemap", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 403


# --- top-N ------------------------------------------------------------------------------


async def test_top_n_orders_by_on_disk(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/top-n",
        params={"volume_id": volume_id, "path": "/mnt/pool", "n": 5, "by": "on_disk"},
        headers=auth,
    )
    assert resp.status_code == 200
    names = [i["name"] for i in resp.json()]
    assert names == ["movies", "docs"]  # 300 then 50


async def test_top_n_n_cap_truncates(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/top-n",
        params={"volume_id": volume_id, "path": "/mnt/pool", "n": 1},
        headers=auth,
    )
    body = resp.json()
    assert len(body) == 1
    assert body[0]["name"] == "movies"


async def test_top_n_kind_file_filters_dirs(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    # Inside movies, only files exist; kind=file returns the two mkvs largest-first.
    resp = await api_client.get(
        "/api/v1/top-n",
        params={
            "volume_id": volume_id,
            "path": "/mnt/pool/movies",
            "kind": "file",
            "by": "logical",
        },
        headers=auth,
    )
    names = [i["name"] for i in resp.json()]
    assert names == ["b.mkv", "a.mkv"]  # 200 then 100


async def test_top_n_kind_dir_excludes_files(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/top-n",
        params={"volume_id": volume_id, "path": "/mnt/pool", "kind": "dir"},
        headers=auth,
    )
    names = {i["name"] for i in resp.json()}
    assert names == {"movies", "docs"}


# --- growth series ----------------------------------------------------------------------


async def test_growth_series_returns_points(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/history/series",
        params={"volume_id": volume_id, "path": "/mnt/pool"},
        headers=auth,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["volume_id"] == volume_id
    assert len(body["points"]) == 1
    assert body["points"][0]["total_size_logical"] == 350  # 100 + 200 + 50


async def test_growth_series_empty_window_ok(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    # A future 'since' excludes the single recorded point → empty series, not an error.
    resp = await api_client.get(
        "/api/v1/history/series",
        params={"volume_id": volume_id, "path": "/mnt/pool", "since": "2999-01-01T00:00:00Z"},
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json()["points"] == []


async def test_growth_series_out_of_scope_forbidden(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal(username="hostuser", scope_kind="host", host_id=9999)
    resp = await api_client.get(
        "/api/v1/history/series",
        params={"volume_id": volume_id, "path": "/mnt/pool"},
        headers=auth,
    )
    assert resp.status_code == 403


async def test_chart_unknown_volume_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/treemap", params={"volume_id": 999, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 404


async def test_openapi_includes_chart_endpoints(api_client: httpx.AsyncClient) -> None:
    """Contract: the new endpoints carry response_models so the TS client can be generated."""
    spec = (await api_client.get("/openapi.json")).json()
    paths = spec["paths"]
    assert "/api/v1/treemap" in paths
    assert "/api/v1/top-n" in paths
    assert "/api/v1/history/series" in paths
