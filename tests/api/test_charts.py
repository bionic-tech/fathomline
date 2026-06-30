"""Chart endpoint tests — treemap / top-N / growth series (ui-viewer, ADD 09 §4, ADD 13).

Mirrors the read-router fixtures: ingest a batch, build the rollup, then exercise the new
chart surface. Asserts subtree sizes come from ``subtree_rollup``, the server-side node caps
hold, top-N ordering by on_disk/logical/kind, growth-series downsampling, and that scope is
enforced (out-of-scope volume → 403, deny-by-default → 401).
"""

from __future__ import annotations

import httpx
from sqlalchemy import update

from fathom.core import db
from fathom.core.catalogue.models import FsEntryRow, Volume
from fathom.core.rollup import RollupService
from tests.api.conftest import FINGERPRINT_HEADER, _entry, batch, seed_principal


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


async def _ingest_entries_and_rollup(
    api_client: httpx.AsyncClient, entries: list[dict], *, mountpoint: str = "/mnt/pool"
) -> int:
    """Ingest a custom entry list (then rollup) — for fan-out / fallback / escape cases."""
    resp = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(mountpoint=mountpoint, entries=entries),
        headers=FINGERPRINT_HEADER,
    )
    volume_id = resp.json()["volume_id"]
    async with db.session_scope() as session:
        await RollupService(session).recompute_full(volume_id)
    return volume_id


async def _soft_delete(volume_id: int, path: str) -> None:
    """Flip one entry to ``present=False`` (the incremental soft-delete marker)."""
    async with db.session_scope() as session:
        await session.execute(
            update(FsEntryRow)
            .where(FsEntryRow.volume_id == volume_id, FsEntryRow.path == path)
            .values(present=False)
        )


async def _set_system_volume(volume_id: int) -> int:
    """Mark a volume ``kind='system'`` (AR-011 gate) and return its ``host_id``."""
    async with db.session_scope() as session:
        volume = await session.get(Volume, volume_id)
        assert volume is not None
        host_id = volume.host_id
        volume.kind = "system"
    return host_id


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


async def test_top_n_requires_auth(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    resp = await api_client.get(
        "/api/v1/top-n", params={"volume_id": volume_id, "path": "/mnt/pool"}
    )
    assert resp.status_code == 401  # deny-by-default — VIEW_METADATA required


async def test_top_n_out_of_scope_volume_forbidden(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal(username="hostuser", scope_kind="host", host_id=9999)
    resp = await api_client.get(
        "/api/v1/top-n", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 403  # existing volume, out of this principal's scope


async def test_top_n_unknown_volume_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/top-n", params={"volume_id": 999, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 404  # absent volume → 404 (distinct from out-of-scope 403)


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


async def test_growth_series_requires_auth(api_client: httpx.AsyncClient) -> None:
    volume_id = await _ingest_and_rollup(api_client)
    resp = await api_client.get(
        "/api/v1/history/series", params={"volume_id": volume_id, "path": "/mnt/pool"}
    )
    assert resp.status_code == 401  # deny-by-default — VIEW_METADATA required


async def test_growth_series_unknown_volume_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/history/series", params={"volume_id": 999, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 404  # absent volume → 404


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


# --- top-N: server-side cap + deterministic ordering (EC-charts-5/15/16) -----------------


async def test_top_n_caps_rowset_to_n_with_many_children(api_client: httpx.AsyncClient) -> None:
    """60 children seeded, n=10 → exactly the 10 largest (cap is enforced in SQL, not Python)."""
    entries = [_entry("/mnt/pool", "", 1, is_dir=True)]
    # f00..f59 with strictly increasing on-disk size (i+1), so the largest 10 are f59..f50.
    entries += [_entry("/mnt/pool", f"f{i:02d}.dat", i + 2, size=i + 1) for i in range(60)]
    volume_id = await _ingest_entries_and_rollup(api_client, entries)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/top-n",
        params={"volume_id": volume_id, "path": "/mnt/pool", "n": 10, "by": "on_disk"},
        headers=auth,
    )
    assert resp.status_code == 200
    names = [i["name"] for i in resp.json()]
    assert len(names) == 10  # capped at n despite 60 live children
    assert names == [f"f{i:02d}.dat" for i in range(59, 49, -1)]  # the 10 largest, biggest first


async def test_top_n_tie_order_is_deterministic_by_path(api_client: httpx.AsyncClient) -> None:
    """Equal-size children order stably by path ASC (deterministic tie-break)."""
    scrambled = ["zebra.dat", "mango.dat", "apple.dat", "quartz.dat", "berry.dat"]
    entries = [_entry("/mnt/pool", "", 1, is_dir=True)]
    entries += [_entry("/mnt/pool", name, i + 2, size=100) for i, name in enumerate(scrambled)]
    volume_id = await _ingest_entries_and_rollup(api_client, entries)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/top-n",
        params={"volume_id": volume_id, "path": "/mnt/pool", "n": 50, "by": "on_disk"},
        headers=auth,
    )
    assert resp.status_code == 200
    names = [i["name"] for i in resp.json()]
    # All sizes equal → tie broken by path ASC → names come back sorted, every call.
    assert names == sorted(scrambled)


# --- top-N: system-volume scope gate (EC-charts-7) ---------------------------------------


async def test_top_n_system_volume_403_for_host_grant(api_client: httpx.AsyncClient) -> None:
    """A host-scoped grant on the right host is still 403'd for a kind='system' volume (AR-011)."""
    volume_id = await _ingest_and_rollup(api_client)
    host_id = await _set_system_volume(volume_id)
    # The grant covers the volume's host, so absent the system gate this would pass.
    auth = await seed_principal(username="hostuser", scope_kind="host", host_id=host_id)
    resp = await api_client.get(
        "/api/v1/top-n", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "system volume out of scope"


# --- input validation → 422 (EC-charts-10/EC-largest-7) ----------------------------------


async def test_top_n_invalid_params_422(api_client: httpx.AsyncClient) -> None:
    """Out-of-range / out-of-vocabulary query params are rejected before the handler runs."""
    auth = await seed_principal()
    base = {"volume_id": 1, "path": "/mnt/pool"}
    for bad in (
        {"volume_id": 0},  # ge=1
        {"path": ""},  # min_length=1
        {"by": "bogus"},  # Literal[on_disk, logical]
        {"kind": "bogus"},  # Literal[dir, file, any]
        {"n": 0},  # ge=1
    ):
        resp = await api_client.get("/api/v1/top-n", params={**base, **bad}, headers=auth)
        assert resp.status_code == 422, bad


async def test_treemap_invalid_params_422(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    base = {"volume_id": 1, "path": "/mnt/pool"}
    for bad in ({"volume_id": 0}, {"path": ""}):
        resp = await api_client.get("/api/v1/treemap", params={**base, **bad}, headers=auth)
        assert resp.status_code == 422, bad


async def test_history_series_buckets_below_min_422(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/history/series",
        params={"volume_id": 1, "path": "/mnt/pool", "buckets": 1},  # ge=2
        headers=auth,
    )
    assert resp.status_code == 422


# --- rollup-missing fallback (EC-charts-14/EC-largest-9) ----------------------------------


async def test_rollup_missing_fallback_size_and_count(api_client: httpx.AsyncClient) -> None:
    """A child with no SubtreeRollup falls back to its own size; file_count = 0 dir / 1 file."""
    entries = [
        _entry("/mnt/pool", "", 1, is_dir=True),
        _entry("/mnt/pool", "empty", 2, is_dir=True),  # no descendants → no rollup row
        _entry("/mnt/pool", "readme.txt", 3, size=42),  # leaf file → no rollup row
    ]
    volume_id = await _ingest_entries_and_rollup(api_client, entries)
    auth = await seed_principal()

    tree = {
        n["name"]: n
        for n in (
            await api_client.get(
                "/api/v1/treemap",
                params={"volume_id": volume_id, "path": "/mnt/pool"},
                headers=auth,
            )
        ).json()
    }
    assert tree["empty"]["subtree_size_on_disk"] == 0
    assert tree["empty"]["file_count"] == 0  # dir fallback
    assert tree["readme.txt"]["subtree_size_on_disk"] == 42  # entry's own size
    assert tree["readme.txt"]["file_count"] == 1  # file fallback

    top = {
        i["name"]: i
        for i in (
            await api_client.get(
                "/api/v1/top-n",
                params={"volume_id": volume_id, "path": "/mnt/pool", "by": "on_disk"},
                headers=auth,
            )
        ).json()
    }
    assert top["readme.txt"]["size_on_disk"] == 42
    assert top["readme.txt"]["file_count"] == 1
    assert top["empty"]["size_on_disk"] == 0
    assert top["empty"]["file_count"] == 0


# --- soft-deleted entries excluded (EC-charts-15/EC-largest-8) ----------------------------


async def test_soft_deleted_child_excluded(api_client: httpx.AsyncClient) -> None:
    """A present=False child never appears in the current-state treemap or top-N."""
    volume_id = await _ingest_and_rollup(api_client)
    await _soft_delete(volume_id, "/mnt/pool/docs")
    auth = await seed_principal()

    tree = await api_client.get(
        "/api/v1/treemap", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert {n["name"] for n in tree.json()} == {"movies"}  # docs is soft-deleted → gone

    top = await api_client.get(
        "/api/v1/top-n", params={"volume_id": volume_id, "path": "/mnt/pool"}, headers=auth
    )
    assert [i["name"] for i in top.json()] == ["movies"]


# --- escape_like keeps wildcards literal (EC-charts-16) -----------------------------------


async def test_escape_like_matches_path_literally(api_client: httpx.AsyncClient) -> None:
    """A path containing a literal '_' must not match a wildcard sibling (AR-0015)."""
    entries = [
        _entry("/mnt/pool", "", 1, is_dir=True),
        _entry("/mnt/pool", "a_b", 2, is_dir=True),
        _entry("/mnt/pool", "a_b/inside.txt", 3, size=10),
        _entry("/mnt/pool", "axb", 4, is_dir=True),  # would match 'a_b' if '_' were a wildcard
        _entry("/mnt/pool", "axb/other.txt", 5, size=20),
    ]
    volume_id = await _ingest_entries_and_rollup(api_client, entries)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/treemap",
        params={"volume_id": volume_id, "path": "/mnt/pool/a_b"},
        headers=auth,
    )
    assert resp.status_code == 200
    names = [n["name"] for n in resp.json()]
    assert names == ["inside.txt"]  # 'axb/other.txt' excluded → '_' matched literally


# --- history inverted window + treemap depth no-op + empty kind filter --------------------


async def test_history_series_inverted_window_empty(api_client: httpx.AsyncClient) -> None:
    """since > until is not an error: the impossible window yields an explicitly-empty series."""
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/history/series",
        params={
            "volume_id": volume_id,
            "path": "/mnt/pool",
            "since": "2999-01-01T00:00:00Z",
            "until": "2000-01-01T00:00:00Z",
        },
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json()["points"] == []


async def test_treemap_depth_is_single_level_no_op(api_client: httpx.AsyncClient) -> None:
    """depth is the lazy-drill contract only: one level per call, so depth=1 == depth=3."""
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    r1 = await api_client.get(
        "/api/v1/treemap",
        params={"volume_id": volume_id, "path": "/mnt/pool", "depth": 1},
        headers=auth,
    )
    r3 = await api_client.get(
        "/api/v1/treemap",
        params={"volume_id": volume_id, "path": "/mnt/pool", "depth": 3},
        headers=auth,
    )
    assert r1.status_code == 200 and r3.status_code == 200
    assert r1.json() == r3.json()  # identical single level regardless of depth


async def test_top_n_kind_filter_empty_for_opposite_kind(api_client: httpx.AsyncClient) -> None:
    """All children are one kind → the opposite-kind filter returns an empty list."""
    volume_id = await _ingest_and_rollup(api_client)
    auth = await seed_principal()
    # /mnt/pool/movies holds only files; asking for directories must return [].
    resp = await api_client.get(
        "/api/v1/top-n",
        params={"volume_id": volume_id, "path": "/mnt/pool/movies", "kind": "dir"},
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json() == []
