"""Duplicates router tests — list/detail, keyset pagination, scope filtering, read-only.

Covers the fullbit-dedup test_plan ``test_duplicates_api_keyset_and_scope``: the read API lists
groups, paginates by cursor, filters by volume/scope, returns read-only payloads, and excludes
out-of-scope members. Groups are produced through the real ingest → DedupService path so the
test exercises the whole report pipeline.
"""

from __future__ import annotations

import httpx

from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.dedup_service import DedupScope, DedupService
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal

_HA = "a" * 64
_HB = "b" * 64
_HC = "c" * 64
_P = "f" * 64


def _entry(mount: str, rel: str, inode: int, *, size: int, full: str) -> dict:
    return {
        "path": f"{mount}/{rel}",
        "name": rel,
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
        "partial_hash": _P,
        "full_hash": full,
    }


async def _ingest_fullbit(
    api_client: httpx.AsyncClient, *, mountpoint: str, entries: list[dict]
) -> int:
    body = batch(mountpoint=mountpoint, mode="fullbit", entries=entries)
    body["volume"]["mountpoint"] = mountpoint
    resp = await api_client.post("/api/v1/agents/ingest", json=body, headers=FINGERPRINT_HEADER)
    assert resp.status_code == 200, resp.text
    return resp.json()["volume_id"]


async def _build_groups(scope: DedupScope | None = None) -> int:
    async with db.session_scope() as session:
        groups = await DedupService(session).build(scope=scope)
        return len(groups)


async def test_duplicates_requires_auth(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.get("/api/v1/duplicates")
    assert resp.status_code == 401


async def test_duplicates_list_and_detail(api_client: httpx.AsyncClient) -> None:
    vol = await _ingest_fullbit(
        api_client,
        mountpoint="/mnt/pool",
        entries=[
            _entry("/mnt/pool", "a", 1, size=100, full=_HA),
            _entry("/mnt/pool", "b", 2, size=100, full=_HA),  # dup of a
            _entry("/mnt/pool", "c", 3, size=100, full=_HC),  # same size, different content
        ],
    )
    assert await _build_groups() == 1

    auth = await seed_principal()
    listing = await api_client.get("/api/v1/duplicates", headers=auth)
    assert listing.status_code == 200
    page = listing.json()
    assert len(page["items"]) == 1
    group = page["items"][0]
    assert group["full_hash"] == _HA
    assert group["member_count"] == 2
    assert group["reclaimable_bytes"] == 100  # size * (members - 1)
    assert group["suggested_keeper_entry_id"] is not None
    assert group["suggested_keeper_reason"]

    detail = await api_client.get(f"/api/v1/duplicates/{group['id']}", headers=auth)
    assert detail.status_code == 200
    members = detail.json()["members"]
    assert {m["path"] for m in members} == {"/mnt/pool/a", "/mnt/pool/b"}
    assert all(m["volume_id"] == vol for m in members)

    # The dashboard KPI: a single aggregate over the in-scope groups (count + reclaimable).
    summary = await api_client.get("/api/v1/duplicates/summary", headers=auth)
    assert summary.status_code == 200
    assert summary.json() == {"group_count": 1, "total_reclaimable_bytes": 100}
    # The literal 'summary' segment must not be parsed as a group id.
    assert summary.json()["group_count"] == 1


async def test_duplicates_keyset_pagination(api_client: httpx.AsyncClient) -> None:
    # Three distinct groups → page with limit=2 then follow the cursor for the last one.
    entries = []
    for i, h in enumerate((_HA, _HB, _HC)):
        entries.append(_entry("/mnt/pool", f"g{i}_x", 10 + i * 2, size=200 + i, full=h))
        entries.append(_entry("/mnt/pool", f"g{i}_y", 11 + i * 2, size=200 + i, full=h))
    await _ingest_fullbit(api_client, mountpoint="/mnt/pool", entries=entries)
    assert await _build_groups() == 3

    auth = await seed_principal()
    first = (await api_client.get("/api/v1/duplicates?limit=2", headers=auth)).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"] is not None
    second = (
        await api_client.get(
            f"/api/v1/duplicates?limit=2&cursor={first['next_cursor']}", headers=auth
        )
    ).json()
    assert len(second["items"]) == 1
    assert second["next_cursor"] is None
    seen = {g["id"] for g in first["items"]} | {g["id"] for g in second["items"]}
    assert len(seen) == 3  # no overlap, full coverage


async def test_duplicates_volume_filter(api_client: httpx.AsyncClient) -> None:
    v1 = await _ingest_fullbit(
        api_client,
        mountpoint="/mnt/a",
        entries=[
            _entry("/mnt/a", "x", 20, size=300, full=_HA),
            _entry("/mnt/a", "y", 21, size=300, full=_HA),
        ],
    )
    await _ingest_fullbit(
        api_client,
        mountpoint="/mnt/b",
        entries=[
            _entry("/mnt/b", "x", 22, size=400, full=_HB),
            _entry("/mnt/b", "y", 23, size=400, full=_HB),
        ],
    )
    await _build_groups()

    auth = await seed_principal()
    filtered = (await api_client.get(f"/api/v1/duplicates?volume_id={v1}", headers=auth)).json()
    assert len(filtered["items"]) == 1
    detail = await api_client.get(f"/api/v1/duplicates/{filtered['items'][0]['id']}", headers=auth)
    assert all(m["volume_id"] == v1 for m in detail.json()["members"])


async def test_duplicates_scope_excludes_out_of_scope(api_client: httpx.AsyncClient) -> None:
    # A cross-volume group: a viewer scoped to only v1 must see the group but NOT v2's member.
    v1 = await _ingest_fullbit(
        api_client, mountpoint="/mnt/a", entries=[_entry("/mnt/a", "shared", 30, size=10, full=_HA)]
    )
    v2 = await _ingest_fullbit(
        api_client, mountpoint="/mnt/b", entries=[_entry("/mnt/b", "shared", 31, size=10, full=_HA)]
    )
    await _build_groups()

    # Scope a viewer to v1 only.
    auth = await seed_principal(
        username="scoped", role=Role.VIEWER, scope_kind="volume", volume_id=v1
    )
    listing = (await api_client.get("/api/v1/duplicates", headers=auth)).json()
    assert len(listing["items"]) == 1  # the group is visible (has an in-scope member)
    detail = await api_client.get(f"/api/v1/duplicates/{listing['items'][0]['id']}", headers=auth)
    members = detail.json()["members"]
    # The out-of-scope v2 copy is excluded — its path is never leaked.
    assert {m["volume_id"] for m in members} == {v1}
    assert all(m["volume_id"] != v2 for m in members)


async def test_duplicates_fully_out_of_scope_hidden(api_client: httpx.AsyncClient) -> None:
    # A group entirely on v2: a viewer scoped to v1 sees it neither in the list nor by id (404).
    await _ingest_fullbit(
        api_client, mountpoint="/mnt/a", entries=[_entry("/mnt/a", "k", 40, size=10, full=_HC)]
    )
    v2 = await _ingest_fullbit(
        api_client,
        mountpoint="/mnt/b",
        entries=[
            _entry("/mnt/b", "x", 41, size=99, full=_HB),
            _entry("/mnt/b", "y", 42, size=99, full=_HB),
        ],
    )
    await _build_groups()
    # Find the v2-only group id as admin first.
    admin = await seed_principal()
    all_groups = (await api_client.get("/api/v1/duplicates", headers=admin)).json()["items"]
    v2_group = all_groups[0]["id"]

    # A viewer scoped to a different (non-existent-member) volume must not see it.
    scoped = await seed_principal(
        username="other", role=Role.VIEWER, scope_kind="volume", volume_id=v2 + 999
    )
    listing = (await api_client.get("/api/v1/duplicates", headers=scoped)).json()
    assert listing["items"] == []
    detail = await api_client.get(f"/api/v1/duplicates/{v2_group}", headers=scoped)
    assert detail.status_code == 404  # existence not leaked


async def test_duplicates_read_only_no_write_routes(api_client: httpx.AsyncClient) -> None:
    # The router exposes only GETs — POST/DELETE on the resource are not allowed (report-only).
    auth = await seed_principal()
    assert (await api_client.post("/api/v1/duplicates", headers=auth)).status_code == 405
    assert (await api_client.delete("/api/v1/duplicates/1", headers=auth)).status_code == 405
