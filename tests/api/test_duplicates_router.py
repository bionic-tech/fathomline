"""Duplicates router tests — list/detail, keyset pagination, scope filtering, read-only.

Covers the fullbit-dedup test_plan ``test_duplicates_api_keyset_and_scope``: the read API lists
groups, paginates by cursor, filters by volume/scope, returns read-only payloads, and excludes
out-of-scope members. Groups are produced through the real ingest → DedupService path so the
test exercises the whole report pipeline.
"""

from __future__ import annotations

import httpx

from fathom.auth.models import User
from fathom.auth.passwords import hash_password
from fathom.auth.principal import Role
from fathom.auth.sessions import create_session
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


async def test_duplicates_detail_aggregate_recomputed_over_visible_members(
    api_client: httpx.AsyncClient,
) -> None:
    """EC-dedup-5b: /duplicates/{id} reports member_count/reclaimable over VISIBLE members only.

    A cross-volume group with two copies on v1 and one on v2 has a whole-group member_count of 3
    and reclaimable = size*(3-1). A viewer scoped to v1 sees two members, so the detail must report
    member_count=2 and reclaimable=size*(2-1) — never a count of copies it cannot see — and a
    suggested keeper, if surfaced, must be one of the visible members.
    """
    v1 = await _ingest_fullbit(
        api_client,
        mountpoint="/mnt/a",
        entries=[
            _entry("/mnt/a", "a", 50, size=100, full=_HA),
            _entry("/mnt/a", "b", 51, size=100, full=_HA),
        ],
    )
    await _ingest_fullbit(
        api_client, mountpoint="/mnt/b", entries=[_entry("/mnt/b", "c", 52, size=100, full=_HA)]
    )
    await _build_groups()

    # Admin sees the whole group: 3 members, reclaimable = 100*(3-1) = 200.
    admin = await seed_principal()
    gid = (await api_client.get("/api/v1/duplicates", headers=admin)).json()["items"][0]["id"]
    full = (await api_client.get(f"/api/v1/duplicates/{gid}", headers=admin)).json()
    assert full["member_count"] == 3
    assert full["reclaimable_bytes"] == 200

    # A viewer scoped to v1 sees only its two copies: member_count=2, reclaimable = 100*(2-1) = 100.
    scoped = await seed_principal(
        username="v1only", role=Role.VIEWER, scope_kind="volume", volume_id=v1
    )
    detail = (await api_client.get(f"/api/v1/duplicates/{gid}", headers=scoped)).json()
    assert detail["member_count"] == 2
    assert detail["reclaimable_bytes"] == 100
    visible_ids = {m["entry_id"] for m in detail["members"]}
    assert len(visible_ids) == 2
    keeper = detail["suggested_keeper_entry_id"]
    assert keeper is None or keeper in visible_ids  # never point at an unseeable copy


async def test_duplicates_read_only_no_write_routes(api_client: httpx.AsyncClient) -> None:
    # The router exposes only GETs — POST/DELETE on the resource are not allowed (report-only).
    auth = await seed_principal()
    assert (await api_client.post("/api/v1/duplicates", headers=auth)).status_code == 405
    assert (await api_client.delete("/api/v1/duplicates/1", headers=auth)).status_code == 405


async def _seed_grantless_principal(username: str = "no-dedup") -> dict[str, str]:
    """A user with a valid session but NO role assignment → no capabilities at all.

    Every human role confers VIEW_DEDUP (see the RBAC matrix / principal.py), so the only principal
    that can LACK it holds no grant at all — the deny-by-default case where ``require(VIEW_DEDUP)``
    rejects with 403 ('insufficient capability') before any query runs.
    """
    async with db.session_scope() as session:
        user = User(
            subject=username,
            source="local",
            display_name=username,
            password_hash=hash_password("correct horse battery staple"),
            is_active=True,
        )
        session.add(user)
        await session.flush()
        _row, raw = await create_session(session, user_id=user.id, ttl_seconds=3600)
    return {"Authorization": f"Bearer {raw}"}


async def test_duplicates_require_view_dedup_403(api_client: httpx.AsyncClient) -> None:
    # EC-dedup-7: a principal lacking VIEW_DEDUP is denied EVERY duplicates route (deny-by-default),
    # whether listing, summary, the provider scan, or a single group by id.
    auth = await _seed_grantless_principal()
    for path in (
        "/api/v1/duplicates",
        "/api/v1/duplicates/summary",
        "/api/v1/duplicates/provider",
        "/api/v1/duplicates/1",
    ):
        resp = await api_client.get(path, headers=auth)
        assert resp.status_code == 403, f"{path} -> {resp.status_code}: {resp.text}"


async def test_duplicates_list_param_bounds_422(api_client: httpx.AsyncClient) -> None:
    # EC-dedup-9: the keyset/list query params are bounded — out-of-range values are 422, not
    # silently clamped. Authenticated as admin so it is the param bound, not auth, that rejects.
    auth = await seed_principal()
    assert (await api_client.get("/api/v1/duplicates?limit=0", headers=auth)).status_code == 422
    assert (await api_client.get("/api/v1/duplicates?limit=201", headers=auth)).status_code == 422
    assert (await api_client.get("/api/v1/duplicates?cursor=-1", headers=auth)).status_code == 422
    assert (await api_client.get("/api/v1/duplicates?volume_id=0", headers=auth)).status_code == 422


async def test_duplicates_detail_non_int_id_422(api_client: httpx.AsyncClient) -> None:
    # EC-dedup-9: a non-integer group id is a path-validation error (422), not a 404 — 'abc' falls
    # through to /duplicates/{group_id} (the literal summary/provider segments are matched first).
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/duplicates/abc", headers=auth)
    assert resp.status_code == 422
