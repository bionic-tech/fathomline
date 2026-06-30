"""/changes churn-feed read route (read.py; ADD 09 §4) — auth/scope/404 + subtree LIKE + window.

Gated by VIEW_METADATA + scope; reads the append-only change_log. These tests seed change_log
rows directly (no ingest churn) so the subtree-prefix LIKE filter (with wildcard neutralisation,
AR-0015) and the since/until time window are asserted exactly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from fathom.auth.scope import ScopeFilter
from fathom.core import db
from fathom.core.concierge.queries import hot_folders
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


async def _seed_volume(
    rows: list[tuple[str, str, datetime]], *, mountpoint: str = "/mnt/pool"
) -> int:
    """Create a host + volume and the given (path, change_type, ts) change rows; return vol id."""
    from fathom.core.catalogue.models import ChangeLog, Host, Volume

    async with db.session_scope() as session:
        host = Host(name="nas-1", cert_fingerprint="ab:cd")
        session.add(host)
        await session.flush()
        volume = Volume(
            host_id=host.id, mountpoint=mountpoint, fs_type="zfs", device="tank", transport="sata"
        )
        session.add(volume)
        await session.flush()
        for path, change_type, ts in rows:
            session.add(ChangeLog(volume_id=volume.id, path=path, change_type=change_type, ts=ts))
        await session.flush()
        return volume.id


async def test_changes_requires_auth(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume([("/mnt/pool/a", "create", _NOW)])
    resp = await api_client.get("/api/v1/changes", params={"volume_id": vol})
    assert resp.status_code == 401  # deny-by-default — VIEW_METADATA required


async def test_changes_unknown_volume_404(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/changes", params={"volume_id": 999}, headers=auth)
    assert resp.status_code == 404  # absent volume → 404 (scope-checked before any row is read)


async def test_changes_out_of_scope_403(api_client: httpx.AsyncClient) -> None:
    # An existing volume the principal can't see → 403 (not a silently-empty feed).
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = resp.json()["volume_id"]
    scoped = await seed_principal(username="hostuser", scope_kind="host", host_id=9999)
    out = await api_client.get("/api/v1/changes", params={"volume_id": vol}, headers=scoped)
    assert out.status_code == 403


async def test_changes_feed_newest_first(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(
        [
            ("/mnt/pool/old.txt", "create", _NOW - timedelta(hours=2)),
            ("/mnt/pool/new.txt", "modify", _NOW),
        ]
    )
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/changes", params={"volume_id": vol}, headers=auth)
    assert resp.status_code == 200, resp.text
    paths = [r["path"] for r in resp.json()]
    assert paths == ["/mnt/pool/new.txt", "/mnt/pool/old.txt"]  # ts desc


async def test_changes_subtree_path_filter(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(
        [
            ("/mnt/pool/movies", "create", _NOW),  # the subtree root itself
            ("/mnt/pool/movies/a.mkv", "create", _NOW),  # under the subtree
            ("/mnt/pool/docs/note.txt", "create", _NOW),  # a sibling → excluded
        ]
    )
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/changes", params={"volume_id": vol, "path": "/mnt/pool/movies"}, headers=auth
    )
    paths = {r["path"] for r in resp.json()}
    assert paths == {"/mnt/pool/movies", "/mnt/pool/movies/a.mkv"}
    assert "/mnt/pool/docs/note.txt" not in paths


async def test_changes_subtree_filter_escapes_wildcards(api_client: httpx.AsyncClient) -> None:
    # AR-0015: a literal '_' in the prefix must NOT act as a single-char LIKE wildcard, so a
    # sibling 'axb' is never matched by a query for 'a_b'.
    vol = await _seed_volume(
        [
            ("/mnt/pool/a_b/real.txt", "create", _NOW),
            ("/mnt/pool/axb/decoy.txt", "create", _NOW),
        ]
    )
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/changes", params={"volume_id": vol, "path": "/mnt/pool/a_b"}, headers=auth
    )
    paths = {r["path"] for r in resp.json()}
    assert paths == {"/mnt/pool/a_b/real.txt"}  # axb decoy excluded — '_' matched literally


async def test_changes_time_window(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(
        [
            ("/mnt/pool/early.txt", "create", _NOW - timedelta(hours=10)),
            ("/mnt/pool/late.txt", "create", _NOW - timedelta(hours=1)),
        ]
    )
    auth = await seed_principal()
    mid = (_NOW - timedelta(hours=5)).isoformat()
    # since=mid → only the late row.
    since_resp = await api_client.get(
        "/api/v1/changes", params={"volume_id": vol, "since": mid}, headers=auth
    )
    assert {r["path"] for r in since_resp.json()} == {"/mnt/pool/late.txt"}
    # until=mid → only the early row.
    until_resp = await api_client.get(
        "/api/v1/changes", params={"volume_id": vol, "until": mid}, headers=auth
    )
    assert {r["path"] for r in until_resp.json()} == {"/mnt/pool/early.txt"}


async def test_changes_limit_bounds(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume([("/mnt/pool/a", "create", _NOW)])
    auth = await seed_principal()
    # limit must be 1..1000 — 0 and 1001 are rejected by the query validator (422).
    too_small = await api_client.get(
        "/api/v1/changes", params={"volume_id": vol, "limit": 0}, headers=auth
    )
    too_big = await api_client.get(
        "/api/v1/changes", params={"volume_id": vol, "limit": 1001}, headers=auth
    )
    assert too_small.status_code == 422
    assert too_big.status_code == 422


# --- hot_folders: the "which folders changed most" roll-up over the same churn feed ----------
# Lives here (not the route tests) because it reads the change_log the /changes feed exposes.


async def test_hot_folders_empty_window_returns_empty(api_client: httpx.AsyncClient) -> None:
    # EC-changes-17: all churn predates the requested window (since is later than every row) →
    # an empty ranking, not an error.
    await _seed_volume([("/mnt/pool/media/a.mkv", "modify", _NOW)])
    async with db.session_scope() as session:
        folders = await hot_folders(session, since=_NOW + timedelta(hours=1))
    assert folders == []


async def test_hot_folders_scope_filtered(api_client: httpx.AsyncClient) -> None:
    # EC-changes-17: the ranking is scope-filtered — an out-of-scope principal sees no hot
    # folders, while a global principal sees the churned (parent_depth=1) folder.
    await _seed_volume([("/mnt/pool/media/a.mkv", "modify", _NOW)])
    since = _NOW - timedelta(days=1)
    async with db.session_scope() as session:
        out_of_scope = await hot_folders(
            session, since=since, scope=ScopeFilter(is_global=False, host_ids=frozenset({9999}))
        )
        in_scope = await hot_folders(session, since=since, scope=ScopeFilter(is_global=True))
    assert out_of_scope == []
    assert [f.path for f in in_scope] == ["/mnt/pool/media"]
