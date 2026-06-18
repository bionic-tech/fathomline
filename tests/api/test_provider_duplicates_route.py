"""GET /api/v1/duplicates/provider — cross-cloud provider-hash dups, scope-gated (ADR-028 2b)."""

from __future__ import annotations

import httpx

from tests.api.conftest import FINGERPRINT_HEADER, _entry, batch, seed_principal


def _cloud_entry(rel: str, inode: int, *, size: int, phash: str) -> dict:
    return {
        **_entry("/mnt/pool", rel, inode, size=size),
        "provider_hash": phash,
        "provider_hash_algo": "md5",
    }


async def _ingest_cloud_dups(client: httpx.AsyncClient) -> None:
    # Two files the provider reports identical (same md5 + size) → one duplicate group.
    entries = [
        _entry("/mnt/pool", "", 1, is_dir=True),
        _cloud_entry("a.bin", 2, size=100, phash="a" * 32),
        _cloud_entry("b.bin", 3, size=100, phash="a" * 32),
        _cloud_entry("lonely.bin", 4, size=50, phash="b" * 32),  # singleton, not a group
    ]
    resp = await client.post(
        "/api/v1/agents/ingest", json=batch(entries=entries), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200


async def test_provider_duplicates_lists_cross_cloud_groups(api_client: httpx.AsyncClient) -> None:
    await _ingest_cloud_dups(api_client)
    auth = await seed_principal()  # ADMIN → VIEW_DEDUP + global scope
    resp = await api_client.get("/api/v1/duplicates/provider", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert body["truncated"] is False
    assert len(body["items"]) == 1
    group = body["items"][0]
    assert group["algo"] == "md5" and group["provider_hash"] == "a" * 32
    assert group["member_count"] == 2 and group["reclaimable_bytes"] == 100
    assert {m["path"] for m in group["members"]} == {"/mnt/pool/a.bin", "/mnt/pool/b.bin"}


async def test_provider_duplicates_scope_isolation(api_client: httpx.AsyncClient) -> None:
    # A principal scoped to a different volume sees no groups — the RBAC predicate is pushed into
    # the scan (fail-closed), so an out-of-scope member can never surface (ADD 13 §4).
    await _ingest_cloud_dups(api_client)
    auth = await seed_principal(username="scoped", scope_kind="volume", volume_id=9999)
    resp = await api_client.get("/api/v1/duplicates/provider", headers=auth)
    assert resp.status_code == 200
    assert resp.json()["items"] == []


async def test_provider_duplicates_truncation(api_client: httpx.AsyncClient) -> None:
    entries = [_entry("/mnt/pool", "", 1, is_dir=True)]
    # Two distinct groups (different hashes), each a pair.
    for i, h in enumerate(("c", "d")):
        entries.append(_cloud_entry(f"{h}1.bin", 10 + i * 2, size=100 + i, phash=h * 32))
        entries.append(_cloud_entry(f"{h}2.bin", 11 + i * 2, size=100 + i, phash=h * 32))
    resp = await api_client.post(
        "/api/v1/agents/ingest", json=batch(entries=entries), headers=FINGERPRINT_HEADER
    )
    assert resp.status_code == 200
    auth = await seed_principal()
    resp = await api_client.get("/api/v1/duplicates/provider?limit=1", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 1 and body["truncated"] is True  # capped + honest truncation flag
