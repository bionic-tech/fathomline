"""Scan-creation router tests — full-bit opt-in, ack persistence, RBAC + scope (fullbit-dedup).

The full-bit scan request is gated by ``TRIGGER_FULLBIT_SCAN`` (operator+), scope-checked against
the target volume, and records the operator's impact ack on a snapshot. It performs no write — it
only persists intent + acknowledgement (ADD 02 non-impact contract).
"""

from __future__ import annotations

import httpx
from sqlalchemy import select

from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.catalogue.models import Snapshot, Volume
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal

_ACK = "target is on a USB RAID5 array; full-bit will be slow and I/O-intensive"


async def _seed_volume(api_client: httpx.AsyncClient) -> int:
    resp = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    return resp.json()["volume_id"]


async def test_create_fullbit_requires_auth(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}
    )
    assert resp.status_code == 401


async def test_create_fullbit_records_ack(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=auth
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["mode"] == "fullbit"
    async with db.session_scope() as session:
        snap = await session.get(Snapshot, body["snapshot_id"])
        assert snap is not None
        assert snap.mode == "fullbit"
        assert snap.warning_ack is not None
        assert snap.warning_ack["impact_ack"] == _ACK
        assert snap.warning_ack["mode"] == "fullbit"


async def test_create_fullbit_rejects_blank_ack(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": "ok"}, headers=auth
    )
    assert resp.status_code == 422  # too short to name a device class


async def test_create_fullbit_scope_path_sets_target(api_client: httpx.AsyncClient) -> None:
    # UC-scans-4: when a sub-tree scope_path is given, the persisted ack target is that PATH, not
    # the whole-volume mountpoint — the audit trail records exactly what was acked for full-bit.
    vol = await _seed_volume(api_client)
    auth = await seed_principal(role=Role.OPERATOR)
    scope_path = "/mnt/pool/movies"
    resp = await api_client.post(
        "/api/v1/scans/fullbit",
        json={"volume_id": vol, "impact_ack": _ACK, "scope_path": scope_path},
        headers=auth,
    )
    assert resp.status_code == 201, resp.text
    async with db.session_scope() as session:
        snap = await session.get(Snapshot, resp.json()["snapshot_id"])
        assert snap is not None
        assert snap.warning_ack["target"] == scope_path
        volume = await session.get(Volume, vol)
        assert volume is not None
        assert snap.warning_ack["target"] != volume.mountpoint  # the sub-tree, not the mount


async def test_create_fullbit_whitespace_ack_rejected(api_client: httpx.AsyncClient) -> None:
    # EC-scans-16: an all-whitespace ack passes the schema's min_length=1 but the router strip()s it
    # before the non-impact-contract length gate, so 8 spaces (strip → "") is refused (422).
    vol = await _seed_volume(api_client)
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": " " * 8}, headers=auth
    )
    assert resp.status_code == 422


async def test_create_fullbit_viewer_denied(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)
    auth = await seed_principal(role=Role.VIEWER)  # viewer cannot trigger full-bit
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=auth
    )
    assert resp.status_code == 403


async def test_create_fullbit_out_of_scope_denied(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)
    # Operator scoped to a different volume → out-of-scope target → 403.
    auth = await seed_principal(role=Role.OPERATOR, scope_kind="volume", volume_id=vol + 999)
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=auth
    )
    assert resp.status_code == 403


async def test_create_fullbit_system_volume_denied_for_host_scope(
    api_client: httpx.AsyncClient,
) -> None:
    # AR-011: a host-scoped grant must NOT confer access to a SYSTEM volume. The full-bit trigger
    # previously omitted volume_kind from the scope check, so a host-scoped operator could trigger a
    # full-bit scan of a system volume — this asserts the system-volume gate now applies here.
    vol = await _seed_volume(api_client)
    async with db.session_scope() as session:
        v = await session.get(Volume, vol)
        assert v is not None
        v.kind = "system"
        host_id = v.host_id
    auth = await seed_principal(role=Role.OPERATOR, scope_kind="host", host_id=host_id)
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=auth
    )
    assert resp.status_code == 403


async def test_create_fullbit_unknown_volume(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal(role=Role.OPERATOR)
    resp = await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": 99999, "impact_ack": _ACK}, headers=auth
    )
    assert resp.status_code == 404


async def test_no_snapshot_written_for_denied_request(api_client: httpx.AsyncClient) -> None:
    # A denied (viewer) request must not persist a snapshot (fail-closed, no side effects).
    vol = await _seed_volume(api_client)
    auth = await seed_principal(role=Role.VIEWER)
    await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=auth
    )
    async with db.session_scope() as session:
        fullbit_snaps = (
            (await session.execute(select(Snapshot).where(Snapshot.mode == "fullbit")))
            .scalars()
            .all()
        )
    assert fullbit_snaps == []


# --- GET /scans (read-only scan history; VIEW_METADATA-gated, scope-filtered) ---------------


async def test_list_scans_requires_auth(api_client: httpx.AsyncClient) -> None:
    await _seed_volume(api_client)
    resp = await api_client.get("/api/v1/scans")
    assert resp.status_code == 401


async def test_list_scans_returns_history_newest_first(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)  # the ingest itself records one 'metadata' snapshot
    operator = await seed_principal(role=Role.OPERATOR)
    # Two full-bit requests → two more snapshot rows on the volume (3 total).
    for _ in range(2):
        await api_client.post(
            "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=operator
        )
    viewer = await seed_principal(username="v", role=Role.VIEWER)
    resp = await api_client.get("/api/v1/scans", headers=viewer)
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert len(rows) == 3  # one metadata (ingest) + two full-bit
    # Newest first (strictly descending id) and the expected wire shape.
    assert [r["id"] for r in rows] == sorted((r["id"] for r in rows), reverse=True)
    assert rows[0]["mode"] == "fullbit"
    assert rows[0]["volume_id"] == vol
    assert rows[0]["warning_ack"]["impact_ack"] == _ACK
    # The oldest row is the ingest's metadata scan.
    assert rows[-1]["mode"] == "metadata"


async def test_list_scans_volume_filter(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)
    operator = await seed_principal(role=Role.OPERATOR)
    await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=operator
    )
    viewer = await seed_principal(username="v", role=Role.VIEWER)
    # A different (non-existent) volume id → 404, not a silent empty list.
    resp = await api_client.get("/api/v1/scans", params={"volume_id": vol + 999}, headers=viewer)
    assert resp.status_code == 404
    resp_ok = await api_client.get("/api/v1/scans", params={"volume_id": vol}, headers=viewer)
    assert resp_ok.status_code == 200
    # Both the metadata (ingest) and the full-bit snapshot are on this volume.
    assert len(resp_ok.json()) == 2


async def test_list_scans_out_of_scope_hidden(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume(api_client)
    operator = await seed_principal(role=Role.OPERATOR)
    await api_client.post(
        "/api/v1/scans/fullbit", json={"volume_id": vol, "impact_ack": _ACK}, headers=operator
    )
    # A viewer scoped to a different volume sees no snapshots (server-authoritative scope).
    scoped = await seed_principal(
        username="scoped", role=Role.VIEWER, scope_kind="volume", volume_id=vol + 999
    )
    resp = await api_client.get("/api/v1/scans", headers=scoped)
    assert resp.status_code == 200
    assert resp.json() == []
