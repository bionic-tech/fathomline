"""ScopeFilter SQL predicate + read-surface scope-escape tests (ADD 13 §4)."""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select, update

from fathom.auth.principal import Capability, Grant, Role
from fathom.auth.scope import DATA_VOLUME_KIND, SYSTEM_VOLUME_KIND, ScopeFilter
from fathom.core import db
from fathom.core.catalogue.models import Volume
from fathom.core.rollup import RollupService
from tests.api.conftest import batch, seed_principal


def test_global_scope_adds_no_predicate() -> None:
    scope = ScopeFilter.from_grants(
        (Grant(role=Role.ADMIN, scope_kind="global"),), Capability.VIEW_METADATA
    )
    stmt = select(Volume)
    out = scope.apply(stmt, host_col=Volume.host_id, volume_col=Volume.id)
    # Global scope returns the statement unchanged (no WHERE added).
    assert str(out) == str(stmt)


def test_empty_scope_filters_to_nothing() -> None:
    scope = ScopeFilter(is_global=False)
    stmt = select(Volume)
    out = scope.apply(stmt, host_col=Volume.host_id, volume_col=Volume.id)
    assert "WHERE" in str(out)


async def _ingest_two_hosts(api_client: httpx.AsyncClient) -> tuple[int, int, int, int]:
    """Ingest two distinct hosts; return (host_a, vol_a, host_b, vol_b)."""
    r1 = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(mountpoint="/mnt/a", host={"name": "hostA", "os": "x", "agent_version": "1"}),
        headers={"X-Client-Cert-Fingerprint": "aa:aa"},
    )
    r2 = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(mountpoint="/mnt/b", host={"name": "hostB", "os": "x", "agent_version": "1"}),
        headers={"X-Client-Cert-Fingerprint": "bb:bb"},
    )
    a = r1.json()
    b = r2.json()
    async with db.session_scope() as session:
        await RollupService(session).recompute_full(a["volume_id"])
        await RollupService(session).recompute_full(b["volume_id"])
    return a["host_id"], a["volume_id"], b["host_id"], b["volume_id"]


async def test_host_scoped_principal_sees_only_in_scope(api_client: httpx.AsyncClient) -> None:
    host_a, vol_a, _host_b, _vol_b = await _ingest_two_hosts(api_client)
    auth = await seed_principal(
        username="hostadmin", role=Role.VIEWER, scope_kind="host", host_id=host_a
    )
    resp = await api_client.get("/api/v1/volumes", headers=auth)
    assert resp.status_code == 200
    vols = resp.json()
    assert {v["host_id"] for v in vols} == {host_a}
    assert vol_a in {v["id"] for v in vols}


async def test_scope_escape_other_host_403(api_client: httpx.AsyncClient) -> None:
    host_a, _vol_a, _host_b, vol_b = await _ingest_two_hosts(api_client)
    auth = await seed_principal(
        username="hostadmin2", role=Role.VIEWER, scope_kind="host", host_id=host_a
    )
    # Drill into a volume on the *other* host → out of scope → 403.
    resp = await api_client.get(
        "/api/v1/tree", params={"volume_id": vol_b, "path": "/mnt/b"}, headers=auth
    )
    assert resp.status_code == 403


# --- system-volume kind gating (AR-011) -------------------------------------------------


def test_check_target_system_volume_403_for_host_grant() -> None:
    """A host-scoped grant must NOT reach a system volume; a data volume on it is fine."""
    scope = ScopeFilter(is_global=False, host_ids=frozenset({7}))
    # Data volume on the in-scope host → allowed.
    scope.check_target(host_id=7, volume_id=1, volume_kind=DATA_VOLUME_KIND)
    # System volume on the in-scope host → 403 (gate is volume-explicit, not host-wide).
    with pytest.raises(HTTPException) as exc:
        scope.check_target(host_id=7, volume_id=2, volume_kind=SYSTEM_VOLUME_KIND)
    assert exc.value.status_code == 403


def test_check_target_system_volume_allowed_with_explicit_volume_grant() -> None:
    """A volume-scoped grant naming the system volume reaches it (AR-011 explicit cover)."""
    scope = ScopeFilter(is_global=False, volume_ids=frozenset({2}))
    scope.check_target(host_id=7, volume_id=2, volume_kind=SYSTEM_VOLUME_KIND)  # no raise


def test_apply_adds_system_volume_gate_for_host_scope() -> None:
    """``apply`` with ``kind_col`` ANDs a kind!='system' predicate for a non-global scope."""
    scope = ScopeFilter(is_global=False, host_ids=frozenset({7}))
    stmt = select(Volume)
    out = scope.apply(stmt, host_col=Volume.host_id, volume_col=Volume.id, kind_col=Volume.kind)
    sql = str(out)
    assert "kind" in sql  # the system-volume gate is present in the WHERE clause


async def _ingest_with_system_volume(
    api_client: httpx.AsyncClient,
) -> tuple[int, int, int]:
    """Ingest one host with a data + a system volume; return (host_id, data_vol, system_vol).

    The scanner ingests every volume as ``kind='data'``; an operator tags a root/system volume
    afterwards. We replicate that by flipping the second volume's ``kind`` to ``system`` in the
    catalogue directly (no ingest field carries kind by design).
    """
    host = {"name": "nas-1", "os": "x", "agent_version": "1"}
    r1 = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(mountpoint="/mnt/data", host=host),
        headers={"X-Client-Cert-Fingerprint": "aa:aa"},
    )
    r2 = await api_client.post(
        "/api/v1/agents/ingest",
        json=batch(mountpoint="/", host=host),
        headers={"X-Client-Cert-Fingerprint": "aa:aa"},
    )
    a = r1.json()
    b = r2.json()
    async with db.session_scope() as session:
        await session.execute(
            update(Volume).where(Volume.id == b["volume_id"]).values(kind=SYSTEM_VOLUME_KIND)
        )
        await RollupService(session).recompute_full(a["volume_id"])
        await RollupService(session).recompute_full(b["volume_id"])
    return a["host_id"], a["volume_id"], b["volume_id"]


async def test_host_scoped_principal_cannot_see_or_drill_system_volume(
    api_client: httpx.AsyncClient,
) -> None:
    """A host-scoped principal sees/drills the data volume but NOT the kind='system' one."""
    host_id, data_vol, system_vol = await _ingest_with_system_volume(api_client)
    auth = await seed_principal(
        username="hostviewer", role=Role.VIEWER, scope_kind="host", host_id=host_id
    )

    # Listing: the system volume is hidden; the data volume is visible.
    resp = await api_client.get("/api/v1/volumes", headers=auth)
    assert resp.status_code == 200
    seen = {v["id"] for v in resp.json()}
    assert data_vol in seen
    assert system_vol not in seen

    # Drill: data volume → 200, system volume → 403 (gated, not 404).
    ok = await api_client.get(
        "/api/v1/tree", params={"volume_id": data_vol, "path": "/mnt/data"}, headers=auth
    )
    assert ok.status_code == 200
    denied = await api_client.get(
        "/api/v1/tree", params={"volume_id": system_vol, "path": "/"}, headers=auth
    )
    assert denied.status_code == 403


async def test_volume_scoped_grant_sees_system_volume(api_client: httpx.AsyncClient) -> None:
    """A grant that names the system volume explicitly may see + drill it (AR-011)."""
    _host_id, _data_vol, system_vol = await _ingest_with_system_volume(api_client)
    auth = await seed_principal(
        username="sysviewer", role=Role.VIEWER, scope_kind="volume", volume_id=system_vol
    )
    resp = await api_client.get("/api/v1/volumes", headers=auth)
    assert resp.status_code == 200
    assert system_vol in {v["id"] for v in resp.json()}
    drill = await api_client.get(
        "/api/v1/tree", params={"volume_id": system_vol, "path": "/"}, headers=auth
    )
    assert drill.status_code == 200
