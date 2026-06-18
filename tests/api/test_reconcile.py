"""Cross-host reconciliation tests (ADR-024): path-aligned divergence classification.

Seeds two volumes (a "definitive" host and a "comparison" host) holding the same relative tree with
deliberately varied files — byte-identical, identical-content-but-mtime-drifted, content-diverged,
size-diverged, present-on-only-one-side, and same-size-but-unhashed — and asserts each lands in the
right class. The service is read-only; nothing is moved. Also covers the route's scope + root-anchor
gates.
"""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.catalogue.models import FsEntryRow, Host, Volume
from fathom.core.reconcile.service import (
    CONTENT_SAME_META_DIFF,
    DIVERGED,
    IDENTICAL,
    MISSING_ON_COMPARISON,
    MISSING_ON_DEFINITIVE,
    SIZE_MATCH_UNHASHED,
    ReconcileService,
)
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal


@pytest.fixture
async def api_client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'cat.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


_INODE = itertools.count(1000)


def _entry(
    vol: Volume, host: Host, rel: str, *, size: int, mtime: float, h: str | None
) -> FsEntryRow:
    return FsEntryRow(
        host_id=host.id,
        volume_id=vol.id,
        name=rel.rsplit("/", 1)[-1],
        path=f"{vol.mountpoint}/{rel}",
        size_logical=size,
        mtime=mtime,
        inode=next(_INODE),
        full_hash=h,
        present=True,
        is_dir=False,
    )


async def _seed_two_trees() -> tuple[int, str, int, str]:
    """Two volumes (/defroot, /cmproot), one file per class. Returns (def_vol, def_root, cmp...)."""
    async with db.session_scope() as session:
        host = Host(name="h", cert_fingerprint="ab:cd")
        session.add(host)
        await session.flush()
        dvol = Volume(
            host_id=host.id, mountpoint="/defroot", fs_type="zfs", device="d", transport="sata"
        )
        cvol = Volume(
            host_id=host.id, mountpoint="/cmproot", fs_type="ext4", device="c", transport="sata"
        )
        session.add_all([dvol, cvol])
        await session.flush()
        rows = [
            # identical: same size, hash, mtime
            _entry(dvol, host, "a/same.bin", size=100, mtime=1000.0, h="hashA"),
            _entry(cvol, host, "a/same.bin", size=100, mtime=1000.0, h="hashA"),
            # content_same_meta_diff: same hash, different mtime (dates got mangled on copy)
            _entry(dvol, host, "a/dates.txt", size=50, mtime=1000.0, h="hashB"),
            _entry(cvol, host, "a/dates.txt", size=50, mtime=2222.0, h="hashB"),
            # diverged: same size, DIFFERENT hash (content actually differs)
            _entry(dvol, host, "b/edited.doc", size=200, mtime=1000.0, h="hashC1"),
            _entry(cvol, host, "b/edited.doc", size=200, mtime=1000.0, h="hashC2"),
            # diverged by size (one side unhashed but sizes differ → still diverged)
            _entry(dvol, host, "b/grew.log", size=300, mtime=1000.0, h=None),
            _entry(cvol, host, "b/grew.log", size=400, mtime=1000.0, h=None),
            # size_match_unhashed: same size, no hashes → cannot confirm content
            _entry(dvol, host, "c/maybe.dat", size=500, mtime=1000.0, h=None),
            _entry(cvol, host, "c/maybe.dat", size=500, mtime=1000.0, h=None),
            # missing on comparison (only on definitive)
            _entry(dvol, host, "only-def.txt", size=10, mtime=1000.0, h="hashD"),
            # missing on definitive (only on comparison)
            _entry(cvol, host, "only-cmp.txt", size=20, mtime=1000.0, h="hashE"),
        ]
        session.add_all(rows)
        await session.flush()
        return dvol.id, "/defroot", cvol.id, "/cmproot"


async def test_reconcile_classifies_every_case(api_client: httpx.AsyncClient) -> None:
    # api_client builds the schema; the comparison runs directly against the service.
    dvol, droot, cvol, croot = await _seed_two_trees()
    async with db.session_scope() as session:
        result = await ReconcileService(session).compare(
            definitive_volume_id=dvol,
            definitive_root=droot,
            comparison_volume_id=cvol,
            comparison_root=croot,
        )
    c = result.counts
    assert c[IDENTICAL] == 1
    assert c[CONTENT_SAME_META_DIFF] == 1  # same bytes, drifted timestamp
    assert c[DIVERGED] == 2  # the edited.doc (hash) + grew.log (size)
    assert c[SIZE_MATCH_UNHASHED] == 1  # maybe.dat
    assert c[MISSING_ON_COMPARISON] == 1  # only-def.txt
    assert c[MISSING_ON_DEFINITIVE] == 1  # only-cmp.txt
    assert result.considered == 7  # 5 matched relpaths + 2 one-sided

    # The flagged items (diverged/unhashed/missing) are surfaced; identical/meta-diff are not noise.
    flagged = {it.relpath: it.classification for it in result.items}
    assert flagged["b/edited.doc"] == DIVERGED
    assert flagged["b/grew.log"] == DIVERGED
    assert flagged["c/maybe.dat"] == SIZE_MATCH_UNHASHED
    assert flagged["only-def.txt"] == MISSING_ON_COMPARISON
    assert flagged["only-cmp.txt"] == MISSING_ON_DEFINITIVE
    assert "a/same.bin" not in flagged  # identical is not in the actionable sample


async def test_reconcile_route_requires_auth(api_client: httpx.AsyncClient) -> None:
    dvol, droot, cvol, croot = await _seed_two_trees()
    body = {
        "definitive_volume_id": dvol,
        "definitive_path": droot,
        "comparison_volume_id": cvol,
        "comparison_path": croot,
    }
    resp = await api_client.post("/api/v1/reconcile", json=body)
    assert resp.status_code == 401  # deny-by-default


async def test_reconcile_route_happy_path(api_client: httpx.AsyncClient) -> None:
    dvol, droot, cvol, croot = await _seed_two_trees()
    auth = await seed_principal(username="rec")
    resp = await api_client.post(
        "/api/v1/reconcile",
        json={
            "definitive_volume_id": dvol,
            "definitive_path": droot,
            "comparison_volume_id": cvol,
            "comparison_path": croot,
        },
        headers=auth,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["counts"][DIVERGED] == 2
    assert body["counts"][IDENTICAL] == 1
    assert body["definitive_root"] == "/defroot"


async def test_reconcile_route_rejects_root_outside_volume(api_client: httpx.AsyncClient) -> None:
    dvol, droot, cvol, _ = await _seed_two_trees()
    auth = await seed_principal(username="rec2")
    resp = await api_client.post(
        "/api/v1/reconcile",
        json={
            "definitive_volume_id": dvol,
            "definitive_path": droot,
            "comparison_volume_id": cvol,
            "comparison_path": "/etc",  # not within /cmproot
        },
        headers=auth,
    )
    assert resp.status_code == 422


async def test_reconcile_out_of_scope_volume_403(api_client: httpx.AsyncClient) -> None:
    dvol, droot, cvol, croot = await _seed_two_trees()
    scoped = await seed_principal(
        username="rec-scoped",
        scope_kind="volume",
        volume_id=dvol,  # in scope for def, NOT for cmp
    )
    resp = await api_client.post(
        "/api/v1/reconcile",
        json={
            "definitive_volume_id": dvol,
            "definitive_path": droot,
            "comparison_volume_id": cvol,
            "comparison_path": croot,
        },
        headers=scoped,
    )
    assert resp.status_code == 403  # comparison volume out of scope
