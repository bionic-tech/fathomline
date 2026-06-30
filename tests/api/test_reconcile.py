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
    MAX_ITEMS,
    MISSING_ON_COMPARISON,
    MISSING_ON_DEFINITIVE,
    SIZE_MATCH_UNHASHED,
    ReconcileService,
    ReconcileTimeoutError,
    ReconcileTooLargeError,
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


async def test_reconcile_refuses_an_oversized_side(api_client: httpx.AsyncClient) -> None:
    # A whole-pool comparison would join millions x millions on an un-indexed relpath and hang. With
    # a low cap, the definitive side (>cap files) is refused up front — no heavy query runs.
    dvol, droot, cvol, croot = await _seed_two_trees()
    async with db.session_scope() as session:
        with pytest.raises(ReconcileTooLargeError) as ei:
            await ReconcileService(session).compare(
                definitive_volume_id=dvol,
                definitive_root=droot,
                comparison_volume_id=cvol,
                comparison_root=croot,
                max_side_entries=2,  # the seeded tree has 6 files/side → over the cap
            )
    assert ei.value.cap == 2
    assert ei.value.definitive_count == 3  # saturates at cap + 1


async def test_reconcile_route_too_large_is_413_with_guidance(
    api_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The router maps the too-large guard to 413 with an actionable, scope-narrowing message.
    dvol, droot, cvol, croot = await _seed_two_trees()
    auth = await seed_principal(username="rec-big")

    async def _too_large(self: ReconcileService, **_: object) -> None:
        raise ReconcileTooLargeError(definitive_count=1_000_001, comparison_count=0, cap=1_000_000)

    monkeypatch.setattr(ReconcileService, "compare", _too_large)
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
    assert resp.status_code == 413, resp.text
    detail = resp.json()["detail"]
    assert "definitive folder" in detail and "matching subfolder" in detail


async def test_reconcile_route_timeout_is_504(
    api_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # EC-reconcile-4: a comparison that blows the DB time budget surfaces as 504 with the
    # narrow-the-scope guidance (mirrors the 413 too-large mapping).
    dvol, droot, cvol, croot = await _seed_two_trees()
    auth = await seed_principal(username="rec-slow")

    async def _timeout(self: ReconcileService, **_: object) -> None:
        raise ReconcileTimeoutError()

    monkeypatch.setattr(ReconcileService, "compare", _timeout)
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
    assert resp.status_code == 504, resp.text
    assert "took too long" in resp.json()["detail"]


async def test_reconcile_unknown_volume_404(api_client: httpx.AsyncClient) -> None:
    # EC-reconcile-7: a non-existent definitive volume id is "unknown volume" (404), distinct from
    # the out-of-scope (403) path — the router's get_volume_in_scope None branch (reconcile.py:43).
    _dvol, droot, cvol, croot = await _seed_two_trees()
    auth = await seed_principal(username="rec-404")
    resp = await api_client.post(
        "/api/v1/reconcile",
        json={
            "definitive_volume_id": 999_999,  # no such volume
            "definitive_path": droot,
            "comparison_volume_id": cvol,
            "comparison_path": croot,
        },
        headers=auth,
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown volume"


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


async def _seed_two_empty_volumes() -> tuple[int, str, int, str]:
    """Two in-scope volumes with NO file rows under either root."""
    async with db.session_scope() as session:
        host = Host(name="h-empty", cert_fingerprint="ee:ff")
        session.add(host)
        await session.flush()
        dvol = Volume(
            host_id=host.id, mountpoint="/edef", fs_type="zfs", device="d", transport="sata"
        )
        cvol = Volume(
            host_id=host.id, mountpoint="/ecmp", fs_type="ext4", device="c", transport="sata"
        )
        session.add_all([dvol, cvol])
        await session.flush()
        return dvol.id, "/edef", cvol.id, "/ecmp"


async def test_reconcile_empty_roots(api_client: httpx.AsyncClient) -> None:
    # EC-reconcile-1: two in-scope volumes with no files under either root produce a clean all-zero
    # verdict (every count 0, considered 0, no items) — not an error.
    dvol, droot, cvol, croot = await _seed_two_empty_volumes()
    auth = await seed_principal(username="rec-empty")
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
    assert all(v == 0 for v in body["counts"].values())
    assert body["considered"] == 0
    assert body["items"] == []
    assert body["truncated"] is False


async def test_reconcile_truncates_item_sample(api_client: httpx.AsyncClient) -> None:
    # EC-reconcile-13: more diverged files than the item cap → the per-class COUNTS stay exact while
    # the returned sample is capped at MAX_ITEMS and `truncated` is set.
    n = MAX_ITEMS + 1
    async with db.session_scope() as session:
        host = Host(name="h-big", cert_fingerprint="tt:uu")
        session.add(host)
        await session.flush()
        dvol = Volume(
            host_id=host.id, mountpoint="/tdef", fs_type="zfs", device="d", transport="sata"
        )
        cvol = Volume(
            host_id=host.id, mountpoint="/tcmp", fs_type="ext4", device="c", transport="sata"
        )
        session.add_all([dvol, cvol])
        await session.flush()
        rows = []
        for i in range(n):
            rel = f"d/f{i:04d}.bin"  # same relpath on both sides, DIFFERENT hash → diverged
            rows.append(_entry(dvol, host, rel, size=100, mtime=1000.0, h=f"def{i}"))
            rows.append(_entry(cvol, host, rel, size=100, mtime=1000.0, h=f"cmp{i}"))
        session.add_all(rows)
        await session.flush()
        dvid, cvid = dvol.id, cvol.id

    async with db.session_scope() as session:
        result = await ReconcileService(session).compare(
            definitive_volume_id=dvid,
            definitive_root="/tdef",
            comparison_volume_id=cvid,
            comparison_root="/tcmp",
        )
    assert result.counts[DIVERGED] == n  # counts are exact (not capped)
    assert result.considered == n
    assert len(result.items) == MAX_ITEMS  # the sample is bounded
    assert result.truncated is True
    assert all(it.classification == DIVERGED for it in result.items)


async def test_reconcile_unsafe_paths_are_422(api_client: httpx.AsyncClient) -> None:
    # EC-reconcile-9/10: a relative, NUL-byte, or relative-'..' root is rejected by the root-anchor
    # validator (422 'not a safe absolute path'); a zero volume id / empty path fails schema bounds.
    dvol, droot, cvol, croot = await _seed_two_trees()
    auth = await seed_principal(username="rec-bad")

    def body(**over: object) -> dict[str, object]:
        b: dict[str, object] = {
            "definitive_volume_id": dvol,
            "definitive_path": droot,
            "comparison_volume_id": cvol,
            "comparison_path": croot,
        }
        b.update(over)
        return b

    for bad in ("relative/not/abs", "/defroot/\x00nul", "../../etc"):
        resp = await api_client.post(
            "/api/v1/reconcile", json=body(definitive_path=bad), headers=auth
        )
        assert resp.status_code == 422, (bad, resp.text)
        assert "not a safe absolute path" in resp.json()["detail"]

    # Schema bounds (ReconcileRequest): volume_id ge=1, path min_length=1.
    assert (
        await api_client.post(
            "/api/v1/reconcile", json=body(definitive_volume_id=0), headers=auth
        )
    ).status_code == 422
    assert (
        await api_client.post("/api/v1/reconcile", json=body(definitive_path=""), headers=auth)
    ).status_code == 422


async def test_reconcile_root_prefix_is_exact_no_sibling_or_wildcard_leak(
    api_client: httpx.AsyncClient,
) -> None:
    # EC-reconcile-19/20: a root matches ONLY its own subtree — a sibling dir sharing the root as a
    # string prefix (/d/a_b vs /d/a_bX) never leaks in, and LIKE metacharacters in the root ('_')
    # are matched literally (escaped), not as wildcards. A trailing slash on the root is equivalent.
    async with db.session_scope() as session:
        host = Host(name="h-prefix", cert_fingerprint="pp:qq")
        session.add(host)
        await session.flush()
        dvol = Volume(
            host_id=host.id, mountpoint="/d", fs_type="zfs", device="d", transport="sata"
        )
        cvol = Volume(
            host_id=host.id, mountpoint="/c", fs_type="ext4", device="c", transport="sata"
        )
        session.add_all([dvol, cvol])
        await session.flush()
        rows = [
            _entry(dvol, host, "a_b/x.bin", size=100, mtime=1000.0, h="H"),  # in root /d/a_b
            _entry(dvol, host, "aXb/leak.bin", size=100, mtime=1000.0, h="H"),  # wildcard leak
            _entry(dvol, host, "a_bX/leak2.bin", size=100, mtime=1000.0, h="H"),  # sibling leak
            _entry(cvol, host, "x.bin", size=100, mtime=1000.0, h="H"),  # comparison side
        ]
        session.add_all(rows)
        await session.flush()
        dvid, cvid = dvol.id, cvol.id

    for root in ("/d/a_b", "/d/a_b/"):  # trailing slash must give the same result
        async with db.session_scope() as session:
            result = await ReconcileService(session).compare(
                definitive_volume_id=dvid,
                definitive_root=root,
                comparison_volume_id=cvid,
                comparison_root="/c",
            )
        # Only a_b/x.bin is in the definitive side → it matches the comparison x.bin (identical).
        assert result.considered == 1, root
        assert result.counts[IDENTICAL] == 1
        assert all(v == 0 for k, v in result.counts.items() if k != IDENTICAL)


async def test_reconcile_excludes_dirs_and_absent_rows(api_client: httpx.AsyncClient) -> None:
    # EC-reconcile-17/21: directory rows and not-present (deleted) rows under a root are excluded
    # from the comparison, and `considered` equals matched + missing-each-side with no double count.
    async with db.session_scope() as session:
        host = Host(name="h-excl", cert_fingerprint="xx:yy")
        session.add(host)
        await session.flush()
        dvol = Volume(
            host_id=host.id, mountpoint="/xd", fs_type="zfs", device="d", transport="sata"
        )
        cvol = Volume(
            host_id=host.id, mountpoint="/xc", fs_type="ext4", device="c", transport="sata"
        )
        session.add_all([dvol, cvol])
        await session.flush()
        rows = [
            _entry(dvol, host, "r/shared.bin", size=100, mtime=1000.0, h="H"),
            _entry(cvol, host, "r/shared.bin", size=100, mtime=1000.0, h="H"),
            _entry(dvol, host, "r/only-def.bin", size=10, mtime=1000.0, h="D"),
            _entry(cvol, host, "r/only-cmp.bin", size=20, mtime=1000.0, h="E"),
        ]
        # A directory and a deleted file under the definitive root — must NOT inflate any count.
        a_dir = _entry(dvol, host, "r/subdir", size=0, mtime=1000.0, h=None)
        a_dir.is_dir = True
        gone = _entry(dvol, host, "r/gone.bin", size=100, mtime=1000.0, h="G")
        gone.present = False
        rows += [a_dir, gone]
        session.add_all(rows)
        await session.flush()
        dvid, cvid = dvol.id, cvol.id

    async with db.session_scope() as session:
        result = await ReconcileService(session).compare(
            definitive_volume_id=dvid,
            definitive_root="/xd/r",
            comparison_volume_id=cvid,
            comparison_root="/xc/r",
        )
    c = result.counts
    assert c[IDENTICAL] == 1  # shared.bin
    assert c[MISSING_ON_COMPARISON] == 1  # only-def.bin (NOT subdir or gone.bin)
    assert c[MISSING_ON_DEFINITIVE] == 1  # only-cmp.bin
    assert result.considered == 3  # 1 matched + 1 + 1, each distinct relpath counted once
    assert result.considered == sum(c.values())  # no double count across matched/missing
    rels = {it.relpath for it in result.items}
    assert "subdir" not in rels and "gone.bin" not in rels
