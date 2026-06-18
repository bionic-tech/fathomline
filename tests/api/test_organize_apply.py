"""Organize *apply* tests (ADR-023, Phase 2b): proposal → MOVE plan → dry-run → execute.

The end-to-end path that turns an operator-approved reorganisation into a reversible relocation,
reusing the remediation spine (signed single-use job, drift re-verify, blast cap, MFA, audit). It
runs over an **in-process loopback actor** (the real :class:`SignedJobListener` over a tmp
filesystem) so the signed-job channel is exercised exactly as a remote agent would — no network.

Every file acted on is a THROWAWAY in a tmp sandbox; this never touches real data. Covers the
happy path (files relocate, inode preserved → reversible), the server-authoritative guards
(out-of-root / traversal / collision / no-op / smuggled-entry rejected at build), and the
default-OFF gates (organize + remediation).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.agent.reader.hasher import BackendHasher
from fathom.api.app import create_app
from fathom.auth.principal import Role
from fathom.backends import PosixBackend
from fathom.core import db
from fathom.core.audit import verify_chain
from fathom.core.audit_store import persisted_records
from fathom.core.catalogue.models import FsEntryRow, Host, Volume
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal
from tests.api.test_remediation_endpoints import _wire_runtime


@pytest.fixture
async def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        organize_enabled=True,
        remediation_enabled=True,
        remediation_blast_cap=100,
    )


async def _client(settings: Settings, *, tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    await db.dispose_engine()
    app = create_app(settings)
    # The job's host scope is the business host id (Host.name == the agent's configured host_id),
    # so the in-process loopback listener pins the seeded host's name (ADR-025 host-scope model).
    _wire_runtime(app, quarantine_dir=tmp_path / "quarantine", host_id="nas-1")
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


@pytest.fixture
async def api_client(settings: Settings, tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client(settings, tmp_path=tmp_path):
        yield c


async def _seed_folder(tmp_path: Path, *, hashed: bool = True) -> tuple[int, dict[str, int], int]:
    """Create a messy on-disk folder + catalogue rows. Returns (volume_id, {name: entry_id}, host).

    With ``hashed`` (default) the stored ``full_hash`` is the REAL BLAKE3 a full-bit scan would have
    recorded, so the actor's dry-run re-hash matches (no spurious drift) — the production invariant.
    With ``hashed=False`` the rows are metadata-only (``full_hash`` NULL), as after a plain scan.
    """
    folder = tmp_path / "Downloads"
    folder.mkdir()
    files = {
        "invoice 2026.pdf": b"PDF-INVOICE" * 50,
        "vacation.JPG": b"\xff\xd8JPEGDATA" * 40,
        "todo.txt": b"buy milk\n" * 10,
    }
    hasher = BackendHasher(PosixBackend())
    ids: dict[str, int] = {}
    async with db.session_scope() as session:
        host = Host(name="nas-1", cert_fingerprint="ab:cd")
        session.add(host)
        await session.flush()
        volume = Volume(
            host_id=host.id,
            mountpoint=str(folder),
            fs_type="zfs",
            device="tank",
            transport="sata",
        )
        session.add(volume)
        await session.flush()
        for name, data in files.items():
            p = folder / name
            p.write_bytes(data)
            st = p.stat()
            row = FsEntryRow(
                host_id=host.id,
                volume_id=volume.id,
                name=name,
                path=str(p),
                size_logical=st.st_size,
                size_on_disk=st.st_size,
                inode=st.st_ino,
                full_hash=(await hasher.full(str(p))) if hashed else None,
                present=True,
                is_dir=False,
            )
            session.add(row)
            await session.flush()
            ids[name] = row.id
        return volume.id, ids, host.id


# --- happy path: build → dry-run → execute, files relocate reversibly -------------------


async def test_organize_apply_relocates_files(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    volume_id, ids, _ = await _seed_folder(tmp_path)
    folder = tmp_path / "Downloads"
    inode_before = (folder / "invoice 2026.pdf").stat().st_ino
    mfa = await seed_principal(username="org-rem", role=Role.REMEDIATOR, mfa_fresh=True)

    built = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(folder),
            "moves": [
                {"entry_id": ids["invoice 2026.pdf"], "dest_rel": "documents/invoices/2026.pdf"},
                {"entry_id": ids["vacation.JPG"], "dest_rel": "photos/vacation.jpg"},
            ],
        },
        headers=mfa,
    )
    assert built.status_code == 201, built.text
    plan = built.json()
    plan_id = plan["plan_id"]
    assert plan["blast_count"] == 2
    assert plan["move_root"] == str(folder)
    assert {i["dest_rel"] for i in plan["items"]} == {
        "documents/invoices/2026.pdf",
        "photos/vacation.jpg",
    }

    # Dry-run via the existing remediation spine — verifies clean (nothing moved yet).
    dr = await api_client.post(f"/api/v1/remediation/plans/{plan_id}/dry-run", headers=mfa)
    assert dr.status_code == 200
    assert dr.json()["ok"] is True
    assert (folder / "invoice 2026.pdf").exists()  # dry-run mutated nothing

    # Execute — the files relocate.
    ex = await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute", json={"confirm_host": "nas-1"}, headers=mfa
    )
    assert ex.status_code == 200
    assert sorted(r["status"] for r in ex.json()["results"]) == ["moved", "moved"]

    moved = folder / "documents" / "invoices" / "2026.pdf"
    assert moved.exists()
    assert not (folder / "invoice 2026.pdf").exists()  # moved, not copied
    assert moved.stat().st_ino == inode_before  # inode preserved → reversible by linking back
    assert (folder / "photos" / "vacation.jpg").exists()


async def test_organize_apply_audit_chain_unbroken(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    volume_id, ids, _ = await _seed_folder(tmp_path)
    folder = tmp_path / "Downloads"
    mfa = await seed_principal(username="org-aud", role=Role.REMEDIATOR, mfa_fresh=True)
    built = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(folder),
            "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "notes/todo.txt"}],
        },
        headers=mfa,
    )
    plan_id = built.json()["plan_id"]
    await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute", json={"confirm_host": "nas-1"}, headers=mfa
    )
    async with db.session_scope() as session:
        records = await persisted_records(session)
        # The organize.plan.build intent record is on the durable chain, and it verifies unbroken.
        assert any(r.action == "organize.plan.build" for r in records)
        assert verify_chain(records) is True


# --- server-authoritative build guards (all → 422, nothing persisted, nothing moved) ----


@pytest.mark.parametrize(
    ("dest_rel", "why"),
    [
        ("../escape.pdf", "traversal"),
        ("/etc/passwd", "absolute"),
        (".", "resolves to root"),
        ("nested/../../escape.pdf", "traversal via nested"),
    ],
)
async def test_organize_plan_rejects_unsafe_target(
    api_client: httpx.AsyncClient, tmp_path: Path, dest_rel: str, why: str
) -> None:
    volume_id, ids, _ = await _seed_folder(tmp_path)
    folder = tmp_path / "Downloads"
    auth = await seed_principal(username=f"org-{why.replace(' ', '')}", role=Role.REMEDIATOR)
    resp = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(folder),
            "moves": [{"entry_id": ids["todo.txt"], "dest_rel": dest_rel}],
        },
        headers=auth,
    )
    assert resp.status_code == 422, f"{why}: {resp.text}"
    assert (folder / "todo.txt").exists()  # nothing moved


async def test_organize_plan_rejects_target_collision(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    volume_id, ids, _ = await _seed_folder(tmp_path)
    folder = tmp_path / "Downloads"
    auth = await seed_principal(username="org-collide", role=Role.REMEDIATOR)
    resp = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(folder),
            "moves": [
                {"entry_id": ids["invoice 2026.pdf"], "dest_rel": "x/same.bin"},
                {"entry_id": ids["vacation.JPG"], "dest_rel": "x/same.bin"},
            ],
        },
        headers=auth,
    )
    assert resp.status_code == 422
    assert "target" in resp.json()["detail"]


async def test_organize_plan_rejects_smuggled_foreign_entry(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # An entry id that exists but lives OUTSIDE the requested folder must not be plannable via the
    # folder route — the server filters to entries under the root (server-authoritative).
    volume_id, _ids, host_id = await _seed_folder(tmp_path)
    other = tmp_path / "Elsewhere"
    other.mkdir()
    secret = other / "secret.txt"
    secret.write_bytes(b"do not touch")
    st = secret.stat()
    async with db.session_scope() as session:
        row = FsEntryRow(
            host_id=host_id,
            volume_id=volume_id,
            name="secret.txt",
            path=str(secret),
            size_logical=st.st_size,
            inode=st.st_ino,
            present=True,
            is_dir=False,
        )
        session.add(row)
        await session.flush()
        foreign_id = row.id
    auth = await seed_principal(username="org-smuggle", role=Role.REMEDIATOR)
    resp = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(tmp_path / "Downloads"),
            "moves": [{"entry_id": foreign_id, "dest_rel": "landed.txt"}],
        },
        headers=auth,
    )
    assert resp.status_code == 422
    assert secret.read_bytes() == b"do not touch"  # untouched


# --- default-OFF gates ------------------------------------------------------------------


async def test_organize_plan_refused_when_organize_disabled(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        organize_enabled=False,  # gate off
        remediation_enabled=True,
    )
    async for client in _client(settings, tmp_path=tmp_path):
        volume_id, ids, _ = await _seed_folder(tmp_path)
        auth = await seed_principal(username="org-off1", role=Role.REMEDIATOR)
        resp = await client.post(
            "/api/v1/organize/plan",
            json={
                "volume_id": volume_id,
                "path": str(tmp_path / "Downloads"),
                "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
            },
            headers=auth,
        )
        assert resp.status_code == 403
        assert "organize is disabled" in resp.json()["detail"]


async def test_organize_plan_refused_when_remediation_disabled(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        organize_enabled=True,
        remediation_enabled=False,  # the write-path gate is off
    )
    async for client in _client(settings, tmp_path=tmp_path):
        volume_id, ids, _ = await _seed_folder(tmp_path)
        auth = await seed_principal(username="org-off2", role=Role.REMEDIATOR)
        resp = await client.post(
            "/api/v1/organize/plan",
            json={
                "volume_id": volume_id,
                "path": str(tmp_path / "Downloads"),
                "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
            },
            headers=auth,
        )
        assert resp.status_code == 403
        assert "remediation is disabled" in resp.json()["detail"]


# --- authz ------------------------------------------------------------------------------


@pytest.mark.parametrize("role", [Role.VIEWER, Role.AUDITOR])
async def test_organize_plan_denied_without_build_capability(
    api_client: httpx.AsyncClient, tmp_path: Path, role: Role
) -> None:
    volume_id, ids, _ = await _seed_folder(tmp_path)
    auth = await seed_principal(username=f"org-{role.value}", role=role)
    resp = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(tmp_path / "Downloads"),
            "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
        },
        headers=auth,
    )
    assert resp.status_code == 403  # no BUILD_REMEDIATION


async def test_organize_plan_out_of_scope_volume_403(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    volume_id, ids, host_id = await _seed_folder(tmp_path)
    scoped = await seed_principal(
        username="org-scoped", role=Role.REMEDIATOR, scope_kind="host", host_id=host_id + 999
    )
    resp = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(tmp_path / "Downloads"),
            "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
        },
        headers=scoped,
    )
    assert resp.status_code == 403


async def test_organize_plan_idempotency_replay(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    volume_id, ids, _ = await _seed_folder(tmp_path)
    auth = await seed_principal(username="org-idem", role=Role.REMEDIATOR)
    body = {
        "volume_id": volume_id,
        "path": str(tmp_path / "Downloads"),
        "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
        "idempotency_key": "org-key-1",
    }
    first = await api_client.post("/api/v1/organize/plan", json=body, headers=auth)
    second = await api_client.post("/api/v1/organize/plan", json=body, headers=auth)
    assert first.status_code == 201
    assert second.json()["plan_id"] == first.json()["plan_id"]  # no second plan built


# --- adversarial-review regression fixes ------------------------------------------------


@pytest.mark.parametrize(
    "bad_path",
    [
        "/",
        "/etc",
        "relative/dir",
        "/tmp/not-this-volume",
        # `..` that prefix-matches the mount but escapes it once normalised — must be rejected.
        "/tmp/pytest-escape/../../etc",
    ],
)
async def test_organize_plan_rejects_root_outside_volume(
    api_client: httpx.AsyncClient, tmp_path: Path, bad_path: str
) -> None:
    # The folder root is the trusted clamp anchor; it must be absolute AND within the volume's
    # mountpoint, else "/" collapses the in-root prefix test to fail-open (adversarial HIGH).
    volume_id, ids, _ = await _seed_folder(tmp_path)
    auth = await seed_principal(username=f"org-root-{abs(hash(bad_path))}", role=Role.REMEDIATOR)
    resp = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": bad_path,
            "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
        },
        headers=auth,
    )
    assert resp.status_code == 422, resp.text


async def test_organize_suggest_rejects_root_outside_volume(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    volume_id, _ids, _ = await _seed_folder(tmp_path)
    auth = await seed_principal(username="org-sugg-root", role=Role.ADMIN)
    resp = await api_client.post(
        "/api/v1/organize/suggest",
        json={"volume_id": volume_id, "path": "/"},
        headers=auth,
    )
    assert resp.status_code == 422


async def test_organize_plan_idempotency_is_principal_scoped(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # A second principal reusing the SAME idempotency key must NOT receive the first principal's
    # plan (paths/host/plan_id disclosure) — the key is filtered by created_by (adversarial HIGH).
    volume_id, ids, _ = await _seed_folder(tmp_path)
    a = await seed_principal(username="org-a", role=Role.REMEDIATOR)
    b = await seed_principal(username="org-b", role=Role.REMEDIATOR)
    body = {
        "volume_id": volume_id,
        "path": str(tmp_path / "Downloads"),
        "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
        "idempotency_key": "shared-key",
    }
    first = await api_client.post("/api/v1/organize/plan", json=body, headers=a)
    assert first.status_code == 201
    a_plan_id = first.json()["plan_id"]
    # B reuses the key: must never be handed A's plan. Global-unique column → a clean 409.
    second = await api_client.post("/api/v1/organize/plan", json=body, headers=b)
    assert second.status_code == 409
    assert a_plan_id not in second.text  # no disclosure of A's plan id / paths


async def test_organize_plan_rejects_unhashed_entry(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # A metadata-only entry (no full_hash) would degrade the actor's TOCTOU re-check to inode+size
    # only — refuse to plan a move for it until a full-bit scan anchors the content (adversarial).
    volume_id, ids, _ = await _seed_folder(tmp_path, hashed=False)
    auth = await seed_principal(username="org-nohash", role=Role.REMEDIATOR)
    resp = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(tmp_path / "Downloads"),
            "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "n/todo.txt"}],
        },
        headers=auth,
    )
    assert resp.status_code == 422
    assert "content hash" in resp.json()["detail"]


async def test_organize_apply_volume_scoped_remediator_not_locked_out(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # A VOLUME-scoped remediator can build AND execute their own plan: the plan persists volume_id
    # and dry-run/execute re-assert scope at volume granularity (adversarial MEDIUM — no lockout).
    volume_id, ids, _ = await _seed_folder(tmp_path)
    folder = tmp_path / "Downloads"
    vscoped = await seed_principal(
        username="org-vscoped",
        role=Role.REMEDIATOR,
        scope_kind="volume",
        volume_id=volume_id,
        mfa_fresh=True,
    )
    built = await api_client.post(
        "/api/v1/organize/plan",
        json={
            "volume_id": volume_id,
            "path": str(folder),
            "moves": [{"entry_id": ids["todo.txt"], "dest_rel": "notes/todo.txt"}],
        },
        headers=vscoped,
    )
    assert built.status_code == 201, built.text
    plan_id = built.json()["plan_id"]
    dr = await api_client.post(f"/api/v1/remediation/plans/{plan_id}/dry-run", headers=vscoped)
    assert dr.status_code == 200 and dr.json()["ok"] is True
    ex = await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute",
        json={"confirm_host": "nas-1"},
        headers=vscoped,
    )
    assert ex.status_code == 200
    assert [r["status"] for r in ex.json()["results"]] == ["moved"]
    assert (folder / "notes" / "todo.txt").exists()
