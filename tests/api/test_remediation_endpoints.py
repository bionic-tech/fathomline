"""Write/Action API tests (ADR-011, remediation-enable): authz matrix, step-up MFA, default-off.

Covers the test_plan write-route cases:
- BUILD/EXECUTE/QUARANTINE authz matrix (deny-by-default; viewer/operator/auditor 403);
- step-up MFA absence/stale → 401 on execute & quarantine; fresh → proceeds;
- default-off gating: execute refused when ``remediation_enabled=False`` even with valid auth;
- scope escape → 403 (out-of-scope group member);
- idempotency-key replay on plan build returns the original plan, no second plan;
- audit completeness: the persisted hash-chained audit is unbroken after a real execute;
- a real end-to-end execute over an in-process loopback actor (signed job verified, quarantined).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.agent.actor import ActorDispatcher, Executor, SignedJobListener
from fathom.agent.actor.planner import VerifyReport
from fathom.agent.reader.hasher import BackendHasher
from fathom.api.app import create_app
from fathom.api.remediation_runtime import ExecuteOutcome, RemediationRuntime
from fathom.auth.principal import Role
from fathom.backends import PosixBackend
from fathom.core import db
from fathom.core.audit import AuditChain, verify_chain
from fathom.core.audit_store import persisted_records
from fathom.core.catalogue.models import DupGroup, DupMember, FsEntryRow, Host, Volume
from fathom.core.remediation.job import SignedJob
from fathom.core.remediation.nonce_store import InMemoryNonceStore
from fathom.core.remediation.signing import Ed25519Signer, Ed25519Verifier
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal

QUARANTINE = "quarantine"


@pytest.fixture
async def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        remediation_enabled=True,
        remediation_blast_cap=100,
    )


@pytest.fixture
async def disabled_settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        remediation_enabled=False,  # default-off
    )


def _wire_runtime(app: object, *, quarantine_dir: Path, host_id: str) -> None:
    """Wire a RemediationRuntime whose dispatch is a real in-process loopback actor.

    The actor is the real :class:`SignedJobListener` over a tmp filesystem — it verifies the
    signed job (signature + nonce + expiry + scope) before any FS touch, exactly as a remote
    agent would. No network, no inbound port: the dispatch callable simply hands the signed job
    to the listener (the agent-initiated channel, looped back in-process for the test).
    """
    priv = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(priv, key_id="orchestrator-v1")
    verifier = Ed25519Verifier(priv.public_key(), key_id="orchestrator-v1")
    sink: list[object] = []
    executor = Executor(
        quarantine_dir=quarantine_dir,
        audit=AuditChain(sink=sink.append),
        write_enabled=True,
    )
    dispatcher = ActorDispatcher(executor=executor, hasher=BackendHasher(PosixBackend()))
    listener = SignedJobListener(
        dispatcher=dispatcher,
        verifier=verifier,
        nonce_store=InMemoryNonceStore(),
        host_id=host_id,
        write_enabled=True,
    )

    async def dry_run_dispatch(signed: SignedJob) -> VerifyReport:
        result = await listener.handle(signed)
        return VerifyReport(drifted=dict(result.drift))

    async def execute_dispatch(signed: SignedJob) -> ExecuteOutcome:
        # The loopback returns the same shape as the queue-backed dispatch: the per-item results
        # PLUS the actor's per-item act audit, so the orchestrator splices it onto the durable
        # chain exactly as it will for a real remote agent (ADR-025).
        result = await listener.handle(signed)
        return ExecuteOutcome(
            results=[(r.entry_id, r.action, r.status) for r in result.results],
            audit=result.audit,
        )

    app.state.remediation_runtime = RemediationRuntime(  # type: ignore[attr-defined]
        signer=signer,
        dry_run_dispatch=dry_run_dispatch,
        execute_dispatch=execute_dispatch,
    )


async def _seed_group(tmp_path: Path) -> tuple[int, int, int]:
    """Create two identical on-disk files + catalogue rows + a dup group. Returns
    (group_id, keep_entry_id, host_db_id)."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    keep = data_dir / "keep.bin"
    dup = data_dir / "dup.bin"
    keep.write_bytes(b"X" * 4096)
    dup.write_bytes(b"X" * 4096)
    keep_st = keep.stat()
    dup_st = dup.stat()
    # The stored full_hash is the REAL BLAKE3 a full-bit scan would have recorded, so the
    # actor's dry-run re-hash matches (no spurious drift) — exactly the production invariant.
    hasher = BackendHasher(PosixBackend())
    real_hash = await hasher.full(str(keep))
    async with db.session_scope() as session:
        host = Host(name="nas-1", cert_fingerprint="ab:cd")
        session.add(host)
        await session.flush()
        volume = Volume(
            host_id=host.id,
            mountpoint=str(data_dir),
            fs_type="zfs",
            device="tank",
            transport="sata",
        )
        session.add(volume)
        await session.flush()
        keep_entry = FsEntryRow(
            host_id=host.id,
            volume_id=volume.id,
            name="keep.bin",
            path=str(keep),
            size_logical=keep_st.st_size,
            inode=keep_st.st_ino,
            full_hash=real_hash,
        )
        dup_entry = FsEntryRow(
            host_id=host.id,
            volume_id=volume.id,
            name="dup.bin",
            path=str(dup),
            size_logical=dup_st.st_size,
            inode=dup_st.st_ino,
            full_hash=real_hash,
        )
        session.add_all([keep_entry, dup_entry])
        await session.flush()
        group = DupGroup(
            full_hash=real_hash,
            size=4096,
            member_count=2,
            reclaimable_bytes=4096,
            suggested_keeper_entry_id=keep_entry.id,
        )
        group.members = [
            DupMember(entry_id=keep_entry.id, host_id=host.id, volume_id=volume.id, path=str(keep)),
            DupMember(entry_id=dup_entry.id, host_id=host.id, volume_id=volume.id, path=str(dup)),
        ]
        session.add(group)
        await session.flush()
        return group.id, keep_entry.id, host.id


async def _client(settings: Settings, *, tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    await db.dispose_engine()
    app = create_app(settings)
    # The signed job's host scope is the business host id (Host.name == "nas-1"), which the agent
    # independently re-verifies; the loopback listener pins the same value (ADR-025).
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


# --- authz matrix -----------------------------------------------------------------------


async def test_build_requires_auth(api_client: httpx.AsyncClient, tmp_path: Path) -> None:
    group_id, keep_id, _ = await _seed_group(tmp_path)
    resp = await api_client.post(
        "/api/v1/remediation/plans", json={"group_id": group_id, "keep_entry_id": keep_id}
    )
    assert resp.status_code == 401  # deny-by-default, no session


@pytest.mark.parametrize("role", [Role.VIEWER, Role.OPERATOR, Role.AUDITOR])
async def test_build_denied_without_build_capability(
    api_client: httpx.AsyncClient, tmp_path: Path, role: Role
) -> None:
    group_id, keep_id, _ = await _seed_group(tmp_path)
    auth = await seed_principal(username=f"u-{role.value}", role=role)
    resp = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=auth,
    )
    assert resp.status_code == 403  # no BUILD_REMEDIATION


async def test_remediator_can_build(api_client: httpx.AsyncClient, tmp_path: Path) -> None:
    group_id, keep_id, _ = await _seed_group(tmp_path)
    auth = await seed_principal(username="rem", role=Role.REMEDIATOR)
    resp = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=auth,
    )
    assert resp.status_code == 201
    plan = resp.json()
    assert plan["blast_count"] == 1  # 2 members - keeper
    assert len(plan["items"]) == 1


# --- step-up MFA ------------------------------------------------------------------------


async def test_execute_without_fresh_mfa_401(api_client: httpx.AsyncClient, tmp_path: Path) -> None:
    group_id, keep_id, _ = await _seed_group(tmp_path)
    no_mfa = await seed_principal(username="rem2", role=Role.REMEDIATOR, mfa_fresh=False)
    built = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=no_mfa,
    )
    plan_id = built.json()["plan_id"]
    resp = await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute", json={}, headers=no_mfa
    )
    assert resp.status_code == 401  # step-up MFA required


async def test_execute_with_fresh_mfa_quarantines(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    group_id, keep_id, _ = await _seed_group(tmp_path)
    mfa = await seed_principal(username="rem3", role=Role.REMEDIATOR, mfa_fresh=True)
    built = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=mfa,
    )
    plan_id = built.json()["plan_id"]
    # dry-run first
    dr = await api_client.post(f"/api/v1/remediation/plans/{plan_id}/dry-run", headers=mfa)
    assert dr.status_code == 200
    assert dr.json()["ok"] is True
    # execute
    resp = await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute", json={"confirm_host": "nas-1"}, headers=mfa
    )
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert [r["status"] for r in results] == ["quarantined"]
    # The duplicate is gone from its original location, the keeper untouched.
    assert not (tmp_path / "data" / "dup.bin").exists()
    assert (tmp_path / "data" / "keep.bin").exists()


async def test_execute_rejects_wrong_confirm_host(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # Danger-zone gate: the operator must type the TARGET host's name. A wrong/empty value blocks
    # the act (422) before anything is dispatched — the duplicate stays put.
    group_id, keep_id, _ = await _seed_group(tmp_path)
    mfa = await seed_principal(username="rem-confirm", role=Role.REMEDIATOR, mfa_fresh=True)
    built = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=mfa,
    )
    plan_id = built.json()["plan_id"]
    await api_client.post(f"/api/v1/remediation/plans/{plan_id}/dry-run", headers=mfa)
    bad = await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute",
        json={"confirm_host": "not-the-host"},
        headers=mfa,
    )
    assert bad.status_code == 422
    assert "confirmation" in bad.json()["detail"]
    empty = await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute", json={}, headers=mfa
    )
    assert empty.status_code == 422
    assert (tmp_path / "data" / "dup.bin").exists()  # nothing was quarantined


async def test_execute_records_acknowledgement_audit(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # The danger-zone acknowledgement is on the durable hash-chained audit: who, the host they
    # confirmed, the risk classes touched, and whether it was high-risk — before any act.
    group_id, keep_id, _ = await _seed_group(tmp_path)
    mfa = await seed_principal(username="rem-ack", role=Role.REMEDIATOR, mfa_fresh=True)
    built = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=mfa,
    )
    plan_id = built.json()["plan_id"]
    await api_client.post(f"/api/v1/remediation/plans/{plan_id}/dry-run", headers=mfa)
    ok = await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute",
        json={"confirm_host": "NAS-1"},  # case-insensitive match
        headers=mfa,
    )
    assert ok.status_code == 200
    async with db.session_scope() as session:
        records = await persisted_records(session)
        ack = [r for r in records if r.action == "remediation.acknowledged"]
        assert len(ack) == 1
        assert ack[0].result == "acknowledged"
        assert ack[0].before_state["confirm_host"] == "nas-1"
        # The seeded dup files live under a tmp dir → ordinary user data, not high-risk.
        assert ack[0].before_state["high_risk"] is False
        assert verify_chain(records) is True


async def test_quarantine_routes_require_mfa(api_client: httpx.AsyncClient, tmp_path: Path) -> None:
    no_mfa = await seed_principal(username="rem4", role=Role.REMEDIATOR, mfa_fresh=False)
    resp = await api_client.post("/api/v1/remediation/quarantine/some-item/purge", headers=no_mfa)
    assert resp.status_code == 401
    mfa = await seed_principal(username="rem5", role=Role.REMEDIATOR, mfa_fresh=True)
    ok = await api_client.post("/api/v1/remediation/quarantine/some-item/purge", headers=mfa)
    assert ok.status_code == 202


async def test_quarantine_routes_require_global_scope(api_client: httpx.AsyncClient) -> None:
    # HIGH (review): restore/purge act on a free-form item not yet bound to a host/volume, so a
    # non-global QUARANTINE_MANAGE principal must be refused — fail-closed, no estate-wide reach.
    scoped = await seed_principal(
        username="qscoped", role=Role.REMEDIATOR, scope_kind="host", host_id=4242, mfa_fresh=True
    )
    for action in ("restore", "purge"):
        r = await api_client.post(
            f"/api/v1/remediation/quarantine/some-item/{action}", headers=scoped
        )
        assert r.status_code == 403


# --- default-off gating -----------------------------------------------------------------


async def test_execute_refused_when_disabled(disabled_settings: Settings, tmp_path: Path) -> None:
    async for client in _client(disabled_settings, tmp_path=tmp_path):
        group_id, keep_id, _ = await _seed_group(tmp_path)
        mfa = await seed_principal(username="rem6", role=Role.REMEDIATOR, mfa_fresh=True)
        # Even build is refused when the server gate is off (default-off, deliberate enablement).
        resp = await client.post(
            "/api/v1/remediation/plans",
            json={"group_id": group_id, "keep_entry_id": keep_id},
            headers=mfa,
        )
        assert resp.status_code == 403
        assert "disabled" in resp.json()["detail"]


# --- scope escape -----------------------------------------------------------------------


async def test_out_of_scope_build_403(api_client: httpx.AsyncClient, tmp_path: Path) -> None:
    group_id, keep_id, host_db_id = await _seed_group(tmp_path)
    # A remediator scoped to a DIFFERENT host has BUILD_REMEDIATION but not over this group.
    auth = await seed_principal(
        username="scoped", role=Role.REMEDIATOR, scope_kind="host", host_id=host_db_id + 999
    )
    resp = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=auth,
    )
    assert resp.status_code == 403  # member host out of scope


async def test_in_scope_host_build_ok(api_client: httpx.AsyncClient, tmp_path: Path) -> None:
    group_id, keep_id, host_db_id = await _seed_group(tmp_path)
    auth = await seed_principal(
        username="scoped-ok", role=Role.REMEDIATOR, scope_kind="host", host_id=host_db_id
    )
    resp = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=auth,
    )
    assert resp.status_code == 201


# --- idempotency ------------------------------------------------------------------------


async def test_build_idempotency_key_replay(api_client: httpx.AsyncClient, tmp_path: Path) -> None:
    group_id, keep_id, _ = await _seed_group(tmp_path)
    auth = await seed_principal(username="idem", role=Role.REMEDIATOR)
    body = {"group_id": group_id, "keep_entry_id": keep_id, "idempotency_key": "abc-123"}
    first = await api_client.post("/api/v1/remediation/plans", json=body, headers=auth)
    second = await api_client.post("/api/v1/remediation/plans", json=body, headers=auth)
    assert first.status_code == 201
    # Replay returns the SAME plan id (no second plan built).
    assert second.json()["plan_id"] == first.json()["plan_id"]


async def test_build_rejects_keeper_not_in_group(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    group_id, _keep_id, _ = await _seed_group(tmp_path)
    auth = await seed_principal(username="badkeep", role=Role.REMEDIATOR)
    resp = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": 999999},
        headers=auth,
    )
    assert resp.status_code == 422


# --- audit completeness + read surface --------------------------------------------------


async def test_audit_chain_unbroken_after_execute(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    group_id, keep_id, _ = await _seed_group(tmp_path)
    mfa = await seed_principal(username="aud", role=Role.REMEDIATOR, mfa_fresh=True)
    built = await api_client.post(
        "/api/v1/remediation/plans",
        json={"group_id": group_id, "keep_entry_id": keep_id},
        headers=mfa,
    )
    plan_id = built.json()["plan_id"]
    await api_client.post(
        f"/api/v1/remediation/plans/{plan_id}/execute", json={"confirm_host": "nas-1"}, headers=mfa
    )
    async with db.session_scope() as session:
        records = await persisted_records(session)
        assert len(records) >= 1
        assert verify_chain(records) is True
        # ADR-025 step 2: the actor's per-item mutation audit (the destructive act itself) is now
        # spliced onto the DURABLE chain — not only the actor's volatile in-memory sink. A
        # ``quarantine`` act by ``strata-actor`` must be present and the chain still unbroken.
        act_records = [r for r in records if r.actor == "strata-actor" and r.action == "quarantine"]
        assert act_records, "actor's quarantine act audit was not spliced onto the durable chain"
        assert any(r.result == "quarantined" for r in act_records)


async def test_audit_read_requires_read_audit_capability(
    api_client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # remediator does NOT hold READ_AUDIT → 403; auditor does → 200.
    rem = await seed_principal(username="rem-noaudit", role=Role.REMEDIATOR)
    denied = await api_client.get("/api/v1/audit", headers=rem)
    assert denied.status_code == 403
    auditor = await seed_principal(username="auditor1", role=Role.AUDITOR)
    ok = await api_client.get("/api/v1/audit", headers=auditor)
    assert ok.status_code == 200


async def test_runtime_unavailable_returns_503(settings: Settings, tmp_path: Path) -> None:
    # When no runtime is provisioned, the write path is genuinely unavailable (no silent no-op).
    await db.dispose_engine()
    app = create_app(settings)  # no _wire_runtime → runtime absent
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            group_id, keep_id, _ = await _seed_group(tmp_path)
            auth = await seed_principal(username="nort", role=Role.REMEDIATOR)
            resp = await client.post(
                "/api/v1/remediation/plans",
                json={"group_id": group_id, "keep_entry_id": keep_id},
                headers=auth,
            )
            assert resp.status_code == 503
    await db.dispose_engine()
