"""Agent listen-mode tests (ADR-025 §2): fail-closed startup, key pinning, end-to-end daemon.

The listen daemon is the most dangerous agent path, so it is fenced on every side:
* it refuses to start without all three of write_enabled + orchestrator_pubkey_ref + quarantine_dir;
* it pins exactly the orchestrator's public key (Ed25519 PEM, or the HMAC fallback secret),
  rejecting a non-Ed25519 PEM as a misconfiguration;
* end-to-end, the real ``run_listen`` loop carries a signed job to the executor and a result back.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.agent.actor.listen import (
    ListenStartupError,
    build_listener_from_config,
    build_verifier,
    run_listen,
)
from fathom.agent.config import AgentConfig
from fathom.api.app import create_app
from fathom.api.remediation_runtime import RemediationRuntime, build_queue_dispatch
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.remediation.job import ActionJob
from fathom.core.remediation.job_queue import JobQueue
from fathom.core.remediation.plan import PlanAction, PlanItem
from fathom.core.remediation.signing import Ed25519Signer, Ed25519Verifier, HmacVerifier
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal
from tests.api.test_remediation_endpoints import _seed_group

FP = "X-Client-Cert-Fingerprint"
AGENT_FP = "ab:cd"


def _ed_pub_pem(private: Ed25519PrivateKey) -> str:
    return (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def _config(*, quarantine_dir: str, **over: object) -> AgentConfig:
    base: dict[str, object] = {
        "host_id": "nas-1",
        "ingest_url": "https://core.example:9443/api/v1/agents/ingest",
        "client_cert_path": "/etc/fathom/agent.crt",
        "client_key_path": "/etc/fathom/agent.key",
        "server_ca_path": "/etc/fathom/ca.crt",
        "scan_scope": ["/mnt/pool/media"],
        "throttle": {
            "pause_when": {"load1_above": 6.0, "iowait_above_percent": 25},
            "resume_when": {"load1_below": 3.0},
        },
        "write_enabled": True,
        "orchestrator_pubkey_ref": "orch_pub",
        "quarantine_dir": quarantine_dir,
    }
    base.update(over)
    return AgentConfig.model_validate(base)


# --- __main__ mode dispatch -------------------------------------------------------------


def test_resolve_mode_argv_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from fathom.agent.__main__ import _resolve_mode

    monkeypatch.delenv("FATHOM_AGENT_MODE", raising=False)
    assert _resolve_mode(["prog"]) == "scan"  # default
    assert _resolve_mode(["prog", "listen"]) == "listen"  # argv wins
    monkeypatch.setenv("FATHOM_AGENT_MODE", "listen")
    assert _resolve_mode(["prog"]) == "listen"  # env when no argv


def test_main_listen_fail_closed_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A listen run whose config lacks write_enabled is refused at startup → non-zero exit so a
    # supervisor alerts, and NOTHING is dispatched (the daemon never opened a connection).
    from fathom.agent.__main__ import main

    cfg_yaml = (
        "host_id: nas-1\n"
        "ingest_url: https://core.example:9443/api/v1/agents/ingest\n"
        "client_cert_path: /etc/fathom/agent.crt\n"
        "client_key_path: /etc/fathom/agent.key\n"
        "server_ca_path: /etc/fathom/ca.crt\n"
        "scan_scope: [/mnt/pool/media]\n"
        "write_enabled: false\n"
        f"quarantine_dir: {tmp_path / 'q'}\n"
        "orchestrator_pubkey_ref: orch_pub\n"
        "throttle:\n"
        "  pause_when: {load1_above: 6.0, iowait_above_percent: 25}\n"
        "  resume_when: {load1_below: 3.0}\n"
    )
    cfg_path = tmp_path / "agent.yaml"
    cfg_path.write_text(cfg_yaml, encoding="utf-8")
    monkeypatch.setenv("FATHOM_AGENT_CONFIG", str(cfg_path))
    assert main(["prog", "listen"]) == 2


def test_main_unknown_mode_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fathom.agent.__main__ import main

    cfg_path = tmp_path / "agent.yaml"
    cfg_path.write_text("host_id: x\n", encoding="utf-8")
    monkeypatch.setenv("FATHOM_AGENT_CONFIG", str(cfg_path))
    assert main(["prog", "frobnicate"]) == 2


# --- fail-closed startup ----------------------------------------------------------------


def test_refuses_without_write_enabled(tmp_path: Path) -> None:
    cfg = _config(quarantine_dir=str(tmp_path / "q"), write_enabled=False)
    with pytest.raises(ListenStartupError, match="write_enabled"):
        build_listener_from_config(cfg, secret_provider=lambda _r: "x")


def test_refuses_without_pubkey_ref(tmp_path: Path) -> None:
    cfg = _config(quarantine_dir=str(tmp_path / "q"), orchestrator_pubkey_ref=None)
    with pytest.raises(ListenStartupError, match="orchestrator_pubkey_ref"):
        build_listener_from_config(cfg, secret_provider=lambda _r: "x")


def test_refuses_without_quarantine_dir(tmp_path: Path) -> None:
    cfg = _config(quarantine_dir=str(tmp_path / "q"))
    cfg = cfg.model_copy(update={"quarantine_dir": None})
    with pytest.raises(ListenStartupError, match="quarantine_dir"):
        build_listener_from_config(cfg, secret_provider=lambda _r: "x")


def test_refuses_when_pubkey_ref_unresolved(tmp_path: Path) -> None:
    cfg = _config(quarantine_dir=str(tmp_path / "q"))
    with pytest.raises(ListenStartupError, match="did not resolve"):
        build_listener_from_config(cfg, secret_provider=lambda _r: "")


# --- key pinning ------------------------------------------------------------------------


def test_build_verifier_ed25519_pins_orchestrator_key() -> None:
    private = Ed25519PrivateKey.generate()
    verifier = build_verifier(_ed_pub_pem(private), key_id="orchestrator-v1")
    assert isinstance(verifier, Ed25519Verifier)
    # A job signed by the matching private key verifies; the channel's trust anchor is sound.
    now = datetime.now(tz=UTC)
    job = ActionJob(
        plan_id="p",
        mode="execute",
        nonce="0123456789abcdef0123",
        issued_at=now,
        expires_at=now + timedelta(seconds=300),
        host_id="nas-1",
        keeper_path="/v/k",
        items=[
            PlanItem(
                entry_id="d",
                path="/v/d",
                prior_inode=1,
                prior_size=1,
                prior_hash="h",
                action=PlanAction.QUARANTINE,
            )
        ],
    )
    signed = Ed25519Signer(private, key_id="orchestrator-v1").sign(job)
    assert verifier.verify_signature(signed) is True


def test_build_verifier_hmac_fallback() -> None:
    verifier = build_verifier("x" * 48, key_id="orchestrator-v1", algorithm="hmac-sha256")
    assert isinstance(verifier, HmacVerifier)


def test_build_verifier_hmac_short_secret_refused() -> None:
    with pytest.raises(ListenStartupError, match="too short"):
        build_verifier("tiny", key_id="orchestrator-v1", algorithm="hmac-sha256")


def test_build_verifier_ed25519_rejects_hmac_secret() -> None:
    # Algorithm pinning: a non-PEM secret under the (default) ed25519 algorithm fails loud, rather
    # than silently building an HMAC verifier (no algorithm auto-detection / confusion).
    with pytest.raises(ListenStartupError, match="PEM public key"):
        build_verifier("x" * 48, key_id="orchestrator-v1", algorithm="ed25519")


def test_build_verifier_rejects_non_ed25519_pem() -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (
        rsa_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    with pytest.raises(ListenStartupError, match="Ed25519"):
        build_verifier(pem, key_id="orchestrator-v1")


# --- end-to-end through the real run_listen daemon --------------------------------------


@pytest.fixture
async def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        session_cookie_secure=False,
        remediation_enabled=True,
        remediation_blast_cap=100,
    )


async def test_run_listen_quarantines_end_to_end(settings: Settings, tmp_path: Path) -> None:
    """The real ``run_listen`` daemon claims signed jobs over the poll route and quarantines."""
    await db.dispose_engine()
    app = create_app(settings)
    private = Ed25519PrivateKey.generate()
    queue = JobQueue(poll_timeout_seconds=0.2)
    dry, execute = build_queue_dispatch(queue, job_ttl_seconds=300)
    quarantine_dir = tmp_path / "quarantine"
    config = _config(quarantine_dir=str(quarantine_dir))
    stop = asyncio.Event()

    async with LifespanManager(app):
        app.state.job_queue = queue
        app.state.remediation_runtime = RemediationRuntime(
            signer=Ed25519Signer(private, key_id="orchestrator-v1"),
            dry_run_dispatch=dry,
            execute_dispatch=execute,
        )
        transport = httpx.ASGITransport(app=app)
        # The agent client carries the cert fingerprint on every request (the mTLS proxy's job in
        # production); run_listen itself sends no auth header.
        agent_client = httpx.AsyncClient(
            transport=transport, base_url="http://test", headers={FP: AGENT_FP}
        )
        operator_client = httpx.AsyncClient(transport=transport, base_url="http://test")

        listen_task = asyncio.create_task(
            run_listen(
                config,
                secret_provider=lambda ref: _ed_pub_pem(private),
                client=agent_client,
                stop_event=stop,
            )
        )
        try:
            group_id, keep_id, _ = await _seed_group(tmp_path)
            mfa = await seed_principal(username="listen-e2e", role=Role.REMEDIATOR, mfa_fresh=True)
            built = await operator_client.post(
                "/api/v1/remediation/plans",
                json={"group_id": group_id, "keep_entry_id": keep_id},
                headers=mfa,
            )
            assert built.status_code == 201, built.text
            plan_id = built.json()["plan_id"]
            dr = await operator_client.post(
                f"/api/v1/remediation/plans/{plan_id}/dry-run", headers=mfa
            )
            assert dr.status_code == 200 and dr.json()["ok"] is True
            ex = await operator_client.post(
                f"/api/v1/remediation/plans/{plan_id}/execute",
                json={"confirm_host": "nas-1"},
                headers=mfa,
            )
            assert ex.status_code == 200, ex.text
            assert [r["status"] for r in ex.json()["results"]] == ["quarantined"]
            assert not (tmp_path / "data" / "dup.bin").exists()
            assert (tmp_path / "data" / "keep.bin").exists()
            # The actor ALSO recorded the act in its durable local JSONL backstop (default path
            # inside the actor-owned quarantine dir) — a lost result still leaves a host record.
            audit_file = quarantine_dir / ".act-audit.jsonl"
            assert audit_file.exists()
            lines = audit_file.read_text(encoding="utf-8").splitlines()
            assert any('"quarantine"' in ln and '"quarantined"' in ln for ln in lines)
        finally:
            stop.set()
            await asyncio.wait_for(listen_task, timeout=5)
            await agent_client.aclose()
            await operator_client.aclose()
    await db.dispose_engine()
