"""Actor signed-job listener tests (STRIDE E-1/T-3): verify-before-act, no FS touch on bad jobs.

These are the named ``test_E1_*`` cases. The listener is the single chokepoint between the wire
and the executor; a bad job must raise *before* any filesystem syscall, and the reader code path
must have no construction route to the executor (separation of duties, ADR-011).
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.agent.actor import (
    ActorDispatcher,
    Executor,
    RemediationUnavailableError,
    ScanDispatcher,
    ScanScopeError,
    SignedJobListener,
)
from fathom.agent.config import AgentConfig
from fathom.agent.reader.hasher import BackendHasher
from fathom.agent.runner import AgentRunSummary, ScopeOutcome
from fathom.backends import PosixBackend
from fathom.core.audit import AuditChain
from fathom.core.remediation.job import ActionJob, ScanJob
from fathom.core.remediation.nonce_store import InMemoryNonceStore
from fathom.core.remediation.plan import PlanAction, PlanItem
from fathom.core.remediation.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    JobVerificationError,
    NonceReuseError,
    sign_job,
)

HOST = "nas-1"
SCAN_ROOT = "/scan/data"


def _ed_pair() -> tuple[Ed25519Signer, Ed25519Verifier]:
    priv = Ed25519PrivateKey.generate()
    return (
        Ed25519Signer(priv, key_id="orchestrator-v1"),
        Ed25519Verifier(priv.public_key(), key_id="orchestrator-v1"),
    )


def _make_listener(
    tmp_path: Path,
    *,
    verifier: Ed25519Verifier,
    write_enabled: bool = True,
    host_id: str = HOST,
) -> tuple[SignedJobListener, list[object], InMemoryNonceStore]:
    sink: list[object] = []
    executor = Executor(
        quarantine_dir=tmp_path / "quarantine",
        audit=AuditChain(sink=sink.append),
        write_enabled=write_enabled,
    )
    dispatcher = ActorDispatcher(executor=executor, hasher=BackendHasher(PosixBackend()))
    store = InMemoryNonceStore()
    listener = SignedJobListener(
        dispatcher=dispatcher,
        verifier=verifier,
        nonce_store=store,
        host_id=host_id,
        write_enabled=write_enabled,
    )
    return listener, sink, store


def _two_identical(tmp_path: Path) -> tuple[Path, Path]:
    a = tmp_path / "keep.bin"
    b = tmp_path / "dup.bin"
    a.write_bytes(b"X" * 4096)
    b.write_bytes(b"X" * 4096)
    return a, b


def _execute_job(dup: Path, *, host_id: str = HOST, mode: str = "execute") -> ActionJob:
    st = dup.stat()
    now = datetime.now(tz=UTC)
    return ActionJob(
        plan_id="plan-listener",
        mode=mode,  # type: ignore[arg-type]
        nonce="abcdef0123456789abcdef",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=300),
        host_id=host_id,
        keeper_path=str(dup.parent / "keep.bin"),
        items=[
            PlanItem(
                entry_id="dup",
                path=str(dup),
                prior_inode=st.st_ino,
                prior_size=st.st_size,
                prior_hash=None,
                action=PlanAction.QUARANTINE,
            )
        ],
    )


async def test_valid_execute_job_quarantines(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    _keep, dup = _two_identical(tmp_path)
    listener, _sink, _store = _make_listener(tmp_path, verifier=verifier)
    signed = sign_job(_execute_job(dup), signer)
    result = await listener.handle(signed)
    assert result.mode == "execute"
    assert [r.status for r in result.results] == ["quarantined"]
    assert not dup.exists()


async def test_unsigned_job_never_touches_fs(tmp_path: Path) -> None:
    _signer, verifier = _ed_pair()
    _other_signer, _ = _ed_pair()  # sign with a DIFFERENT key → invalid signature
    _keep, dup = _two_identical(tmp_path)
    listener, sink, _store = _make_listener(tmp_path, verifier=verifier)
    signed = sign_job(_execute_job(dup), _other_signer)
    with pytest.raises(JobVerificationError):
        await listener.handle(signed)
    assert dup.exists()  # nothing happened
    assert sink == []  # nothing audited (the executor was never reached)


async def test_tampered_job_never_touches_fs(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    _keep, dup = _two_identical(tmp_path)
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"do not touch")
    listener, sink, _store = _make_listener(tmp_path, verifier=verifier)
    signed = sign_job(_execute_job(dup), signer)
    # Repoint the item at the victim after signing — signature no longer matches.
    tampered_item = signed.job.items[0].model_copy(update={"path": str(victim)})
    tampered = signed.model_copy(
        update={"job": signed.job.model_copy(update={"items": [tampered_item]})}
    )
    with pytest.raises(JobVerificationError):
        await listener.handle(tampered)
    assert victim.exists() and victim.read_bytes() == b"do not touch"
    assert dup.exists()
    assert sink == []


async def test_replayed_job_rejected_after_first(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    _keep, dup = _two_identical(tmp_path)
    listener, _sink, _store = _make_listener(tmp_path, verifier=verifier)
    signed = sign_job(_execute_job(dup), signer)
    await listener.handle(signed)  # first time acts
    # Resend the identical signed job → nonce already consumed → replay rejected (T-3).
    with pytest.raises(NonceReuseError):
        await listener.handle(signed)


async def test_out_of_scope_job_rejected(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    _keep, dup = _two_identical(tmp_path)
    listener, sink, _store = _make_listener(tmp_path, verifier=verifier, host_id=HOST)
    # Job addressed to a different host → out of scope → rejected before any FS touch.
    signed = sign_job(_execute_job(dup, host_id="other-host"), signer)
    with pytest.raises(JobVerificationError, match="host scope"):
        await listener.handle(signed)
    assert dup.exists()
    assert sink == []


async def test_expired_job_rejected(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    _keep, dup = _two_identical(tmp_path)
    listener, sink, _store = _make_listener(tmp_path, verifier=verifier)
    now = datetime.now(tz=UTC)
    expired = _execute_job(dup).model_copy(
        update={"issued_at": now - timedelta(seconds=600), "expires_at": now - timedelta(seconds=1)}
    )
    signed = sign_job(expired, signer)
    with pytest.raises(JobVerificationError, match="expired"):
        await listener.handle(signed)
    assert dup.exists()
    assert sink == []


async def test_dry_run_job_never_mutates(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    _keep, dup = _two_identical(tmp_path)
    listener, sink, _store = _make_listener(tmp_path, verifier=verifier)
    signed = sign_job(_execute_job(dup, mode="dry_run"), signer)
    result = await listener.handle(signed)
    assert result.mode == "dry_run"
    assert result.drift == {}  # nothing drifted
    assert dup.exists()  # dry-run never mutates
    assert sink == []  # and never audits a mutation


def _scan_config(scope_root: str = SCAN_ROOT) -> AgentConfig:
    return AgentConfig.model_validate(
        {
            "host_id": HOST,
            "ingest_url": "https://core:9443/api/v1/agents/ingest",
            "client_cert_path": "/etc/fathom/agent.crt",
            "client_key_path": "/etc/fathom/agent.key",
            "server_ca_path": "/etc/fathom/ca.crt",
            "scan_scope": [scope_root],
            "throttle": {
                "pause_when": {"load1_above": 6.0, "iowait_above_percent": 25},
                "resume_when": {"load1_below": 3.0},
            },
        }
    )


def _scan_job(*, root: str = SCAN_ROOT, mode: str = "metadata", host_id: str = HOST) -> ScanJob:
    now = datetime.now(tz=UTC)
    return ScanJob(
        nonce="abcdef0123456789abcdef",
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=300),
        host_id=host_id,
        root=root,
        mode=mode,  # type: ignore[arg-type]
    )


class _RecordingScanRunner:
    """A fake scan runner: records (root, mode) and returns a canned single-scope summary."""

    def __init__(self, *, entries_seen: int = 42, pushed: int = 40) -> None:
        self.calls: list[tuple[str, str]] = []
        self._entries_seen = entries_seen
        self._pushed = pushed

    async def __call__(self, job: ScanJob) -> AgentRunSummary:
        self.calls.append((job.root, job.mode))
        return AgentRunSummary(
            host_id=HOST,
            scopes=[ScopeOutcome(job.root, self._entries_seen, self._entries_seen)],
            pushed=self._pushed,
        )


def _scan_listener(
    tmp_path: Path,
    *,
    verifier: Ed25519Verifier,
    config: AgentConfig,
    scan_runner: _RecordingScanRunner,
) -> SignedJobListener:
    listener, _sink, _store = _make_listener(tmp_path, verifier=verifier)
    # Re-build a listener wired with the scan dispatcher (the remediation dispatcher is unchanged).
    return SignedJobListener(
        dispatcher=listener._dispatcher,
        verifier=verifier,
        nonce_store=listener._nonce_store,
        host_id=HOST,
        write_enabled=True,
        scan_dispatcher=ScanDispatcher(config=config, scan_runner=scan_runner),
    )


async def test_scan_job_triggers_scan_of_right_root_and_mode(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    runner = _RecordingScanRunner()
    listener = _scan_listener(
        tmp_path, verifier=verifier, config=_scan_config(), scan_runner=runner
    )
    signed = sign_job(_scan_job(root=SCAN_ROOT, mode="fullbit"), signer)
    result = await listener.handle(signed)
    # The scan was triggered for exactly the signed root + mode (not the remediation executor).
    assert runner.calls == [(SCAN_ROOT, "fullbit")]
    # The result reuses the read-only dry_run shape with a synthetic scan ledger id + summary row.
    assert result.mode == "dry_run"
    assert result.plan_id == f"scan:{HOST}:{SCAN_ROOT}"
    assert len(result.results) == 1
    only = result.results[0]
    assert only.entry_id == SCAN_ROOT
    assert only.action == "scan_now"
    assert only.status == "completed"
    assert "mode=fullbit" in only.detail and "entries_seen=42" in only.detail
    assert result.audit == []


async def test_out_of_scope_scan_job_refused(tmp_path: Path) -> None:
    signer, verifier = _ed_pair()
    runner = _RecordingScanRunner()
    # The agent's scan_scope is /scan/data; /scan/other is out of scope (defence in depth).
    listener = _scan_listener(
        tmp_path, verifier=verifier, config=_scan_config(SCAN_ROOT), scan_runner=runner
    )
    signed = sign_job(_scan_job(root="/scan/other", mode="metadata"), signer)
    with pytest.raises(ScanScopeError, match="scan_scope"):
        await listener.handle(signed)
    assert runner.calls == []  # no scan was ever triggered


async def test_scan_only_listener_refuses_remediation(tmp_path: Path) -> None:
    # A scan-only listener (dispatcher=None) carries the Scan Now path but REFUSES a verified
    # remediation ActionJob fail-closed — a read-only host never carries the write path (ADR-027).
    # (The scan path itself is covered by test_scan_job_triggers_scan_of_right_root_and_mode.)
    signer, verifier = _ed_pair()
    runner = _RecordingScanRunner()
    scan_only = SignedJobListener(
        dispatcher=None,
        verifier=verifier,
        nonce_store=InMemoryNonceStore(),
        host_id=HOST,
        write_enabled=False,
        scan_dispatcher=ScanDispatcher(config=_scan_config(), scan_runner=runner),
    )
    dup = tmp_path / "dup.bin"
    dup.write_bytes(b"x")
    with pytest.raises(RemediationUnavailableError, match="scan-only"):
        await scan_only.handle(sign_job(_execute_job(dup), signer))
    assert runner.calls == []  # nothing scanned either — the job was refused before any dispatch


async def test_scan_job_refused_when_listener_has_no_scan_dispatcher(tmp_path: Path) -> None:
    # A listener built without a scan dispatcher refuses a verified scan job fail-closed (it never
    # silently swallows a job it cannot service).
    signer, verifier = _ed_pair()
    listener, _sink, _store = _make_listener(tmp_path, verifier=verifier)
    signed = sign_job(_scan_job(), signer)
    with pytest.raises(ScanScopeError, match="not configured"):
        await listener.handle(signed)


def test_reader_code_path_has_no_executor_import() -> None:
    # Separation of duties (E-1): the reader package must not import the executor/listener.
    # A reader process can never construct the write surface — it has no symbol path to it.
    for mod_name in (
        "fathom.agent.reader.walker",
        "fathom.agent.reader.supervisor",
        "fathom.agent.reader.feed",
        "fathom.agent.reader.fullbit",
        "fathom.agent.reader.incremental",
    ):
        module = importlib.import_module(mod_name)
        source = Path(module.__file__ or "").read_text()
        assert "actor.executor" not in source
        assert "actor.listener" not in source
        assert "Executor" not in source
        assert "SignedJobListener" not in source
