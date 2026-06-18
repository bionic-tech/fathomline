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

from fathom.agent.actor import ActorDispatcher, Executor, SignedJobListener
from fathom.agent.reader.hasher import BackendHasher
from fathom.backends import PosixBackend
from fathom.core.audit import AuditChain
from fathom.core.remediation.job import ActionJob
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
