"""Signed action-job tests (STRIDE T-3/S-3): tamper / replay / expiry / wrong-key rejection.

These are the named ``test_T3_*`` cases ADR-011 requires green before any execute build. Every
failure mode is fail-closed: ``verify_job`` raises before returning a job, so the actor never
touches the filesystem on a bad job.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.core.remediation.job import ActionJob, ScanJob, SignedJob
from fathom.core.remediation.nonce_store import InMemoryNonceStore
from fathom.core.remediation.plan import PlanAction, PlanItem
from fathom.core.remediation.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    HmacSigner,
    HmacVerifier,
    JobVerificationError,
    NonceReuseError,
    sign_job,
    verify_job,
)

HOST = "nas-1"


def _job(*, nonce: str = "0123456789abcdef0123", mode: str = "execute") -> ActionJob:
    now = datetime.now(tz=UTC)
    return ActionJob(
        plan_id="plan-1",
        mode=mode,  # type: ignore[arg-type]
        nonce=nonce,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=300),
        host_id=HOST,
        keeper_path="/v/keep.bin",
        items=[
            PlanItem(
                entry_id="dup",
                path="/v/dup.bin",
                prior_inode=42,
                prior_size=4096,
                prior_hash="abc",
                action=PlanAction.QUARANTINE,
            )
        ],
    )


def _ed_pair() -> tuple[Ed25519Signer, Ed25519Verifier]:
    priv = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(priv, key_id="orchestrator-v1")
    verifier = Ed25519Verifier(priv.public_key(), key_id="orchestrator-v1")
    return signer, verifier


async def test_sign_and_verify_roundtrip() -> None:
    signer, verifier = _ed_pair()
    signed = sign_job(_job(), signer)
    job = await verify_job(
        signed,
        verifier=verifier,
        nonce_store=InMemoryNonceStore(),
        expected_host_id=HOST,
    )
    assert job.plan_id == "plan-1"
    assert signed.algorithm == "ed25519"


async def test_tampered_job_rejected() -> None:
    signer, verifier = _ed_pair()
    signed = sign_job(_job(), signer)
    # Swap the target path after signing → canonical bytes change → signature no longer valid.
    tampered_job = signed.job.model_copy(
        update={"items": [signed.job.items[0].model_copy(update={"path": "/v/victim.bin"})]}
    )
    tampered = signed.model_copy(update={"job": tampered_job})
    with pytest.raises(JobVerificationError):
        await verify_job(
            tampered,
            verifier=verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id=HOST,
        )


async def test_replayed_nonce_rejected() -> None:
    signer, verifier = _ed_pair()
    store = InMemoryNonceStore()
    signed = sign_job(_job(), signer)
    await verify_job(signed, verifier=verifier, nonce_store=store, expected_host_id=HOST)
    # Same nonce a second time → replay → rejected (T-3).
    with pytest.raises(NonceReuseError):
        await verify_job(signed, verifier=verifier, nonce_store=store, expected_host_id=HOST)


async def test_expired_job_rejected() -> None:
    signer, verifier = _ed_pair()
    now = datetime.now(tz=UTC)
    expired = _job().model_copy(
        update={"issued_at": now - timedelta(seconds=600), "expires_at": now - timedelta(seconds=1)}
    )
    signed = sign_job(expired, signer)
    with pytest.raises(JobVerificationError, match="expired"):
        await verify_job(
            signed,
            verifier=verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id=HOST,
        )


async def test_not_yet_valid_job_rejected() -> None:
    signer, verifier = _ed_pair()
    now = datetime.now(tz=UTC)
    future = _job().model_copy(
        update={
            "issued_at": now + timedelta(seconds=60),
            "expires_at": now + timedelta(seconds=600),
        }
    )
    signed = sign_job(future, signer)
    with pytest.raises(JobVerificationError, match="not yet valid"):
        await verify_job(
            signed,
            verifier=verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id=HOST,
        )


async def test_wrong_key_signature_rejected() -> None:
    signer, _ = _ed_pair()
    _, other_verifier = _ed_pair()  # a different keypair
    signed = sign_job(_job(), signer)
    with pytest.raises(JobVerificationError):
        await verify_job(
            signed,
            verifier=other_verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id=HOST,
        )


async def test_out_of_scope_host_rejected() -> None:
    signer, verifier = _ed_pair()
    signed = sign_job(_job(), signer)
    with pytest.raises(JobVerificationError, match="host scope"):
        await verify_job(
            signed,
            verifier=verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id="some-other-host",
        )


async def test_failed_verification_does_not_burn_nonce() -> None:
    # A bad-signature job must NOT consume its nonce (an attacker cannot exhaust the ledger,
    # and a corrected resend would still be honoured). Signature is checked before nonce.
    signer, verifier = _ed_pair()
    store = InMemoryNonceStore()
    good = sign_job(_job(nonce="aaaaaaaaaaaaaaaa1111"), signer)
    tampered = good.model_copy(update={"signature": "AAAA"})
    with pytest.raises(JobVerificationError):
        await verify_job(tampered, verifier=verifier, nonce_store=store, expected_host_id=HOST)
    # The same nonce is still fresh because the tampered job failed before consuming it.
    assert await store.consume("aaaaaaaaaaaaaaaa1111", job_id="x") is True


async def test_algorithm_downgrade_rejected() -> None:
    # An Ed25519 verifier must reject an HMAC-labelled job (no silent algorithm downgrade).
    _ed_signer, ed_verifier = _ed_pair()
    hmac_signed = sign_job(_job(), HmacSigner(b"shared-secret", key_id="orchestrator-v1"))
    with pytest.raises(JobVerificationError):
        await verify_job(
            hmac_signed,
            verifier=ed_verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id=HOST,
        )


async def test_hmac_fallback_roundtrip() -> None:
    signer = HmacSigner(b"shared-secret", key_id="orchestrator-v1")
    verifier = HmacVerifier(b"shared-secret", key_id="orchestrator-v1")
    signed = sign_job(_job(), signer)
    job = await verify_job(
        signed,
        verifier=verifier,
        nonce_store=InMemoryNonceStore(),
        expected_host_id=HOST,
    )
    assert job.plan_id == "plan-1"
    # A different shared secret must not verify.
    wrong = HmacVerifier(b"different-secret", key_id="orchestrator-v1")
    with pytest.raises(JobVerificationError):
        await verify_job(
            signed, verifier=wrong, nonce_store=InMemoryNonceStore(), expected_host_id=HOST
        )


def test_signed_job_is_frozen_and_strict() -> None:
    signer, _ = _ed_pair()
    signed = sign_job(_job(), signer)
    assert isinstance(signed, SignedJob)
    with pytest.raises(ValueError, match=r"frozen|Instance is frozen"):
        signed.signature = "x"  # type: ignore[misc]


# --- Scan Now jobs ride the same signed channel (ADR-025 + Scan Now) -----------------------------


def _scan(
    *, nonce: str = "0123456789abcdef0123", mode: str = "metadata", root: str = "/scan/data"
) -> ScanJob:
    now = datetime.now(tz=UTC)
    return ScanJob(
        nonce=nonce,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=300),
        host_id=HOST,
        root=root,
        mode=mode,  # type: ignore[arg-type]
    )


async def test_scan_job_sign_and_verify_roundtrip() -> None:
    signer, verifier = _ed_pair()
    signed = sign_job(_scan(mode="fullbit"), signer)
    job = await verify_job(
        signed, verifier=verifier, nonce_store=InMemoryNonceStore(), expected_host_id=HOST
    )
    assert isinstance(job, ScanJob)
    assert job.kind == "scan_now" and job.mode == "fullbit" and job.root == "/scan/data"


async def test_scan_job_hmac_roundtrip() -> None:
    signer = HmacSigner(b"k" * 32, key_id="hmac-1")
    verifier = HmacVerifier(b"k" * 32, key_id="hmac-1")
    signed = sign_job(_scan(), signer)
    job = await verify_job(
        signed, verifier=verifier, nonce_store=InMemoryNonceStore(), expected_host_id=HOST
    )
    assert isinstance(job, ScanJob)


async def test_scan_job_tamper_rejected() -> None:
    # Re-pointing the scan root after signing must invalidate the signature (T-3).
    signer, verifier = _ed_pair()
    signed = sign_job(_scan(root="/scan/data"), signer)
    forged = signed.model_copy(update={"job": signed.job.model_copy(update={"root": "/scan/root"})})
    with pytest.raises(JobVerificationError):
        await verify_job(
            forged, verifier=verifier, nonce_store=InMemoryNonceStore(), expected_host_id=HOST
        )


async def test_scan_job_expired_and_wrong_host_rejected() -> None:
    signer, verifier = _ed_pair()
    now = datetime.now(tz=UTC)
    expired = ScanJob(
        nonce="0123456789abcdef0123",
        issued_at=now - timedelta(seconds=600),
        expires_at=now - timedelta(seconds=1),
        host_id=HOST,
        root="/scan/data",
        mode="metadata",
    )
    with pytest.raises(JobVerificationError, match="expired"):
        await verify_job(
            sign_job(expired, signer),
            verifier=verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id=HOST,
        )
    with pytest.raises(JobVerificationError, match="host scope"):
        await verify_job(
            sign_job(_scan(), signer),
            verifier=verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id="other-host",
        )


async def test_scan_job_nonce_is_single_use() -> None:
    signer, verifier = _ed_pair()
    store = InMemoryNonceStore()
    signed = sign_job(_scan(), signer)
    await verify_job(signed, verifier=verifier, nonce_store=store, expected_host_id=HOST)
    with pytest.raises(NonceReuseError):
        await verify_job(signed, verifier=verifier, nonce_store=store, expected_host_id=HOST)


def test_scan_and_action_jobs_never_share_signed_bytes() -> None:
    # The signed bytes differ by kind, so a scan-job signature can NEVER authorize a remediation
    # job (or vice versa) even if the overlapping fields matched.
    scan = _scan()
    action = _job()
    assert scan.canonical_bytes() != action.canonical_bytes()
    signer, verifier = _ed_pair()
    signed_scan = sign_job(scan, signer)
    # Paste the scan signature onto an ActionJob envelope → must fail verification.
    forged = SignedJob(
        job=action,
        key_id=signed_scan.key_id,
        algorithm=signed_scan.algorithm,
        signature=signed_scan.signature,
    )
    assert verifier.verify_signature(forged) is False


def test_signed_job_union_discriminates_by_kind() -> None:
    # Over the wire, SignedJob parses to the right job shape via the ``kind`` discriminator.
    signer, _ = _ed_pair()
    parsed_scan = SignedJob.model_validate_json(sign_job(_scan(), signer).model_dump_json())
    assert isinstance(parsed_scan.job, ScanJob)
    parsed_action = SignedJob.model_validate_json(sign_job(_job(), signer).model_dump_json())
    assert isinstance(parsed_action.job, ActionJob)
