"""Runtime provisioning tests (ADR-025 §3): default-OFF, by-reference signer, fail-loud on bad key.

``build_remediation_runtime`` is the single place the write-path runtime is assembled at startup.
It must:
* return ``None`` when remediation is disabled (default-OFF — runtime unset → get_runtime 503s);
* return ``None`` when enabled but no signing key is provisioned (staged enablement, still 503);
* load the Ed25519 signing key **by reference** from the secret backend and build a working signer
  whose jobs verify under the matching public key;
* fail loud (raise) when a key reference is set but invalid — never half-arm the write path.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.api.remediation_runtime import (
    RemediationProvisioningError,
    build_remediation_runtime,
    load_orchestrator_signer,
)
from fathom.core.remediation.job import ActionJob
from fathom.core.remediation.job_queue import JobQueue
from fathom.core.remediation.plan import PlanAction, PlanItem
from fathom.core.remediation.signing import Ed25519Verifier
from fathom.core.settings import Settings


def _pem(private: Ed25519PrivateKey) -> str:
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "remediation_enabled": True,
        "remediation_signing_key_ref": "fathom_orchestrator_key",
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_disabled_returns_none() -> None:
    queue = JobQueue()
    runtime = build_remediation_runtime(
        _settings(remediation_enabled=False), queue, secret_provider=lambda _r: "x"
    )
    assert runtime is None


def test_enabled_without_key_returns_none() -> None:
    # Enabled but no key reference → staged enablement; runtime stays unset (write path 503s).
    queue = JobQueue()
    runtime = build_remediation_runtime(
        _settings(remediation_signing_key_ref=None), queue, secret_provider=lambda _r: "x"
    )
    assert runtime is None


def test_provisioned_signer_signs_verifiable_jobs() -> None:
    private = Ed25519PrivateKey.generate()
    pem = _pem(private)
    queue = JobQueue()
    runtime = build_remediation_runtime(_settings(), queue, secret_provider=lambda _ref: pem)
    assert runtime is not None
    assert runtime.signer.key_id == "orchestrator-v1"
    # A job signed by the provisioned signer verifies under the matching public key — the agent's
    # pinned verifier will accept exactly these jobs (the channel's trust anchor is sound).
    from datetime import UTC, datetime, timedelta

    now = datetime.now(tz=UTC)
    job = ActionJob(
        plan_id="p1",
        mode="execute",
        nonce="0123456789abcdef0123",
        issued_at=now,
        expires_at=now + timedelta(seconds=300),
        host_id="nas-1",
        keeper_path="/v/keep",
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
    signed = runtime.signer.sign(job)
    verifier = Ed25519Verifier(private.public_key(), key_id="orchestrator-v1")
    assert verifier.verify_signature(signed) is True


def test_unresolvable_key_ref_fails_loud() -> None:
    def _boom(_ref: str) -> str:
        raise RuntimeError("secret backend down")

    with pytest.raises(RemediationProvisioningError):
        build_remediation_runtime(_settings(), JobQueue(), secret_provider=_boom)


def test_empty_key_material_fails_loud() -> None:
    with pytest.raises(RemediationProvisioningError):
        build_remediation_runtime(_settings(), JobQueue(), secret_provider=lambda _r: "")


def test_non_pem_key_material_fails_loud() -> None:
    with pytest.raises(RemediationProvisioningError):
        build_remediation_runtime(
            _settings(), JobQueue(), secret_provider=lambda _r: "not-a-pem-key"
        )


def test_wrong_algorithm_key_fails_loud() -> None:
    # An RSA PEM under the ed25519 algorithm setting is a mismatch → fail loud, never silent.
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    with pytest.raises(RemediationProvisioningError):
        build_remediation_runtime(_settings(), JobQueue(), secret_provider=lambda _r: pem)


def test_hmac_fallback_signer() -> None:
    queue = JobQueue()
    runtime = build_remediation_runtime(
        _settings(remediation_signing_algorithm="hmac-sha256"),
        queue,
        secret_provider=lambda _r: "x" * 48,  # ≥32-byte HMAC secret
    )
    assert runtime is not None
    assert runtime.signer.key_id == "orchestrator-v1"


def test_hmac_short_secret_fails_loud() -> None:
    # A trivially-short HMAC secret is refused rather than producing a weak MAC (review fix).
    with pytest.raises(RemediationProvisioningError):
        build_remediation_runtime(
            _settings(remediation_signing_algorithm="hmac-sha256"),
            JobQueue(),
            secret_provider=lambda _r: "tooshort",
        )


def test_load_signer_directly_none_without_ref() -> None:
    assert load_orchestrator_signer(_settings(remediation_signing_key_ref=None)) is None
