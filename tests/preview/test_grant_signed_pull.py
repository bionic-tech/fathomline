"""Signed single-file pull grant — adversarial verification (owner ruling; ADR-014, STRIDE T-3).

The grant rides the agent-initiated channel and reuses the Ed25519 + single-use-nonce primitives.
Verification is fail-closed on every axis: a tampered signature, an expired/not-yet-valid window,
a wrong host scope, and a replayed nonce are all rejected before the agent serves the one file.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fathom.core.remediation.nonce_store import InMemoryNonceStore
from fathom.preview.grant import (
    FileGrant,
    GrantReplayError,
    GrantSigner,
    GrantVerificationError,
    GrantVerifier,
    verify_grant,
)

_HOST = "nas-1"


def _grant(*, host: str = _HOST, ttl: int = 60, nonce: str = "a" * 32) -> FileGrant:
    issued = datetime.now(tz=UTC)
    return FileGrant(
        grant_id="grant-1",
        entry_id=7,
        host_id=host,
        volume_id=3,
        inode=4242,
        path="/mnt/pool/photo.jpg",
        content_hash="f" * 64,
        nonce=nonce,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=ttl),
    )


def _keys() -> tuple[GrantSigner, GrantVerifier]:
    priv = Ed25519PrivateKey.generate()
    return (
        GrantSigner(priv, key_id="preview-grant-v1"),
        GrantVerifier(priv.public_key(), key_id="preview-grant-v1"),
    )


async def test_valid_grant_verifies_and_consumes_nonce() -> None:
    signer, verifier = _keys()
    store = InMemoryNonceStore()
    signed = signer.sign(_grant())
    grant = await verify_grant(signed, verifier=verifier, nonce_store=store, expected_host_id=_HOST)
    assert grant.entry_id == 7
    assert grant.inode == 4242


async def test_tampered_signature_rejected() -> None:
    signer, verifier = _keys()
    signed = signer.sign(_grant())
    forged = signed.model_copy(update={"grant": signed.grant.model_copy(update={"volume_id": 99})})
    with pytest.raises(GrantVerificationError):
        await verify_grant(
            forged, verifier=verifier, nonce_store=InMemoryNonceStore(), expected_host_id=_HOST
        )


async def test_wrong_key_rejected() -> None:
    signer, _ = _keys()
    _, other_verifier = _keys()  # a different keypair's verifier
    signed = signer.sign(_grant())
    with pytest.raises(GrantVerificationError):
        await verify_grant(
            signed,
            verifier=other_verifier,
            nonce_store=InMemoryNonceStore(),
            expected_host_id=_HOST,
        )


async def test_expired_grant_rejected() -> None:
    signer, verifier = _keys()
    issued = datetime.now(tz=UTC) - timedelta(seconds=120)
    expired = _grant().model_copy(
        update={"issued_at": issued, "expires_at": issued + timedelta(seconds=30)}
    )
    signed = signer.sign(expired)
    with pytest.raises(GrantVerificationError):
        await verify_grant(
            signed, verifier=verifier, nonce_store=InMemoryNonceStore(), expected_host_id=_HOST
        )


async def test_out_of_scope_host_rejected() -> None:
    signer, verifier = _keys()
    signed = signer.sign(_grant(host="other-host"))
    with pytest.raises(GrantVerificationError):
        await verify_grant(
            signed, verifier=verifier, nonce_store=InMemoryNonceStore(), expected_host_id=_HOST
        )


async def test_replayed_nonce_rejected() -> None:
    signer, verifier = _keys()
    store = InMemoryNonceStore()
    signed = signer.sign(_grant(nonce="b" * 32))
    await verify_grant(signed, verifier=verifier, nonce_store=store, expected_host_id=_HOST)
    # A second redemption of the same grant (same nonce) is a replay → rejected (T-3).
    with pytest.raises(GrantReplayError):
        await verify_grant(signed, verifier=verifier, nonce_store=store, expected_host_id=_HOST)
