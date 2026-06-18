"""Signed single-file pull grant (owner ruling; ADR-014, reuses ADR-011 signing primitives).

Preview file delivery is a **signed single-file pull** over the agent-initiated mTLS channel:
the gVisor preview worker requests exactly **one** file by a nonce'd, audited, scope-checked,
short-TTL token. There is **no new agent inbound port** and **no broad mount** — the grant rides
the same channel the actor uses, and the agent serves exactly the one file the grant names.

Rather than invent a second signing scheme (the owner ruling forbids that), this reuses the
project's Ed25519 :class:`~fathom.core.remediation.signing.Signer`/``Verifier`` and the atomic
single-use :class:`~fathom.core.remediation.signing.NonceStore`. A :class:`FileGrant` is the
parallel envelope to ``ActionJob``: a frozen, ``extra='forbid'`` Pydantic model with a canonical
byte serialization the signature is computed over, a single-use ``nonce``, an
``issued_at``/``expires_at`` window, the target ``host_id`` scope, and the **exact** file
identity (``volume_id``, ``inode``, ``content_hash``) the worker may pull — never a free path
string the worker could redirect.

Verification is fail-closed on every axis, mirroring ``verify_job``:

* wrong / tampered signature        → :class:`GrantVerificationError`
* expired or not-yet-valid          → :class:`GrantVerificationError`
* addressed to another host (scope) → :class:`GrantVerificationError`
* replayed (nonce already consumed) → :class:`GrantReplayError`
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from fathom.core.remediation.signing import NonceStore


class GrantVerificationError(Exception):
    """A file grant failed signature / expiry / scope verification (fail-closed; no FS access)."""


class GrantReplayError(GrantVerificationError):
    """A grant's nonce was already consumed — a replay (T-3). Subclass so callers may catch
    either the specific replay or any verification failure."""


class FileGrant(BaseModel):
    """A scoped, time-boxed, single-use authorisation to pull exactly ONE file (owner ruling).

    The worker presents this (signed) to the agent over the agent-initiated channel; the agent
    serves only the file matching ``(volume_id, inode)`` and re-stats to confirm the content
    still matches ``content_hash`` (the worker never trusts a path the grant could be widened to).
    The signature (over :meth:`canonical_bytes`) covers every field, so a widened path / swapped
    inode / extended expiry invalidates it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str = Field(min_length=1, max_length=64)
    entry_id: int = Field(ge=1)
    host_id: str = Field(min_length=1, max_length=255)  # the one host that may serve this file
    volume_id: int = Field(ge=1)
    # An opaque identity key, NOT a magnitude: the catalogue stores st_ino reinterpreted as
    # signed-64 (_to_signed64) so large NTFS/ZFS file ids fit BigInteger, which can be negative.
    # No ``ge=0`` constraint — a wrapped (negative) inode is valid and must not fail grant minting.
    inode: int
    path: str = Field(min_length=1, max_length=4096)  # for audit/logging; identity is inode+hash
    content_hash: str | None = Field(default=None, max_length=64)
    nonce: str = Field(min_length=16, max_length=128)  # single-use; 128-bit+ CSPRNG hex
    issued_at: datetime
    expires_at: datetime

    def canonical_bytes(self) -> bytes:
        """Return the stable byte string the signature is computed over (sorted, compact).

        Two semantically equal grants serialise identically; any field change (a widened path, a
        swapped inode, an extended expiry) changes these bytes and invalidates the signature.
        """
        payload: dict[str, object] = {
            "grant_id": self.grant_id,
            "entry_id": self.entry_id,
            "host_id": self.host_id,
            "volume_id": self.volume_id,
            "inode": self.inode,
            "path": self.path,
            "content_hash": self.content_hash,
            "nonce": self.nonce,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignedFileGrant(BaseModel):
    """A :class:`FileGrant` plus its detached Ed25519 signature (base64) and key id (ADR-010)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant: FileGrant
    key_id: str = Field(min_length=1)
    algorithm: str = Field(default="ed25519")
    signature: str = Field(min_length=1)  # base64-encoded


class GrantSigner:
    """Core-side Ed25519 signer for file grants (reuses the orchestrator's key custody, ADR-010).

    The same Ed25519 primitive as the remediation signer (owner ruling: do not invent a second
    signing scheme); a deployment may share the orchestrator key or provision a distinct
    preview-grant key, both injected from the secret backend — never read from code here.
    """

    algorithm = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey, *, key_id: str) -> None:
        self._private_key = private_key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, grant: FileGrant) -> SignedFileGrant:
        signature = self._private_key.sign(grant.canonical_bytes())
        return SignedFileGrant(
            grant=grant,
            key_id=self._key_id,
            algorithm="ed25519",
            signature=base64.b64encode(signature).decode("ascii"),
        )


class GrantVerifier:
    """Agent-side Ed25519 verifier — trusts exactly one core public key (key_id)."""

    algorithm = "ed25519"

    def __init__(self, public_key: Ed25519PublicKey, *, key_id: str) -> None:
        self._public_key = public_key
        self._key_id = key_id

    def verify_signature(self, signed: SignedFileGrant) -> bool:
        if signed.algorithm != "ed25519" or signed.key_id != self._key_id:
            return False  # algorithm/key downgrade or unknown key → reject (fail-closed)
        try:
            self._public_key.verify(
                base64.b64decode(signed.signature), signed.grant.canonical_bytes()
            )
        except (InvalidSignature, ValueError):
            return False
        return True


def _as_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp (round-trips can drop tzinfo) to UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


async def verify_grant(
    signed: SignedFileGrant,
    *,
    verifier: GrantVerifier,
    nonce_store: NonceStore,
    expected_host_id: str,
    now: datetime | None = None,
) -> FileGrant:
    """Verify a signed file grant on **every** axis before returning it (fail-closed).

    Order mirrors ``verify_job``: signature → time window → host scope are checked *before* the
    nonce is consumed, so a tampered/expired/out-of-scope grant never burns a nonce. The nonce is
    consumed last, atomically (insert-or-fail), so a replay is rejected with
    :class:`GrantReplayError` (T-3). Only after all of this does the agent serve the one file.

    Raises:
        GrantVerificationError: bad signature, expired/not-yet-valid, or wrong host scope.
        GrantReplayError: the nonce has already been consumed (a replay).
    """
    if not verifier.verify_signature(signed):
        raise GrantVerificationError("grant signature verification failed")
    grant = signed.grant
    current = now or datetime.now(tz=UTC)
    if _as_utc(grant.expires_at) <= current:
        raise GrantVerificationError("grant has expired")
    if _as_utc(grant.issued_at) > current:
        raise GrantVerificationError("grant is not yet valid")
    if grant.host_id != expected_host_id:
        raise GrantVerificationError(
            f"grant host scope {grant.host_id!r} does not match this agent {expected_host_id!r}"
        )
    if not await nonce_store.consume(grant.nonce, job_id=grant.grant_id):
        raise GrantReplayError(f"grant nonce already consumed (replay): {grant.nonce}")
    return grant
