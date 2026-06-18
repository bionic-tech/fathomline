"""Action-job signing + fail-closed verification (ADR-010 secret backend; STRIDE T-3/S-3).

Owner ruling (design_question #1): jobs are **Ed25519-signed by the orchestrator**, and each
agent trusts only the orchestrator's public key — asymmetric signing gives non-repudiation
(the agent can prove a job came from the orchestrator and the orchestrator cannot deny it),
which a shared HMAC secret cannot. An :class:`HmacSigner` is provided as a documented fallback
for a deployment that cannot run asymmetric key custody, but Ed25519 is the default.

The verifier is **fail-closed** on every axis (T-3/S-3):

* wrong / tampered signature  → :class:`JobVerificationError`
* expired or not-yet-valid    → :class:`JobVerificationError`
* algorithm / key-id mismatch → :class:`JobVerificationError`
* replayed (nonce already consumed) → :class:`NonceReuseError`

Key material (the Ed25519 private key, the HMAC secret) is supplied by the caller from the
pluggable secret backend (Docker secret / OpenBao, ADR-010) and never read from code, ``.env``,
or config here — this module only knows how to sign and verify given a key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from fathom.core.remediation.job import ActionJob, SignedJob


class JobVerificationError(Exception):
    """A job failed signature / expiry / scope verification (fail-closed; no FS access)."""


class NonceReuseError(JobVerificationError):
    """A job's nonce has already been consumed — a replay (T-3). Subclass so callers may
    catch either the specific replay or any verification failure."""


@runtime_checkable
class NonceStore(Protocol):
    """A single-use nonce ledger. ``consume`` must be atomic: insert-or-fail, never
    read-then-write, so two concurrent jobs can never both consume the same nonce (the
    nonce-store race risk). Returns ``True`` if the nonce was fresh (now consumed), ``False``
    if it was already present (a replay)."""

    async def consume(self, nonce: str, *, job_id: str) -> bool: ...


class Signer(Protocol):
    """Signs an :class:`ActionJob`, producing a :class:`SignedJob`."""

    @property
    def key_id(self) -> str: ...

    def sign(self, job: ActionJob) -> SignedJob: ...


class Verifier(Protocol):
    """Verifies a :class:`SignedJob`'s signature (not its nonce/expiry — those are checked
    by :func:`verify_job`, which composes a verifier with a nonce store and a clock)."""

    def verify_signature(self, signed: SignedJob) -> bool: ...


class Ed25519Signer:
    """Orchestrator-side Ed25519 signer (owner-recommended primitive, non-repudiation)."""

    algorithm = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey, *, key_id: str) -> None:
        self._private_key = private_key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, job: ActionJob) -> SignedJob:
        signature = self._private_key.sign(job.canonical_bytes())
        return SignedJob(
            job=job,
            key_id=self._key_id,
            algorithm="ed25519",
            signature=base64.b64encode(signature).decode("ascii"),
        )


class Ed25519Verifier:
    """Agent-side Ed25519 verifier — trusts exactly one orchestrator public key (key_id)."""

    algorithm = "ed25519"

    def __init__(self, public_key: Ed25519PublicKey, *, key_id: str) -> None:
        self._public_key = public_key
        self._key_id = key_id

    def verify_signature(self, signed: SignedJob) -> bool:
        if signed.algorithm != "ed25519" or signed.key_id != self._key_id:
            return False  # algorithm/key downgrade or unknown key → reject (fail-closed)
        try:
            self._public_key.verify(
                base64.b64decode(signed.signature), signed.job.canonical_bytes()
            )
        except (InvalidSignature, ValueError):
            return False
        return True


class HmacSigner:
    """Symmetric HMAC-SHA256 signer — the documented fallback when asymmetric key custody is
    not available. No non-repudiation (the verifier holds the same secret), so Ed25519 is
    preferred (design_question #1)."""

    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes, *, key_id: str) -> None:
        self._secret = secret
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, job: ActionJob) -> SignedJob:
        mac = hmac.new(self._secret, job.canonical_bytes(), hashlib.sha256).digest()
        return SignedJob(
            job=job,
            key_id=self._key_id,
            algorithm="hmac-sha256",
            signature=base64.b64encode(mac).decode("ascii"),
        )


class HmacVerifier:
    """Symmetric HMAC verifier (constant-time compare). Pairs with :class:`HmacSigner`."""

    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes, *, key_id: str) -> None:
        self._secret = secret
        self._key_id = key_id

    def verify_signature(self, signed: SignedJob) -> bool:
        if signed.algorithm != "hmac-sha256" or signed.key_id != self._key_id:
            return False
        expected = hmac.new(self._secret, signed.job.canonical_bytes(), hashlib.sha256).digest()
        try:
            provided = base64.b64decode(signed.signature)
        except ValueError:
            return False
        return hmac.compare_digest(expected, provided)


def sign_job(job: ActionJob, signer: Signer) -> SignedJob:
    """Sign ``job`` with ``signer`` (Ed25519 by default). The returned :class:`SignedJob` is
    what crosses the wire; the bare :class:`ActionJob` never is."""
    return signer.sign(job)


async def verify_job(
    signed: SignedJob,
    *,
    verifier: Verifier,
    nonce_store: NonceStore,
    expected_host_id: str,
    now: datetime | None = None,
) -> ActionJob:
    """Verify a signed job on **every** axis before returning it; raise otherwise (fail-closed).

    Order matters: signature → time window → scope are checked *before* the nonce is consumed,
    so a tampered/expired/out-of-scope job never burns a nonce (and an attacker cannot exhaust
    the ledger with junk). The nonce is consumed last, atomically (insert-or-fail), so a replay
    of a previously-acted job is rejected with :class:`NonceReuseError` (T-3).

    Args:
        signed: The signed job received over the agent-initiated channel.
        verifier: The agent's trusted-key verifier (Ed25519 by default).
        nonce_store: The single-use nonce ledger (atomic consume).
        expected_host_id: The host this agent is — a job addressed elsewhere is out of scope.
        now: Injectable clock for tests (defaults to ``datetime.now(UTC)``).

    Raises:
        JobVerificationError: bad signature, expired/not-yet-valid, or wrong host scope.
        NonceReuseError: the nonce has already been consumed (a replay).
    """
    if not verifier.verify_signature(signed):
        raise JobVerificationError("signature verification failed")
    job = signed.job
    current = now or datetime.now(tz=UTC)
    if _as_utc(job.expires_at) <= current:
        raise JobVerificationError("job has expired")
    if _as_utc(job.issued_at) > current:
        raise JobVerificationError("job is not yet valid")
    if job.host_id != expected_host_id:
        # Server-authoritative scope: a job addressed to another host is refused here too —
        # the actor never trusts that the orchestrator routed it correctly (defence in depth).
        raise JobVerificationError(
            f"job host scope {job.host_id!r} does not match this agent {expected_host_id!r}"
        )
    if not await nonce_store.consume(job.nonce, job_id=job.plan_id):
        raise NonceReuseError(f"nonce already consumed (replay): {job.nonce}")
    return job


def _as_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp (round-trips can drop tzinfo) to UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


# --- Audit-checkpoint signing (bytes-level; security-architecture OQ3) ----------------------
#
# The audit head anchor signs the canonical bytes of ``(seq, row_hash)``, not an ``ActionJob``,
# so it needs a bytes-in/bytes-out primitive distinct from the job ``Signer``/``Verifier`` above.
# Same key custody rules apply (ADR-010): keys arrive from the secret backend, never from code.
# These satisfy :class:`fathom.core.audit_store.CheckpointSigner` / ``CheckpointVerifier``.


class Ed25519CheckpointSigner:
    """Ed25519 signer for audit-head checkpoints (non-repudiation; OQ3, security-review fix (3))."""

    algorithm = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey, *, key_id: str) -> None:
        self._private_key = private_key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


class Ed25519CheckpointVerifier:
    """Ed25519 verifier for audit-head checkpoints (fail-closed; pairs with the signer)."""

    algorithm = "ed25519"

    def __init__(self, public_key: Ed25519PublicKey, *, key_id: str) -> None:
        self._public_key = public_key
        self._key_id = key_id

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True


class HmacCheckpointSigner:
    """HMAC-SHA256 checkpoint signer — the documented symmetric fallback (no non-repudiation)."""

    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes, *, key_id: str) -> None:
        self._secret = secret
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._secret, message, hashlib.sha256).digest()


class HmacCheckpointVerifier:
    """HMAC-SHA256 checkpoint verifier (constant-time compare). Pairs with the signer."""

    algorithm = "hmac-sha256"

    def __init__(self, secret: bytes, *, key_id: str) -> None:
        self._secret = secret
        self._key_id = key_id

    def verify(self, message: bytes, signature: bytes) -> bool:
        expected = hmac.new(self._secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)
