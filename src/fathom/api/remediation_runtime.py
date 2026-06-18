"""Remediation runtime wiring — signer + the agent-initiated dispatch channel (ADR-010/011).

The orchestrator needs two collaborators it cannot build itself: a :class:`Signer` (whose key
comes from the secret backend, ADR-010) and a *dispatch* handle to the actor. Owner ruling: the
actor is reached over the **agent-initiated outbound channel** — the agent long-polls core for
signed jobs; core never opens a connection to the agent. The dispatch callables here are core's
in-process handle to that already-open channel: they enqueue a signed job for the agent to pull
and await its result.

This module keeps that wiring out of the route handlers and out of the orchestrator, and makes
it injectable so tests can supply an in-process loopback actor (a real
:class:`~fathom.agent.actor.listener.SignedJobListener` over a tmp filesystem) without any
network. The runtime lives on ``app.state.remediation_runtime``; :func:`get_runtime` reads it.

Default posture: if no runtime is configured (no signing key provisioned), :func:`get_runtime`
raises 503 — the write path is genuinely unavailable until a deliberate enablement step wires a
signer. There is no silent-no-op default that could mask a mis-enabled deployment.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException, Request, status

from fathom.agent.actor.planner import VerifyReport
from fathom.core.audit import AuditRecord
from fathom.core.remediation.job import SignedJob
from fathom.core.remediation.job_queue import AuditRecordPayload, JobQueue
from fathom.core.remediation.orchestrator import (
    DryRunDispatch,
    ExecuteDispatch,
    ExecuteOutcome,
)
from fathom.core.remediation.signing import Ed25519Signer, HmacSigner, Signer
from fathom.logging import get_logger

if TYPE_CHECKING:
    from fathom.core.settings import Settings

_log = get_logger("fathom.api.remediation_runtime")

# A "resolve this secret reference to its material" seam (ADR-010), shared with the agent's
# credential resolution. The default is env-first-then-Docker-secrets; tests inject a fake.
SecretProvider = Callable[[str], str]

# Minimum length for the symmetric HMAC fallback secret — a short MAC key is cryptographically
# weak, so a misconfigured trivial secret is refused at provisioning (adversarial-review fix).
_MIN_HMAC_SECRET_BYTES = 32


@dataclass(frozen=True, slots=True)
class RemediationRuntime:
    """The injectable collaborators for the write path (signer + dispatch handles)."""

    signer: Signer
    dry_run_dispatch: DryRunDispatch
    execute_dispatch: ExecuteDispatch


def _audit_record_from_payload(payload: AuditRecordPayload) -> AuditRecord:
    """Map an over-the-wire :class:`AuditRecordPayload` back to an :class:`AuditRecord`.

    Only the *content* fields matter: the orchestrator re-chains each record onto its durable
    head (``AuditChain.splice`` → ``rechain``), recomputing ``prev_hash``/``row_hash`` against
    core's chain, so the actor's own chain linkage is preserved here only for completeness.
    """
    return AuditRecord(
        ts=payload.ts,
        actor=payload.actor,
        action=payload.action,
        target=payload.target,
        before_state=payload.before_state,
        result=payload.result,
        prev_hash=payload.prev_hash,
        row_hash=payload.row_hash,
    )


def build_queue_dispatch(
    queue: JobQueue, *, job_ttl_seconds: int
) -> tuple[DryRunDispatch, ExecuteDispatch]:
    """Build the queue-backed dispatch callables (the production agent-initiated channel).

    Each callable enqueues the signed job for ``job.host_id`` (the business host id == ``Host.name``
    the polling agent resolves to) and blocks on the agent's correlated result, bounded by the job
    TTL so a timed-out dispatch corresponds to an *expired* job the agent would refuse anyway (no
    act-after-give-up). The EXECUTE result carries the actor's per-item act audit, mapped back to
    :class:`~fathom.core.audit.AuditRecord`s for the orchestrator's durable splice (ADR-025).
    """

    async def dry_run_dispatch(signed: SignedJob) -> VerifyReport:
        payload = await queue.enqueue_and_wait(
            signed, host_id=signed.job.host_id, timeout_seconds=job_ttl_seconds
        )
        return VerifyReport(drifted=dict(payload.drift))

    async def execute_dispatch(signed: SignedJob) -> ExecuteOutcome:
        payload = await queue.enqueue_and_wait(
            signed, host_id=signed.job.host_id, timeout_seconds=job_ttl_seconds
        )
        return ExecuteOutcome(
            results=[(r.entry_id, r.action, r.status) for r in payload.results],
            audit=[_audit_record_from_payload(a) for a in payload.audit],
        )

    return dry_run_dispatch, execute_dispatch


class RemediationProvisioningError(RuntimeError):
    """A signing key was configured but could not be loaded (fail-loud at startup, not silent).

    Distinct from the *default-OFF* path (no key reference at all → runtime stays unset → 503):
    this is a misconfiguration during a deliberate enablement (a key reference that does not
    resolve, or resolves to the wrong key type/algorithm) and must abort startup rather than
    leave the operator believing the write path is armed when it is not.
    """


def load_orchestrator_signer(
    settings: Settings, *, secret_provider: SecretProvider | None = None
) -> Signer | None:
    """Load the orchestrator's signing key **by reference** from the secret backend (ADR-010).

    Returns ``None`` when no key reference is configured — the default-OFF posture: the runtime
    stays unset and the write path 503s until a key is deliberately provisioned. The private key
    material itself never lives in code/``.env``/the image; only the *reference* is configured and
    it is resolved at runtime via ``secret_provider`` (env var → Docker secret by default).

    Raises:
        RemediationProvisioningError: a reference is set but does not resolve, or resolves to a key
            that is not the configured algorithm (a misconfigured enablement — fail loud).
    """
    key_ref = settings.remediation_signing_key_ref
    if not key_ref:
        return None
    from fathom.backends.remote import env_or_docker_secret_provider

    provider = secret_provider or env_or_docker_secret_provider
    try:
        material = provider(key_ref)
    except Exception as exc:  # any resolver failure is a fail-loud provisioning error
        raise RemediationProvisioningError(
            f"signing key reference {key_ref!r} did not resolve from the secret backend"
        ) from exc
    if not material:
        raise RemediationProvisioningError(
            f"signing key reference {key_ref!r} resolved to an empty value"
        )
    algorithm = settings.remediation_signing_algorithm.lower()
    key_id = settings.remediation_signing_key_id
    if algorithm == "ed25519":
        try:
            private = serialization.load_pem_private_key(material.encode("utf-8"), password=None)
        except (ValueError, TypeError) as exc:
            raise RemediationProvisioningError(
                "configured Ed25519 signing key is not a valid PEM private key"
            ) from exc
        if not isinstance(private, Ed25519PrivateKey):
            raise RemediationProvisioningError(
                "configured signing key is not an Ed25519 private key (algorithm mismatch)"
            )
        return Ed25519Signer(private, key_id=key_id)
    if algorithm in {"hmac", "hmac-sha256"}:
        secret = material.encode("utf-8")
        if len(secret) < _MIN_HMAC_SECRET_BYTES:
            raise RemediationProvisioningError(
                f"HMAC signing secret is too short (need ≥{_MIN_HMAC_SECRET_BYTES} bytes)"
            )
        return HmacSigner(secret, key_id=key_id)
    raise RemediationProvisioningError(f"unknown signing algorithm {algorithm!r}")


def build_remediation_runtime(
    settings: Settings, queue: JobQueue, *, secret_provider: SecretProvider | None = None
) -> RemediationRuntime | None:
    """Assemble the write-path runtime, or ``None`` to preserve default-OFF (ADR-025 §3).

    Returns a :class:`RemediationRuntime` (signer + queue-backed dispatch) **only when** the server
    gate ``remediation_enabled`` is on AND a signing key is provisioned. With remediation disabled,
    or enabled-but-no-key, it returns ``None`` so ``app.state.remediation_runtime`` stays unset and
    :func:`get_runtime` 503s — no silent no-op, no half-armed write path. A key reference that is
    set but invalid raises :class:`RemediationProvisioningError` (fail loud at startup).
    """
    if not settings.remediation_enabled:
        return None
    signer = load_orchestrator_signer(settings, secret_provider=secret_provider)
    if signer is None:
        _log.warning(
            "remediation_enabled but no signing key provisioned — write path stays 503 "
            "(provision remediation_signing_key_ref to arm it)"
        )
        return None
    dry_run_dispatch, execute_dispatch = build_queue_dispatch(
        queue, job_ttl_seconds=settings.remediation_job_ttl_seconds
    )
    _log.info(
        "remediation runtime provisioned",
        extra={"key_id": signer.key_id, "algorithm": settings.remediation_signing_algorithm},
    )
    return RemediationRuntime(
        signer=signer,
        dry_run_dispatch=dry_run_dispatch,
        execute_dispatch=execute_dispatch,
    )


def get_runtime(request: Request) -> RemediationRuntime:
    """Return the configured runtime, or 503 if the write path is not provisioned (default)."""
    runtime = getattr(request.app.state, "remediation_runtime", None)
    if not isinstance(runtime, RemediationRuntime):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="remediation runtime not provisioned (no signing key / dispatch channel)",
        )
    return runtime


__all__ = [
    "DryRunDispatch",
    "ExecuteDispatch",
    "ExecuteOutcome",
    "RemediationProvisioningError",
    "RemediationRuntime",
    "VerifyReport",
    "build_queue_dispatch",
    "build_remediation_runtime",
    "get_runtime",
    "load_orchestrator_signer",
]
