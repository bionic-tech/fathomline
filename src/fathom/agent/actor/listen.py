"""Agent ``listen`` mode — the daemon side of the signed-job dispatch channel (ADR-025 §2).

Where the one-shot scanner runs ``scan → stage → push`` and exits, the listener runs a loop:

    long-poll core ──▶ SignedJobListener.verify (signature, nonce, expiry, host scope)
                       └─ on ANY failure: log, never touch the FS, re-poll (fail-closed)
                       └─ on success:     ActorDispatcher → executor → post the result back

It is **agent-initiated outbound** (the owner ruling): the agent opens the connection to core and
long-polls; core never connects to the agent, so enabling remediation adds **no inbound port** on
the fleet host. The loop is **fail-closed at startup** — it refuses to run unless all three of
``write_enabled``, ``orchestrator_pubkey_ref`` and ``quarantine_dir`` are configured, so a
scan-only host (or a half-configured one) can never accidentally carry the write path.

Key trust: the listener pins exactly the orchestrator's public key (resolved **by reference** from
the agent's secret backend, ADR-010 — never embedded) under the configured ``orchestrator_key_id``;
a job signed under a different key id or a different algorithm is rejected before any FS access.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fathom.agent.actor.dispatch import ActorDispatcher, JobResult, ScanDispatcher
from fathom.agent.actor.executor import Executor
from fathom.agent.actor.listener import SignedJobListener
from fathom.agent.config import AgentConfig
from fathom.agent.reader.hasher import BackendHasher
from fathom.agent.transport.push import mtls_client
from fathom.backends import PosixBackend
from fathom.core.audit import AuditChain, AuditRecord
from fathom.core.remediation.job_queue import (
    AuditRecordPayload,
    ClaimedJob,
    ExecResultPayload,
    JobResultPayload,
)
from fathom.core.remediation.nonce_store import SqliteNonceStore
from fathom.core.remediation.signing import Ed25519Verifier, HmacVerifier, Verifier
from fathom.logging import get_logger

if TYPE_CHECKING:
    from fathom.agent.runner import AgentRunSummary
    from fathom.core.remediation.job import ScanJob

_log = get_logger("fathom.agent.actor.listen")

SecretProvider = Callable[[str], str]

POLL_PATH = "/api/v1/agents/jobs/poll"
RESULT_PATH = "/api/v1/agents/jobs/{job_id}/result"
# The listen client's read timeout must exceed core's long-poll window (≈25s) so a parked poll is
# not torn down by the client mid-wait; 60s gives comfortable headroom.
_LISTEN_TIMEOUT_SECONDS = 60.0
# Minimum length for the symmetric HMAC fallback secret — a short MAC key is cryptographically
# weak, so a misconfigured trivial secret is refused (adversarial-review fix). 32 bytes = the
# SHA-256 block-security target. Ed25519 (the default) is unaffected.
_MIN_HMAC_SECRET_BYTES = 32


class ListenStartupError(RuntimeError):
    """The listener refused to start because a write-path precondition was not met (fail-closed)."""


class _FileAuditSink:
    """Append-only JSONL act-audit sink for the agent (ADR-025 adversarial-review fix).

    The executor calls this *before* each mutation (audit-before-act) and again with the result;
    each call appends one hash-chained :class:`~fathom.core.audit.AuditRecord` as a JSON line and
    flushes it to the OS. So even if the dispatch result never reaches core (a core restart in the
    act→result window), the act is still durably recorded on the host that performed it — the
    actor's own tamper-evident log, as ADD 02 always intended. A write failure raises, which the
    executor surfaces *before* mutating, so a host that cannot persist its audit does not act.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def __call__(self, record: AuditRecord) -> None:
        line = json.dumps(
            {
                "ts": record.ts,
                "actor": record.actor,
                "action": record.action,
                "target": record.target,
                "before_state": record.before_state,
                "result": record.result,
                "prev_hash": record.prev_hash,
                "row_hash": record.row_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        # Open/append/flush per record (acts are infrequent) so each record is durable on return.
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)


def build_verifier(material: str, *, key_id: str, algorithm: str = "ed25519") -> Verifier:
    """Build the orchestrator-key verifier from resolved key material, pinned to ``algorithm``.

    The expected ``algorithm`` is configured (not auto-detected from the material's shape): for
    ``ed25519`` the material MUST be an Ed25519 public-key PEM; for ``hmac-sha256`` it is the shared
    secret (≥32 bytes). A material that does not match the configured algorithm fails loud at
    startup — there is no silent fallback that could leave a confused, broken verifier. Either way
    the verifier pins ``key_id`` and rejects a job signed under a different key id or algorithm.

    Raises:
        ListenStartupError: the material does not match ``algorithm``, or ``algorithm`` is unknown.
    """
    algo = algorithm.lower()
    if algo == "ed25519":
        try:
            public = serialization.load_pem_public_key(material.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise ListenStartupError(
                "orchestrator_pubkey_ref is not a valid PEM public key (Ed25519 expected)"
            ) from exc
        if not isinstance(public, Ed25519PublicKey):
            raise ListenStartupError(
                "orchestrator_pubkey_ref is not an Ed25519 public key (algorithm mismatch)"
            )
        return Ed25519Verifier(public, key_id=key_id)
    if algo in {"hmac", "hmac-sha256"}:
        secret = material.encode("utf-8")
        if len(secret) < _MIN_HMAC_SECRET_BYTES:
            raise ListenStartupError(
                f"HMAC orchestrator secret is too short (need ≥{_MIN_HMAC_SECRET_BYTES} bytes)"
            )
        return HmacVerifier(secret, key_id=key_id)
    raise ListenStartupError(f"unknown orchestrator signing algorithm {algorithm!r}")


def build_scan_dispatcher(
    config: AgentConfig, *, staging_path: str, operator: str
) -> ScanDispatcher:
    """Wire the default Scan Now dispatcher (ADR-025 + Scan Now): scope-check + scan-one-root-now.

    The ``scan_runner`` runs the SAME scan -> stage -> push -> finalize pipeline a scheduled run
    uses, restricted to the job's root (:func:`fathom.agent.runner.scan_one_root_now`). It builds a
    fresh control-plane adapter per scan (closed by ``run_agent``) so a full-bit Scan Now on a
    ZFS/TrueNAS host gets a real resync signal (AR-0002), and resolves remote/secret refs the same
    way a normal run does (ADR-010). Read-only: it carries no write gate, so even a write-disabled
    deployment could service scan jobs — but in practice scan jobs ride the same listen daemon,
    which itself requires the write preconditions to start.
    """
    from fathom.agent.__main__ import _build_adapter
    from fathom.agent.runner import scan_one_root_now
    from fathom.backends.remote import env_or_docker_secret_provider

    async def _run(job: ScanJob) -> AgentRunSummary:
        return await scan_one_root_now(
            config,
            root=job.root,
            mode=job.mode,
            staging_path=staging_path,
            operator=operator,
            adapter=_build_adapter(config),
            adapter_pool=config.adapter_pool,
            secret_provider=env_or_docker_secret_provider,
        )

    return ScanDispatcher(config=config, scan_runner=_run)


def build_listener_from_config(
    config: AgentConfig,
    *,
    secret_provider: SecretProvider,
    staging_path: str | None = None,
    operator: str = "fathom-agent",
) -> SignedJobListener:
    """Assemble the fail-closed :class:`SignedJobListener` from the agent config (ADR-025 §2).

    Two shapes, chosen by ``write_enabled``:

    * **scan-only** (``write_enabled=false``) — verifies + runs read-only Scan Now jobs and
      **refuses remediation jobs** (no executor, no ``quarantine_dir`` needed). This lets a host run
      Scan Now without ever arming the destructive path, and is the only shape a native Windows
      agent uses (its write path is deferred under ADR-027). The replay-nonce ledger lives next to
      the staging DB.
    * **full** (``write_enabled=true``) — additionally carries the remediation write path, so it
      requires ``quarantine_dir`` (the reversible tier + the nonce/act-audit home).

    Either shape requires ``orchestrator_pubkey_ref`` (the trusted key). Building touches no
    filesystem beyond opening the nonce ledger; a scan only runs if a scan job actually arrives.

    Raises:
        ListenStartupError: ``orchestrator_pubkey_ref`` missing/unresolvable, or
            ``write_enabled`` is set without a ``quarantine_dir``.
    """
    if not config.orchestrator_pubkey_ref:
        raise ListenStartupError("listen mode requires orchestrator_pubkey_ref (no trusted key)")
    material = secret_provider(config.orchestrator_pubkey_ref)
    if not material:
        raise ListenStartupError("orchestrator_pubkey_ref did not resolve from the secret backend")
    verifier = build_verifier(
        material,
        key_id=config.orchestrator_key_id,
        algorithm=config.orchestrator_signing_algorithm,
    )
    if staging_path is None:
        # Reuse the agent's standard OS staging path (the same default scan mode uses) so a Scan Now
        # writes to the same staging DB; resolved lazily to avoid a module-load import cycle.
        from fathom.agent.__main__ import _default_staging

        staging_path = _default_staging()
    scan_dispatcher = build_scan_dispatcher(config, staging_path=staging_path, operator=operator)

    if not config.write_enabled:
        # SCAN-ONLY: no write path. The replay-nonce ledger sits beside the (writable) staging DB
        # so a replayed scan job is still rejected (T-3) across restarts, without a quarantine dir.
        nonce_db = str(Path(staging_path).parent / ".scan-nonce-ledger.sqlite")
        return SignedJobListener(
            dispatcher=None,
            verifier=verifier,
            nonce_store=SqliteNonceStore(nonce_db),
            host_id=config.host_id,
            write_enabled=False,
            scan_dispatcher=scan_dispatcher,
        )

    # FULL (write path): the remediation executor needs the reversible quarantine tier.
    if not config.quarantine_dir:
        raise ListenStartupError(
            "listen mode with write_enabled=true requires quarantine_dir (no reversible tier)"
        )
    # Durable local act-audit: the per-item act audit is still returned to core for the durable
    # splice, but it is ALSO appended here so a lost result (core restart in the act→result window)
    # never leaves an act unrecorded on the host that performed it. Defaults INSIDE the quarantine
    # dir (strata-actor-owned, restricted) so the audit is not co-located with looser-perm dirs.
    audit_path = config.act_audit_path or str(Path(config.quarantine_dir) / ".act-audit.jsonl")
    executor = Executor(
        quarantine_dir=config.quarantine_dir,
        audit=AuditChain(sink=_FileAuditSink(audit_path)),
        write_enabled=True,
    )
    dispatcher = ActorDispatcher(executor=executor, hasher=BackendHasher(PosixBackend()))
    # Durable replay guard: the consumed-nonce ledger lives in the actor-owned quarantine dir so a
    # replayed job is still rejected (T-3) after an agent restart/crash — InMemoryNonceStore would
    # lose its set on restart, reopening the replay window. The DB-backed store is the server side.
    nonce_db = str(Path(config.quarantine_dir) / ".nonce-ledger.sqlite")
    return SignedJobListener(
        dispatcher=dispatcher,
        verifier=verifier,
        nonce_store=SqliteNonceStore(nonce_db),
        host_id=config.host_id,
        write_enabled=True,
        scan_dispatcher=scan_dispatcher,
    )


def payload_from_job_result(job_id: str, result: JobResult) -> JobResultPayload:
    """Map the actor's :class:`JobResult` to the wire :class:`JobResultPayload` for correlation."""
    return JobResultPayload(
        job_id=job_id,
        plan_id=result.plan_id,
        mode=result.mode,  # the same dry_run|execute literal the wire model validates
        drift=result.drift,
        results=[
            ExecResultPayload(
                entry_id=r.entry_id, action=r.action, status=r.status, detail=r.detail
            )
            for r in result.results
        ],
        audit=[
            AuditRecordPayload(
                ts=a.ts,
                actor=a.actor,
                action=a.action,
                target=a.target,
                before_state=a.before_state,
                result=a.result,
                prev_hash=a.prev_hash,
                row_hash=a.row_hash,
            )
            for a in result.audit
        ],
    )


async def handle_one(
    client: httpx.AsyncClient, listener: SignedJobListener, *, confirm_blast: bool = False
) -> bool:
    """Run one poll→verify→execute→post cycle. Returns ``True`` if a job was handled.

    A poll that returns 204 (no job) is a normal idle tick → ``False``. A job that fails
    verification (tampered / replayed / expired / out-of-scope) is logged and dropped without any
    FS access — core's dispatch then times out for it (fail-closed); the daemon keeps running.
    """
    resp = await client.post(POLL_PATH)
    if resp.status_code == 204:
        return False
    resp.raise_for_status()
    claimed = ClaimedJob.model_validate(resp.json())
    try:
        result = await listener.handle(claimed.signed_job, confirm_blast=confirm_blast)
    except Exception:  # verification / execution failure must not kill the daemon (fail-closed)
        _log.warning(
            "dropping a job that failed verification/execution (no FS action taken)",
            extra={"job_id": claimed.job_id},
        )
        return True
    payload = payload_from_job_result(claimed.job_id, result)
    posted = await client.post(
        RESULT_PATH.format(job_id=claimed.job_id), json=payload.model_dump(mode="json")
    )
    if posted.status_code != 200:
        _log.warning(
            "result post was not accepted",
            extra={"job_id": claimed.job_id, "status": posted.status_code},
        )
    return True


async def run_listen(
    config: AgentConfig,
    *,
    secret_provider: SecretProvider,
    client: httpx.AsyncClient | None = None,
    stop_event: asyncio.Event | None = None,
    staging_path: str | None = None,
    operator: str = "fathom-agent",
) -> None:
    """Run the listen loop until ``stop_event`` is set (or forever). Fail-closed at startup.

    Builds the fail-closed listener (raising :class:`ListenStartupError` on a missing precondition
    *before* any connection), then long-polls core over the CA-pinned mTLS client, verifying and
    executing each signed job (remediation OR Scan Now) and posting its result. ``client`` is
    injectable for tests; in production it is the agent's mTLS client (CA-pinned, presents the
    client cert). ``staging_path``/``operator`` configure where a Scan Now job stages and the
    operator recorded on its impact ack (defaulted by the listener when unset).
    """
    listener = build_listener_from_config(
        config, secret_provider=secret_provider, staging_path=staging_path, operator=operator
    )
    owns_client = client is None
    active = client or mtls_client(config, timeout=_LISTEN_TIMEOUT_SECONDS)
    _log.info(
        "agent listen mode started",
        extra={"host_id": config.host_id, "key_id": config.orchestrator_key_id},
    )
    try:
        while stop_event is None or not stop_event.is_set():
            try:
                await handle_one(active, listener)
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                # A transient transport error (core restart, network blip) is logged and retried
                # after a short backoff — the daemon must survive a core bounce, never crash.
                _log.warning("listen poll failed; backing off", extra={"error": str(exc)})
                await asyncio.sleep(2.0)
    finally:
        if owns_client:
            await active.aclose()
