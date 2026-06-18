"""Agent-deployment runtime wiring (ADR-026, ADR-010).

Mirrors the remediation runtime: a default-OFF, fail-loud, injectable handle the routes read from
``app.state.deploy_runtime``. It exists **only when** ``agent_deployment_enabled`` is on AND the CA
material is provisioned by reference; otherwise it stays unset and :func:`get_deploy_runtime` 503s
— no half-armed deploy surface. The CA material (cert + signing key) is resolved at runtime via the
secret provider, never embedded.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, Request, status

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.certs import CertificateAuthority
from fathom.core.deploy.engine import DeployEngine, DeployRunRegistry
from fathom.core.deploy.enrollment import EnrollmentRegistry
from fathom.core.deploy.ssh import AsyncSshConnector, SshConnector
from fathom.logging import get_logger

if TYPE_CHECKING:
    from fathom.core.settings import Settings

_log = get_logger("fathom.api.deploy_runtime")

SecretProvider = Callable[[str], str]


class DeploymentProvisioningError(RuntimeError):
    """CA material was configured but could not be loaded (fail-loud at startup, not silent)."""


@dataclass
class DeployRuntime:
    """The injectable collaborators for the deploy surface (engine + registries + CA).

    NOTE (single-worker): ``runs`` and ``enrollment`` are **per-process in-memory** registries, like
    ADR-025's dispatch queue. Core MUST run a single worker — with >1 worker the registries diverge
    and enroll-redeem / run-status silently break across workers (ADR-026 §Single-worker, round-5).
    """

    ca: CertificateAuthority
    engine: DeployEngine
    runs: DeployRunRegistry
    enrollment: EnrollmentRegistry
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)

    def schedule(self, coro: Coroutine[Any, Any, None]) -> None:
        """Run a background deploy task, holding a strong reference until it finishes."""
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task[None]) -> None:
        """Drop the task reference and surface any orchestration-level fault (round 1, P3).

        Per-host failures are caught inside ``deploy_one`` and never raise; this only fires if the
        batch/audit orchestration itself dies (e.g. the durable-audit session fails), which would
        otherwise be a silent "Task exception was never retrieved" on GC.
        """
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            _log.error("background deploy task failed", extra={"error": str(task.exception())})

    async def drain(self, *, timeout_s: float = 30.0) -> None:
        """Await in-flight deploy tasks at shutdown, cancelling stragglers (round-5 F2).

        Called from the app lifespan teardown *before* the DB engine is disposed, so a deploy's
        terminal ``deployment.host.result`` audit lands rather than racing ``dispose_engine`` (which
        would otherwise re-init the engine from the task's ``finally`` — a use-after-dispose leak).
        """
        if not self._tasks:
            return
        _done, pending = await asyncio.wait(set(self._tasks), timeout=timeout_s)
        for task in pending:
            task.cancel()
        if pending:
            _log.warning("cancelled in-flight deploy tasks at shutdown", extra={"n": len(pending)})
            # Await the cancellations so each task's ``finally`` (its terminal host.result audit)
            # runs to completion before the caller disposes the DB engine (round-9).
            await asyncio.gather(*pending, return_exceptions=True)


def build_deploy_runtime(
    settings: Settings,
    *,
    secret_provider: SecretProvider | None = None,
    connector: SshConnector | None = None,
) -> DeployRuntime | None:
    """Assemble the deploy runtime, or ``None`` to preserve default-OFF (ADR-026).

    Returns a :class:`DeployRuntime` only when ``agent_deployment_enabled`` is on AND both CA refs
    resolve to valid PEM material. With deployment disabled, or enabled-but-no-CA, returns ``None``.
    A ref that is set but resolves to invalid material raises :class:`DeploymentProvisioningError`
    (fail loud at startup).
    """
    if not settings.agent_deployment_enabled:
        return None
    cert_ref = settings.agent_deployment_ca_cert_ref
    key_ref = settings.agent_deployment_ca_key_ref
    if not cert_ref or not key_ref:
        _log.warning(
            "agent_deployment_enabled but CA refs not provisioned — deploy surface stays 503 "
            "(set agent_deployment_ca_cert_ref + agent_deployment_ca_key_ref to arm it)"
        )
        return None
    from fathom.backends.remote import env_or_docker_secret_provider

    provider = secret_provider or env_or_docker_secret_provider
    try:
        cert_pem = provider(cert_ref)
        key_pem = provider(key_ref)
    except Exception as exc:  # any resolver failure is a fail-loud provisioning error
        raise DeploymentProvisioningError(
            "agent deployment CA reference did not resolve from the secret backend"
        ) from exc
    if not cert_pem or not key_pem:
        raise DeploymentProvisioningError(
            "agent deployment CA reference resolved to an empty value"
        )
    try:
        ca = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem)
    except DeploymentError as exc:
        raise DeploymentProvisioningError(str(exc)) from exc
    engine = DeployEngine(
        connector=connector or AsyncSshConnector(),
        ca=ca,
        cert_days=settings.agent_deployment_cert_days,
        max_concurrent=settings.agent_deployment_max_concurrent,
        image_archive_path=settings.agent_deployment_image_archive_path,
    )
    _log.info("agent deployment runtime provisioned (assumes single-worker core — ADR-026)")
    return DeployRuntime(
        ca=ca,
        engine=engine,
        runs=DeployRunRegistry(),
        enrollment=EnrollmentRegistry(ttl_seconds=settings.agent_deployment_enroll_ttl_seconds),
    )


def get_deploy_runtime(request: Request) -> DeployRuntime:
    """Return the configured runtime, or 503 if the deploy surface is not provisioned (default)."""
    runtime = getattr(request.app.state, "deploy_runtime", None)
    if not isinstance(runtime, DeployRuntime):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent deployment runtime not provisioned (disabled or no CA material)",
        )
    return runtime
