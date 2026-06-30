"""Agent deployment router (ADR-026): push SSH-deploy + pull enrollment.

A separate, default-OFF route group. Every operator-facing route requires the ``DEPLOY_AGENT``
capability; the *mutating* ones (deploy, enroll-issue) additionally require fresh step-up MFA. The
data flow:

    PUSH:  POST /preflight                 (DEPLOY_AGENT) — connect + check, no change
           POST /deploy                    (DEPLOY_AGENT + FRESH MFA) — batch, returns run id
           GET  /runs/{run_id}             (DEPLOY_AGENT) — per-host status
    PULL:  POST /enroll                    (DEPLOY_AGENT + FRESH MFA) — issue one-time token + cmd
           GET  /enroll/image              (Bearer token) — stream the agent image archive
           GET  /enroll/bundle             (Bearer token) — the target redeems to fetch its bundle

The image/bundle routes carry NO human auth (the target has no session); they are gated by the
single-use, short-TTL enrollment token presented in an ``Authorization: Bearer`` header and
validated server-side (image fetch verifies without consuming; bundle redeem consumes). Operator
credentials in deploy/preflight are transient (never persisted) and arrive over the TLS session.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from typing import Annotated, Literal

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from fathom.api.auth_deps import PrincipalDep, require, require_step_up_mfa
from fathom.api.deploy_runtime import DeployRuntime, get_deploy_runtime
from fathom.api.deps import SessionDep, SettingsDep
from fathom.auth.principal import Capability
from fathom.auth.scope import ScopeFilter
from fathom.core import db
from fathom.core.audit_store import append_durable
from fathom.core.browse import BrowseResult, BrowseVolume
from fathom.core.deploy import DeploymentError
from fathom.core.deploy.bundle import (
    BundleSpec,
    RemoteTargetSpec,
    ScopeMount,
    build_agent_bundle,
    validate_host_id,
    validate_host_or_ip,
)
from fathom.core.deploy.credentials import SshCredential
from fathom.core.deploy.engine import DeployPhase, DeployRun, HostDeployRequest, HostStatus
from fathom.core.deploy.enrollment import (
    PLATFORM_LINUX,
    PLATFORM_WINDOWS,
    bootstrap_command,
    windows_powershell_bootstrap,
)
from fathom.core.deploy.winbundle import (
    WindowsBundleSpec,
    WindowsScanPath,
    build_windows_agent_bundle,
    windows_ingest_url,
)
from fathom.core.settings import Settings
from fathom.logging import get_logger

_log = get_logger("fathom.api.routers.deployment")

router = APIRouter(prefix="/api/v1/deployment", tags=["deployment"])

DeployScopeDep = Annotated[ScopeFilter, Depends(require(Capability.DEPLOY_AGENT))]

_DEFAULT_MOUNTS = (ScopeMount(container_path="/scan/data", host_path="/mnt/data", fullbit=True),)


def _v_host_id(value: str) -> str:
    try:
        return validate_host_id(value)
    except DeploymentError as exc:
        raise ValueError(str(exc)) from exc


def _v_host_or_ip(value: str) -> str:
    try:
        return validate_host_or_ip(value)
    except DeploymentError as exc:
        raise ValueError(str(exc)) from exc


def _v_host_or_ip_opt(value: str | None) -> str | None:
    # Optional fields fall back to the server-wide setting at resolve time (no shipped default).
    return None if value is None else _v_host_or_ip(value)


def _v_abs_dir(value: str) -> str:
    if not value.startswith("/") or any(c in value for c in "\n\r\0"):
        raise ValueError(f"remote_dir must be an absolute path: {value!r}")
    if ".." in value.split("/"):  # no traversal — it is sudo-mkdir'd + chowned on the target (r7)
        raise ValueError(f"remote_dir must not contain '..': {value!r}")
    return value


def _v_core_base_url(value: str) -> str:
    """Validate the pull bootstrap's core URL and **rebuild** it from parsed, validated parts.

    ``core_base_url`` is interpolated into the bootstrap shell command the operator pastes (often as
    root) on the target, so it must not carry shell metacharacters or a path/query that smuggles in
    an extra URL (round-2 P1). Returning a URL reconstructed from only ``scheme://host[:port]`` —
    with the host charset-validated and the port numeric — drops any injected path/userinfo/quote.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(value)
        port = parsed.port  # raises ValueError on a non-numeric port
    except ValueError as exc:
        raise ValueError(f"invalid core_base_url: {exc}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("core_base_url must be http:// or https://")
    host = parsed.hostname
    if not host:
        raise ValueError("core_base_url must include a host")
    try:
        validate_host_or_ip(host)
    except DeploymentError as exc:
        raise ValueError(str(exc)) from exc
    host_part = f"[{host}]" if ":" in host else host  # bracket IPv6 literals
    netloc = host_part if port is None else f"{host_part}:{port}"
    return f"{parsed.scheme}://{netloc}"


def _v_core_base_url_opt(value: str | None) -> str | None:
    # Optional field: falls back to the server-wide setting at resolve time (no shipped default).
    return None if value is None else _v_core_base_url(value)


def _resolve_proxy_host_ip(settings: Settings, value: str | None) -> str:
    """The request's value, else ``FATHOM_AGENT_DEPLOYMENT_PROXY_HOST_IP`` — one is required.

    The proxy address is deployment-specific (the IP/hostname targets map ``proxy`` to), so the
    product ships no default; the settings fallback is re-validated because it bypasses the
    request-schema validator and is interpolated into a remote shell test + compose extra_hosts.
    """
    resolved = value or settings.agent_deployment_proxy_host_ip
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="proxy_host_ip is required — pass it in the request or set "
            "FATHOM_AGENT_DEPLOYMENT_PROXY_HOST_IP",
        )
    try:
        return validate_host_or_ip(resolved)
    except DeploymentError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc


def _resolve_core_base_url(settings: Settings, value: str | None) -> str:
    """The request's value, else ``FATHOM_AGENT_DEPLOYMENT_CORE_BASE_URL`` — one is required."""
    resolved = value or settings.agent_deployment_core_base_url
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="core_base_url is required — pass it in the request or set "
            "FATHOM_AGENT_DEPLOYMENT_CORE_BASE_URL",
        )
    try:
        return _v_core_base_url(resolved)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc


def _require_global(scope: ScopeFilter) -> None:
    """Deploy/enrol acts on hosts not yet in any scope, so it is a global-only capability.

    A host/volume-scoped ``deploy_agent`` grant cannot be proven to cover a brand-new target, so it
    is refused rather than silently treated as estate-wide (fail-closed; round-1 F-3). Today only
    the global admin role holds the capability, so this is defence-in-depth for a future grant.
    """
    if not scope.is_global:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="deploy_agent requires a global-scope grant",
        )


# --------------------------------------------------------------------------- request/response


class ScopeMountIn(BaseModel):
    """One scanned tree (agent path ← host path)."""

    container_path: str = Field(min_length=1)
    host_path: str = Field(min_length=1)
    fullbit: bool = True

    def to_domain(self) -> ScopeMount:
        return ScopeMount(
            container_path=self.container_path, host_path=self.host_path, fullbit=self.fullbit
        )


class SshCredentialIn(BaseModel):
    """Transient SSH login material (never persisted; redacted in domain repr)."""

    username: str = Field(min_length=1)
    private_key: str | None = None
    passphrase: str | None = None
    certificate: str | None = None
    password: str | None = None
    sudo_password: str | None = None

    def to_domain(self) -> SshCredential:
        cred = SshCredential(
            username=self.username,
            private_key=self.private_key,
            passphrase=self.passphrase,
            certificate=self.certificate,
            password=self.password,
            sudo_password=self.sudo_password,
        )
        try:
            cred.validate()
        except DeploymentError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
        return cred


class PreflightRequest(BaseModel):
    target: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    credential: SshCredentialIn
    proxy_host_ip: str | None = Field(default=None)
    expected_host_key: str | None = None

    _ck_target = field_validator("target")(_v_host_or_ip)
    _ck_proxy = field_validator("proxy_host_ip")(_v_host_or_ip_opt)


class PreflightOut(BaseModel):
    target: str
    ok: bool
    reachable: bool
    docker_present: bool
    proxy_reachable: bool
    host_key_fingerprint: str
    notes: list[str]


class DeployBrowseRequest(PreflightRequest):
    """Live browse on a not-yet-enrolled target (ADR-034 Phase 2): preflight conn + a path."""

    path: str = Field(min_length=1, max_length=4096)
    with_sizes: bool = True


class RemoteTargetIn(BaseModel):
    """A remote scan target (rclone/SMB/SFTP) to generate into the agent bundle (ADR-029).

    A thin wire model; the safety validation lives in :class:`RemoteTargetSpec` (mapped to a 422),
    and the agent re-validates the rendered config. Credentials are references only (ADR-010).
    """

    protocol: Literal["rclone", "smb", "sftp"]
    host: str = Field(min_length=1, max_length=255)
    remote_path: str = Field(default="/", min_length=1, max_length=4096)
    share: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    password_ref: str | None = Field(default=None, max_length=128)
    private_key_ref: str | None = Field(default=None, max_length=128)
    verify: bool = True
    lab_insecure: bool = False

    def to_domain(self) -> RemoteTargetSpec:
        return RemoteTargetSpec(
            protocol=self.protocol,
            host=self.host,
            remote_path=self.remote_path,
            share=self.share,
            port=self.port,
            username=self.username,
            password_ref=self.password_ref,
            private_key_ref=self.private_key_ref,
            verify=self.verify,
            lab_insecure=self.lab_insecure,
        )


class DeployHostIn(BaseModel):
    target: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    host_id: str = Field(min_length=1)
    credential: SshCredentialIn
    mounts: list[ScopeMountIn] = Field(default_factory=list)
    remote_targets: list[RemoteTargetIn] = Field(default_factory=list, max_length=64)
    proxy_host_ip: str | None = Field(default=None)
    expected_host_key: str | None = None
    remote_dir: str = Field(default="/opt/fathom-agent")

    _ck_target = field_validator("target")(_v_host_or_ip)
    _ck_host_id = field_validator("host_id")(_v_host_id)
    _ck_proxy = field_validator("proxy_host_ip")(_v_host_or_ip_opt)
    _ck_remote_dir = field_validator("remote_dir")(_v_abs_dir)

    @model_validator(mode="after")
    def _password_requires_pinned_host_key(self) -> DeployHostIn:
        # Password auth sends the password during the SSH handshake; without a pinned host key it
        # would reach an unverified host (threat-model T-1 / round-1 F-1). Force preflight + pin
        # first. Key auth is exempt — it proves identity with a challenge-bound signature, so no
        # secret leaks to a wrong host (and no command runs there: connect aborts on key mismatch).
        if self.credential.password is not None and not self.expected_host_key:
            raise ValueError(
                "password SSH auth requires a pinned host key — preflight the target and pin its "
                "key before deploying"
            )
        return self


class DeployRequest(BaseModel):
    hosts: list[DeployHostIn] = Field(min_length=1, max_length=64)


class HostStatusOut(BaseModel):
    host_id: str
    target: str
    phase: str
    detail: str
    fingerprint: str | None
    host_key: str | None


class DeployRunOut(BaseModel):
    run_id: str
    created_by: str
    complete: bool
    hosts: list[HostStatusOut]


class EnrollRequest(BaseModel):
    host_id: str = Field(min_length=1)
    # platform selects the bundle/bootstrap shape: "linux" (Docker, default) or "windows"
    # (native W1 agent — ADR-027). The Windows path uses windows_scan_paths instead of mounts.
    platform: Literal["linux", "windows"] = PLATFORM_LINUX
    mounts: list[ScopeMountIn] = Field(default_factory=list)
    remote_targets: list[RemoteTargetIn] = Field(default_factory=list, max_length=64)
    windows_scan_paths: list[str] = Field(default_factory=list)
    # Subset of windows_scan_paths to content-hash (ADR-027 W2 full-bit; local-only, never
    # hydrates cloud placeholders). Empty = metadata-only, the safe default for an unknown drive.
    windows_fullbit_paths: list[str] = Field(default_factory=list)
    proxy_host_ip: str | None = Field(default=None)
    core_base_url: str | None = Field(default=None)

    _ck_host_id = field_validator("host_id")(_v_host_id)
    _ck_proxy = field_validator("proxy_host_ip")(_v_host_or_ip_opt)
    _ck_core = field_validator("core_base_url")(_v_core_base_url_opt)

    @model_validator(mode="after")
    def _windows_requires_scan_paths(self) -> EnrollRequest:
        if self.platform == PLATFORM_WINDOWS and not self.windows_scan_paths:
            raise ValueError("windows enrollment requires at least one windows_scan_paths entry")
        extra = set(self.windows_fullbit_paths) - set(self.windows_scan_paths)
        if extra:
            raise ValueError(
                "windows_fullbit_paths must be a subset of windows_scan_paths "
                f"(stray: {sorted(extra)})"
            )
        return self


class EnrollOut(BaseModel):
    host_id: str
    token: str
    command: str
    expires_at: str


# --------------------------------------------------------------------------- helpers


def _spec(
    settings: Settings,
    *,
    host_id: str,
    mounts: list[ScopeMountIn],
    proxy_host_ip: str,
    remote_targets: list[RemoteTargetIn] | None = None,
) -> BundleSpec:
    try:
        resolved = tuple(m.to_domain() for m in mounts)
        # to_domain() builds a RemoteTargetSpec, whose __post_init__ raises DeploymentError on an
        # unsafe value — inside the try so it maps to a 422, not an unhandled 500.
        rts = tuple(t.to_domain() for t in (remote_targets or ()))
        # Only inject the default local mount when there's nothing to scan at all — a remote-only
        # agent (remote_targets, no local mounts) is legitimate (ADR-029) and gets an empty scope.
        if not resolved and not rts:
            resolved = _DEFAULT_MOUNTS
        return BundleSpec(
            host_id=host_id,
            ingest_url=settings.agent_deployment_ingest_url,
            image=settings.agent_deployment_image,
            mounts=resolved,
            remote_targets=rts,
            proxy_host_ip=proxy_host_ip,
        )
    except DeploymentError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc


def _windows_spec(
    settings: Settings,
    *,
    host_id: str,
    scan_paths: list[str],
    fullbit_paths: list[str],
    proxy_host_ip: str,
) -> WindowsBundleSpec:
    """Build the native Windows bundle spec; map DeploymentError to a 422 (ADR-027)."""
    fullbit = set(fullbit_paths)
    try:
        return WindowsBundleSpec(
            host_id=host_id,
            # The native agent has no compose extra_hosts → dial the proxy by IP (cert SAN must
            # include it). Scheme/port/path come from the configured ingest_url.
            ingest_url=windows_ingest_url(settings.agent_deployment_ingest_url, proxy_host_ip),
            proxy_host_ip=proxy_host_ip,
            scan_paths=tuple(WindowsScanPath(path=p, fullbit=p in fullbit) for p in scan_paths),
        )
    except DeploymentError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc


def _status_out(host: HostStatus) -> HostStatusOut:
    return HostStatusOut(
        host_id=host.host_id,
        target=host.target,
        phase=host.phase.value,
        detail=host.detail,
        fingerprint=host.fingerprint,
        host_key=host.host_key,
    )


async def _deploy_and_audit(
    runtime: DeployRuntime, run: DeployRun, requests: list[HostDeployRequest], *, created_by: str
) -> None:
    """Run the batch, then splice each host's terminal outcome onto the durable audit chain.

    The deploy runs in a background task — the request's DB session is long gone — so a fresh
    session is opened to record the per-host result on the hash-chained audit. That is the durable
    deploy *history* (it survives an api restart), beyond the ephemeral in-memory run status. The
    record runs in ``finally`` so a result is logged even if the batch raised unexpectedly.
    """
    try:
        await runtime.engine.deploy_batch(run, requests)
    finally:
        # append_durable (not the session-staging chain) because this runs in a *background* task
        # that races the request's deployment.initiated append on the shared hash chain — it
        # reloads the head + retries on a UNIQUE prev_hash collision instead of failing (round-1).
        async with db.session_scope() as session:
            for host in run.hosts:
                await append_durable(
                    session,
                    actor=created_by,
                    action="deployment.host.result",
                    target=host.host_id,
                    before_state={
                        "target": host.target,
                        "fingerprint": host.fingerprint,
                        "detail": host.detail,
                    },
                    result=host.phase.value,
                )


def _run_out(runtime_run: DeployRun) -> DeployRunOut:
    return DeployRunOut(
        run_id=runtime_run.run_id,
        created_by=runtime_run.created_by,
        complete=runtime_run.complete,
        hosts=[_status_out(h) for h in runtime_run.hosts],
    )


# --------------------------------------------------------------------------- routes


@router.post("/preflight", response_model=PreflightOut)
async def preflight_route(
    body: PreflightRequest, scope: DeployScopeDep, settings: SettingsDep, request: Request
) -> PreflightOut:
    """Connect to one target and check Docker + proxy reachability (no change made)."""
    _require_global(scope)
    runtime = get_deploy_runtime(request)
    report = await runtime.engine.preflight(
        body.target,
        body.port,
        body.credential.to_domain(),
        proxy_host_ip=_resolve_proxy_host_ip(settings, body.proxy_host_ip),
        expected_host_key=body.expected_host_key,
    )
    return PreflightOut(
        target=report.target,
        ok=report.ok,
        reachable=report.reachable,
        docker_present=report.docker_present,
        proxy_reachable=report.proxy_reachable,
        host_key_fingerprint=report.host_key_fingerprint,
        notes=list(report.notes),
    )


@router.post("/probe-volumes", response_model=list[BrowseVolume])
async def probe_volumes_route(
    body: PreflightRequest,
    scope: DeployScopeDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
    request: Request,
) -> list[BrowseVolume]:
    """List a target's mounted volumes via ``df`` (the Deploy df-style dropdown; read-only).

    DEPLOY_AGENT + a fresh per-request step-up MFA — it opens an SSH session to the target.
    """
    _require_global(scope)
    runtime = get_deploy_runtime(request)
    return await runtime.engine.probe_volumes(
        body.target,
        body.port,
        body.credential.to_domain(),
        expected_host_key=body.expected_host_key,
    )


@router.post("/browse", response_model=BrowseResult)
async def deploy_browse_route(
    body: DeployBrowseRequest,
    scope: DeployScopeDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
    request: Request,
) -> BrowseResult:
    """List one directory on a not-yet-enrolled target over SSH (ADR-034 Phase 2; read-only).

    DEPLOY_AGENT + a fresh per-request step-up MFA. Metadata only (never file contents); optional
    bounded per-child subtree size. Lets the Deploy wizard pick scan roots/excludes before enrol.
    """
    _require_global(scope)
    runtime = get_deploy_runtime(request)
    return await runtime.engine.browse_directory(
        body.target,
        body.port,
        body.credential.to_domain(),
        path=body.path,
        with_sizes=body.with_sizes,
        expected_host_key=body.expected_host_key,
    )


@router.post("/deploy", response_model=DeployRunOut, status_code=status.HTTP_202_ACCEPTED)
async def deploy_route(
    body: DeployRequest,
    scope: DeployScopeDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
    principal: PrincipalDep,
    settings: SettingsDep,
    request: Request,
) -> DeployRunOut:
    """Start a batch push-deploy (DEPLOY_AGENT + fresh MFA); returns the run to poll."""
    _require_global(scope)
    runtime = get_deploy_runtime(request)
    requests: list[HostDeployRequest] = []
    statuses: list[HostStatus] = []
    for host in body.hosts:
        spec = _spec(
            settings,
            host_id=host.host_id,
            mounts=host.mounts,
            remote_targets=host.remote_targets,
            proxy_host_ip=_resolve_proxy_host_ip(settings, host.proxy_host_ip),
        )
        requests.append(
            HostDeployRequest(
                target=host.target,
                port=host.port,
                credential=host.credential.to_domain(),
                spec=spec,
                expected_host_key=host.expected_host_key,
                remote_dir=host.remote_dir,
            )
        )
        statuses.append(
            HostStatus(host_id=host.host_id, target=host.target, phase=DeployPhase.PENDING)
        )
    run = runtime.runs.create(created_by=principal.subject, hosts=statuses)
    # Audit-before-act: record who is deploying what, COMMITTED before the background task starts
    # (AR-0012). Its own session_scope (not the request session, whose commit is post-yield and
    # un-retried) so the background host.result append chains off a committed head — never racing
    # the request commit on the shared hash chain (round-2 P2; round-1 first found the race).
    async with db.session_scope() as init_session:
        await append_durable(
            init_session,
            actor=principal.subject,
            action="deployment.initiated",
            target=run.run_id,
            before_state={
                "hosts": [{"host_id": h.host_id, "target": h.target} for h in body.hosts]
            },
            result="queued",
        )
    runtime.schedule(_deploy_and_audit(runtime, run, requests, created_by=principal.subject))
    _log.info(
        "deploy run scheduled",
        extra={"run_id": run.run_id, "hosts": len(requests), "by": principal.subject},
    )
    return _run_out(run)


@router.get("/runs/{run_id}", response_model=DeployRunOut)
async def run_status_route(run_id: str, scope: DeployScopeDep, request: Request) -> DeployRunOut:
    """Return the live per-host status of a deploy run."""
    _require_global(scope)
    runtime = get_deploy_runtime(request)
    run = runtime.runs.get(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="deploy run not found")
    return _run_out(run)


@router.post("/enroll", response_model=EnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll_route(
    body: EnrollRequest,
    scope: DeployScopeDep,
    _mfa: Annotated[None, Depends(require_step_up_mfa)],
    principal: PrincipalDep,
    session: SessionDep,
    settings: SettingsDep,
    request: Request,
) -> EnrollOut:
    """Issue a one-time pull-enrollment token + the bootstrap command (DEPLOY_AGENT + fresh MFA)."""
    _require_global(scope)
    runtime = get_deploy_runtime(request)
    proxy_host_ip = _resolve_proxy_host_ip(settings, body.proxy_host_ip)
    core_base_url = _resolve_core_base_url(settings, body.core_base_url)
    if core_base_url.startswith("http://"):
        # The bootstrap fetches the bundle (which carries the agent's private key) and sends the
        # one-time token over this URL — cleartext http exposes both to an active MITM (T-2). The
        # transport is the operator's to secure; surface it loudly rather than failing (localhost
        # http is a legitimate single-host case). Front core with https for any real deployment.
        _log.warning(
            "enroll core_base_url is http — bundle (agent private key) + token transit in "
            "cleartext; front core with https (threat-model T-2)",
            extra={"host_id": body.host_id, "platform": body.platform},
        )

    spec: BundleSpec | WindowsBundleSpec
    if body.platform == PLATFORM_WINDOWS:
        spec = _windows_spec(
            settings,
            host_id=body.host_id,
            scan_paths=body.windows_scan_paths,
            fullbit_paths=body.windows_fullbit_paths,
            proxy_host_ip=proxy_host_ip,
        )
    else:
        spec = _spec(
            settings,
            host_id=body.host_id,
            mounts=body.mounts,
            remote_targets=body.remote_targets,
            proxy_host_ip=proxy_host_ip,
        )

    try:
        token, expires = runtime.enrollment.issue(body.host_id, spec, platform=body.platform)
    except DeploymentError as exc:
        # The pending-token cap is back-pressure, not a malformed request: surface it as 429 with
        # the registry's retry hint (the _spec/_windows_spec validation errors above map to 422).
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    if isinstance(spec, WindowsBundleSpec):
        command = windows_powershell_bootstrap(core_base_url, token, install_dir=spec.install_dir)
    else:
        serve_image = bool(settings.agent_deployment_image_archive_path)
        command = bootstrap_command(core_base_url, token, image=spec.image, serve_image=serve_image)
    await append_durable(
        session,
        actor=principal.subject,
        action="deployment.enroll.issued",
        target=body.host_id,
        before_state={"expires_at": expires.isoformat(), "platform": body.platform},
        result="issued",
    )
    _log.info(
        "enroll token issued",
        extra={"host_id": body.host_id, "by": principal.subject, "platform": body.platform},
    )
    return EnrollOut(
        host_id=body.host_id,
        token=token,
        command=command,
        expires_at=expires.isoformat(),
    )


def _bearer_token(request: Request) -> str:
    """Extract the enrollment token from the ``Authorization: Bearer`` header (round-1 F-2).

    Carrying the token in a header rather than the URL path keeps it out of reverse-proxy / uvicorn
    access logs, shell history and ``Referer``. 403 (not 401) if absent/malformed — the deploy
    surface never advertises an auth challenge to anonymous callers.
    """
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="missing enrollment token"
        )
    return token.strip()


@router.get("/enroll/image")
async def enroll_image_route(request: Request) -> FileResponse:
    """Stream the agent image archive for a *live* (non-consumed) enrollment token.

    The image is not secret, so this does not spend the token (the bundle fetch does); but a live
    token is still required so the multi-hundred-MB transfer is not an open endpoint. 404 if no
    archive is configured. The bootstrap calls this only when the image is absent on the target.
    """
    token = _bearer_token(request)
    runtime = get_deploy_runtime(request)
    # Validate the token BEFORE touching the filesystem so an invalid token always 403s and cannot
    # probe whether an archive is configured (404-vs-403 oracle) or trigger a pre-auth stat (P3).
    try:
        runtime.enrollment.verify(token)  # live-token gate (does NOT consume)
    except DeploymentError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    settings: Settings = request.app.state.settings
    archive = settings.agent_deployment_image_archive_path
    if not archive or not await anyio.Path(archive).is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no agent image archive configured"
        )
    return FileResponse(archive, media_type="application/gzip", filename="fathom-agent-image.tgz")


@router.get("/enroll/bundle")
async def enroll_bundle_route(request: Request) -> Response:
    """Redeem a one-time enrollment token and return the agent bundle.

    Linux grants get a gzip tarball; Windows grants get a zip (PowerShell ``Expand-Archive``;
    Server 2016 has no ``tar.exe``). Token-only auth via the ``Authorization: Bearer`` header
    (the target has no session): a single-use, short-TTL token validated server-side. Mints the
    agent cert + renders the platform-appropriate bundle.
    """
    token = _bearer_token(request)
    runtime = get_deploy_runtime(request)
    try:
        grant = runtime.enrollment.redeem(token)
    except DeploymentError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    minted = runtime.ca.mint_client_cert(
        f"{grant.spec.host_id}-agent",
        days=request.app.state.settings.agent_deployment_cert_days,
    )
    if isinstance(grant.spec, WindowsBundleSpec):
        bundle = build_windows_agent_bundle(grant.spec, minted)
        body_bytes = _zip(bundle.files)
        media_type, filename = "application/zip", "fathomline-bundle.zip"
    else:
        bundle = build_agent_bundle(grant.spec, minted)
        body_bytes = _tar_gz(bundle.files)
        media_type, filename = "application/gzip", "fathom-bundle.tgz"
    # Durable record that a minted identity was handed out (threat-model R-1): the redeem has no
    # human session, so the actor is the enrolling host. Records the cert fingerprint that was
    # issued, so a later "which key is this host?" is answerable from the audit chain.
    async with db.session_scope() as session:
        await append_durable(
            session,
            actor=f"enroll:{grant.spec.host_id}",
            action="deployment.enroll.redeemed",
            target=grant.spec.host_id,
            before_state={"fingerprint": minted.fingerprint_sha1},
            result="bundle_served",
        )
    _log.info(
        "enroll bundle served",
        extra={"host_id": grant.spec.host_id, "platform": grant.platform},
    )
    return Response(
        content=body_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _tar_gz(files: dict[str, bytes]) -> bytes:
    """Pack ``path -> bytes`` into a deterministic gzip tarball (client.key at 0600)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in sorted(files.items()):
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            info.mode = 0o600 if path.endswith("client.key") else 0o644
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _zip(files: dict[str, bytes]) -> bytes:
    """Pack ``path -> bytes`` into a deterministic zip (Windows bundle; PowerShell Expand-Archive).

    POSIX file modes do not carry to Windows, so client.key is protected by NTFS ACLs rather than a
    stored mode. The protection is *enforced*, not assumed: the PowerShell bootstrap locks the
    install dir to SYSTEM + Administrators (icacls /inheritance:r) before the bundle is extracted
    into it and again afterwards (see ``windows_powershell_bootstrap``).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in sorted(files.items()):
            # Fixed timestamp → byte-deterministic archive (no Date.now in the build).
            info = zipfile.ZipInfo(filename=path, date_time=(1980, 1, 1, 0, 0, 0))
            zf.writestr(info, content)
    return buf.getvalue()
