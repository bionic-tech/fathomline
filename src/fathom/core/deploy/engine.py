"""Push-deploy orchestration + batch run tracking (ADR-026 §Mode A).

:class:`DeployEngine` drives one host through ``connect → preflight → mint → upload → start →
verify``, mutating a :class:`HostStatus` as it goes; :meth:`DeployEngine.deploy_batch` fans a
:class:`DeployRun` out over many hosts with bounded concurrency. A single host's failure is caught
and recorded as ``FAILED`` — it never aborts the batch or raises out. Run state lives in an
in-memory :class:`DeployRunRegistry` (core is single-worker), and every phase transition is the
caller's to audit.
"""

from __future__ import annotations

import asyncio
import posixpath
import secrets
import shlex
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from fathom.core.browse import BrowseEntry, BrowseResult, BrowseVolume
from fathom.core.deploy import DeploymentError
from fathom.core.deploy.bundle import BundleSpec, build_agent_bundle, validate_host_or_ip
from fathom.core.deploy.certs import CertificateAuthority
from fathom.core.deploy.credentials import SshCredential
from fathom.core.deploy.ssh import SshClient, SshConnector
from fathom.logging import get_logger

_log = get_logger("fathom.core.deploy.engine")


class DeployPhase(StrEnum):
    """Where a single host's deploy has reached (terminal: ``succeeded`` / ``failed``)."""

    PENDING = "pending"
    CONNECTING = "connecting"
    PREFLIGHT = "preflight"
    MINTING = "minting"
    UPLOADING = "uploading"
    LOADING_IMAGE = "loading_image"
    STARTING = "starting"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


_TERMINAL = {DeployPhase.SUCCEEDED, DeployPhase.FAILED}


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Read-only reachability check before any change is made to the target."""

    target: str
    reachable: bool
    docker_present: bool
    proxy_reachable: bool
    host_key_fingerprint: str
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.reachable and self.docker_present and self.proxy_reachable


@dataclass(slots=True)
class HostStatus:
    """Live, mutable status for one host within a run."""

    host_id: str
    target: str
    phase: DeployPhase = DeployPhase.PENDING
    detail: str = ""
    fingerprint: str | None = None  # the minted agent cert's SHA-1 (its Fathom identity)
    host_key: str | None = None  # the target's SSH host-key fingerprint (TOFU record)

    @property
    def done(self) -> bool:
        return self.phase in _TERMINAL


@dataclass(slots=True)
class DeployRun:
    """A batch deploy: a set of per-host statuses plus run metadata."""

    run_id: str
    created_by: str
    created_at: datetime
    hosts: list[HostStatus] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return all(h.done for h in self.hosts)


@dataclass(frozen=True, slots=True)
class HostDeployRequest:
    """One host's full deploy input (target + transient credential + what to install)."""

    target: str
    port: int
    credential: SshCredential
    spec: BundleSpec
    expected_host_key: str | None = None
    remote_dir: str = "/opt/fathom-agent"


class DeployRunRegistry:
    """In-memory registry of deploy runs (status is ephemeral; a lost run is re-issuable).

    Bounded to ``max_runs`` (FIFO eviction of the oldest) so a long-lived single-worker core cannot
    accumulate run state without limit (threat-model D-3). Durable history is on the audit chain;
    this registry only serves the *live* status poll, so evicting old completed runs is safe.
    """

    def __init__(self, *, max_runs: int = 200, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or (lambda: datetime.now(tz=UTC))
        self._max_runs = max_runs
        self._runs: OrderedDict[str, DeployRun] = OrderedDict()

    def create(self, *, created_by: str, hosts: list[HostStatus]) -> DeployRun:
        run = DeployRun(
            run_id=f"deploy-{secrets.token_hex(8)}",
            created_by=created_by,
            created_at=self._now(),
            hosts=hosts,
        )
        self._runs[run.run_id] = run
        # Evict the oldest *complete* run when over cap — never an in-flight one, or a live status
        # poll would 404 and (the frontend) loop forever (round 1, P3). If nothing is complete yet
        # we briefly exceed the cap rather than drop a running deploy.
        while len(self._runs) > self._max_runs:
            victim = next((rid for rid, r in self._runs.items() if r.complete), None)
            if victim is None:
                break
            del self._runs[victim]
        return run

    def get(self, run_id: str) -> DeployRun | None:
        return self._runs.get(run_id)


class DeployEngine:
    """Drives push deploys over an injected SSH connector + :class:`CertificateAuthority`."""

    def __init__(
        self,
        *,
        connector: SshConnector,
        ca: CertificateAuthority,
        cert_days: int,
        max_concurrent: int = 3,
        image_archive_path: str | None = None,
    ) -> None:
        self._connector = connector
        self._ca = ca
        self._cert_days = cert_days
        self._image_archive_path = image_archive_path
        self._sema = asyncio.Semaphore(max_concurrent)

    async def preflight(
        self,
        target: str,
        port: int,
        credential: SshCredential,
        *,
        proxy_host_ip: str,
        proxy_port: int = 9443,
        expected_host_key: str | None = None,
    ) -> PreflightReport:
        """Connect and check Docker presence + proxy reachability without changing anything."""
        credential.validate()
        validate_host_or_ip(proxy_host_ip)  # it lands in a remote shell test — no metacharacters
        try:
            client = await self._connector.connect(
                target, port, credential, expected_host_key=expected_host_key
            )
        except DeploymentError as exc:
            return PreflightReport(
                target=target,
                reachable=False,
                docker_present=False,
                proxy_reachable=False,
                host_key_fingerprint="",
                notes=(str(exc),),
            )
        try:
            docker = await client.run("docker --version")
            proxy = await client.run(f"timeout 5 bash -c '</dev/tcp/{proxy_host_ip}/{proxy_port}'")
            notes: list[str] = []
            if not docker.ok:
                notes.append("docker not found on target")
            if not proxy.ok:
                notes.append(f"target cannot reach proxy {proxy_host_ip}:{proxy_port}")
            return PreflightReport(
                target=target,
                reachable=True,
                docker_present=docker.ok,
                proxy_reachable=proxy.ok,
                host_key_fingerprint=client.host_key_fingerprint,
                notes=tuple(notes),
            )
        finally:
            await client.close()

    async def browse_directory(
        self,
        target: str,
        port: int,
        credential: SshCredential,
        *,
        path: str,
        with_sizes: bool = True,
        max_entries: int = 2000,
        size_budget_seconds: int = 5,
        expected_host_key: str | None = None,
    ) -> BrowseResult:
        """List one directory on a (not-yet-enrolled) target over SSH (ADR-034 Phase 2) — read-only.

        Metadata only (type, size, mtime, name) via a single ``find -printf``; optional BOUNDED
        per-child subtree size via one ``timeout … du -b -d 1`` (so a slow tree can't hang the
        request). Never reads file contents. The operator path is shell-quoted (no injection).
        """
        credential.validate()
        rid = "deploy-browse"
        q = shlex.quote(path)
        try:
            client = await self._connector.connect(
                target, port, credential, expected_host_key=expected_host_key
            )
        except DeploymentError as exc:
            return BrowseResult(request_id=rid, path=path, error=str(exc)[:200])
        try:
            listing = await client.run(
                f"find {q} -maxdepth 1 -mindepth 1 -printf '%y\\t%s\\t%T@\\t%f\\n' "
                f"2>/dev/null | head -n {max_entries + 1}"
            )
            if not listing.stdout and not listing.ok:
                return BrowseResult(
                    request_id=rid, path=path, error=listing.stderr.strip()[:200] or "cannot list"
                )
            child_sizes: dict[str, int] = {}
            size_truncated = False
            if with_sizes:
                du = await client.run(
                    f"timeout {size_budget_seconds} du -b -d 1 -- {q} 2>/dev/null"
                )
                size_truncated = not du.ok  # shell `timeout` exits 124 (or the engine cap, -1)
                for line in du.stdout.splitlines():
                    cols = line.split("\t", 1)
                    if len(cols) != 2:
                        continue
                    try:
                        size = int(cols[0])
                    except ValueError:
                        continue
                    child_sizes[cols[1].rstrip("/").rsplit("/", 1)[-1]] = size
            lines = listing.stdout.splitlines()
            truncated = len(lines) > max_entries
            entries: list[BrowseEntry] = []
            for line in lines[:max_entries]:
                cols = line.split("\t")
                if len(cols) != 4:
                    continue
                ftype, size_s, mtime_s, name = cols
                try:
                    size, mtime = int(size_s), float(mtime_s)
                except ValueError:
                    continue
                is_dir, is_symlink = ftype == "d", ftype == "l"
                sub = child_sizes.get(name) if (with_sizes and is_dir and not is_symlink) else None
                entries.append(
                    BrowseEntry(
                        name=name,
                        path=posixpath.join(path, name),
                        is_dir=is_dir,
                        is_symlink=is_symlink,
                        size=size,
                        mtime=mtime,
                        subtree_size=sub,
                        subtree_truncated=bool(sub is not None and size_truncated),
                    )
                )
            entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
            return BrowseResult(request_id=rid, path=path, entries=entries, truncated=truncated)
        finally:
            await client.close()

    async def probe_volumes(
        self,
        target: str,
        port: int,
        credential: SshCredential,
        *,
        expected_host_key: str | None = None,
    ) -> list[BrowseVolume]:
        """List a target's mounted volumes via ``df`` (the Deploy df-style dropdown; read-only)."""
        credential.validate()
        client = await self._connector.connect(
            target, port, credential, expected_host_key=expected_host_key
        )
        try:
            # -P POSIX columns, -T fs type, -B1 byte blocks, -x pseudo-fs excluded by the caller's
            # shell; we filter obvious pseudo-mounts below. Cols: FS TYPE 1B Used Avail Cap Mount.
            res = await client.run("df -PTB1 2>/dev/null")
        finally:
            await client.close()
        vols: list[BrowseVolume] = []
        for line in res.stdout.splitlines()[1:]:  # skip the header row
            cols = line.split()
            if len(cols) < 7:
                continue
            fs_type, total, used, free, mount = cols[1], cols[2], cols[3], cols[4], cols[6]
            if fs_type in {"tmpfs", "devtmpfs", "proc", "sysfs", "overlay", "squashfs"}:
                continue
            try:
                vols.append(
                    BrowseVolume(
                        mountpoint=mount,
                        fs_type=fs_type,
                        total=int(total),
                        used=int(used),
                        free=int(free),
                    )
                )
            except ValueError:
                continue
        vols.sort(key=lambda v: v.mountpoint)
        return vols

    async def deploy_one(self, request: HostDeployRequest, status: HostStatus) -> None:
        """Run the full deploy for one host, recording progress on ``status`` (never raises)."""
        try:
            await self._deploy_one_inner(request, status)
        except DeploymentError as exc:
            status.phase = DeployPhase.FAILED
            status.detail = str(exc)
            _log.warning("deploy failed", extra={"target": request.target, "reason": str(exc)})
        except Exception as exc:  # defensive: one host must never crash the batch
            status.phase = DeployPhase.FAILED
            status.detail = f"unexpected error: {exc}"
            _log.exception("deploy crashed", extra={"target": request.target})

    async def _deploy_one_inner(self, request: HostDeployRequest, status: HostStatus) -> None:
        request.credential.validate()
        status.phase = DeployPhase.CONNECTING
        client = await self._connector.connect(
            request.target,
            request.port,
            request.credential,
            expected_host_key=request.expected_host_key,
        )
        try:
            status.host_key = client.host_key_fingerprint
            await self._preflight_or_fail(client, request, status)
            await self._mint_and_upload(client, request, status)
            await self._ensure_image(client, request, status)
            await self._compose_up(client, request, status)
            await self._verify(client, request, status)
            status.phase = DeployPhase.SUCCEEDED
            status.detail = "agent deployed"
        finally:
            await client.close()

    async def _preflight_or_fail(
        self, client: SshClient, request: HostDeployRequest, status: HostStatus
    ) -> None:
        status.phase = DeployPhase.PREFLIGHT
        docker = await client.run("docker --version")
        if not docker.ok:
            raise DeploymentError("docker not found on target")
        proxy = await client.run(f"timeout 5 bash -c '</dev/tcp/{request.spec.proxy_host_ip}/9443'")
        if not proxy.ok:
            raise DeploymentError(f"target cannot reach proxy {request.spec.proxy_host_ip}:9443")

    async def _mint_and_upload(
        self, client: SshClient, request: HostDeployRequest, status: HostStatus
    ) -> None:
        status.phase = DeployPhase.MINTING
        minted = self._ca.mint_client_cert(f"{request.spec.host_id}-agent", days=self._cert_days)
        status.fingerprint = minted.fingerprint_sha1
        bundle = build_agent_bundle(request.spec, minted)
        status.phase = DeployPhase.UPLOADING
        # The bundle dir may live under a root-only path (e.g. /opt); create it and hand ownership
        # to the SSH user so the unprivileged SFTP upload can write into it. ``$SUDO_USER`` is the
        # invoking login (set by sudo), so this is correct whatever the SSH username is.
        prep = await client.run(
            f"mkdir -p {shlex.quote(request.remote_dir)}/certs "
            f'&& chown -R "$SUDO_USER" {shlex.quote(request.remote_dir)}',
            sudo=True,
        )
        if not prep.ok:
            reason = prep.stderr.strip() or prep.stdout.strip()
            raise DeploymentError(f"could not prepare {request.remote_dir}: {reason}")
        for rel_path, content in bundle.files.items():
            remote = f"{request.remote_dir}/{rel_path}"
            # The private key is the one 0600 file; everything else is world-readable bundle config.
            mode = 0o600 if rel_path.endswith("client.key") else 0o644
            await client.write_file(remote, content, mode=mode)

    async def _ensure_image(
        self, client: SshClient, request: HostDeployRequest, status: HostStatus
    ) -> None:
        """Load the agent image onto the target if it is missing and an archive is configured.

        Idempotent: a present image is left untouched (no needless multi-hundred-MB transfer). The
        archive is streamed over SFTP (chunked) into the bundle dir, ``docker load``-ed, then
        removed. With no archive configured the image is assumed already present (v1 default).
        """
        if self._image_archive_path is None:
            return
        present = await client.run(f"docker image inspect {shlex.quote(request.spec.image)}")
        if present.ok:
            return
        status.phase = DeployPhase.LOADING_IMAGE
        remote_archive = f"{request.remote_dir}/agent-image.tgz"
        await client.upload_file(self._image_archive_path, remote_archive, mode=0o644)
        load = await client.run(f"docker load -i {shlex.quote(remote_archive)}", sudo=True)
        await client.run(f"rm -f {shlex.quote(remote_archive)}")  # reclaim the staged archive
        if not load.ok:
            raise DeploymentError(
                f"docker load failed: {load.stderr.strip() or load.stdout.strip()}"
            )

    async def _compose_up(
        self, client: SshClient, request: HostDeployRequest, status: HostStatus
    ) -> None:
        status.phase = DeployPhase.STARTING
        result = await client.run(
            f"cd {shlex.quote(request.remote_dir)} && docker compose up -d agent", sudo=True
        )
        if not result.ok:
            raise DeploymentError(
                f"compose up failed: {result.stderr.strip() or result.stdout.strip()}"
            )

    async def _verify(
        self, client: SshClient, request: HostDeployRequest, status: HostStatus
    ) -> None:
        status.phase = DeployPhase.VERIFYING
        container = shlex.quote(f"fathom-agent-{request.spec.host_id}")
        check = await client.run(
            f"docker inspect -f '{{{{.State.Status}}}}' {container}",
            sudo=True,
        )
        # ``docker inspect`` exits 0 **iff** the container object exists; a missing container (or a
        # sudo failure) is non-zero. The scan agent is a one-shot (restart:no) so it may already
        # have exited — presence, not running-state, is what proves it was created. Do NOT match
        # stderr: Docker changed the message to lowercase "no such object" in v25, so the old
        # capital-N match silently passed missing containers (adversarial round 1, P1).
        if not check.ok:
            raise DeploymentError(
                f"agent container was not created: {check.stderr.strip() or check.stdout.strip()}"
            )

    async def deploy_batch(self, run: DeployRun, requests: Sequence[HostDeployRequest]) -> None:
        """Deploy every request concurrently (bounded), recording status on ``run`` in place.

        Requests and ``run.hosts`` are built 1:1 in order by the caller, so they are paired
        **positionally**. (Keying by ``target`` would collapse two hosts that share a target onto
        one status — leaving the other forever PENDING so the run never completes; round 1, P1.)
        """

        async def _guarded(req: HostDeployRequest, status: HostStatus) -> None:
            async with self._sema:
                await self.deploy_one(req, status)

        await asyncio.gather(
            *(_guarded(req, status) for req, status in zip(requests, run.hosts, strict=True))
        )
