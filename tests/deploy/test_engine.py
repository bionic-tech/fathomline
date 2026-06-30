"""Engine tests: push orchestration + batch, driven by a fake SSH layer + in-test CA."""

from __future__ import annotations

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.bundle import BundleSpec, ScopeMount
from fathom.core.deploy.certs import CertificateAuthority
from fathom.core.deploy.credentials import SshCredential
from fathom.core.deploy.engine import (
    DeployEngine,
    DeployPhase,
    DeployRunRegistry,
    HostDeployRequest,
    HostStatus,
)
from fathom.core.deploy.ssh import CommandResult
from tests.deploy.fakes import FakeSshClient, FakeSshConnector, make_test_ca


def _ca() -> CertificateAuthority:
    cert_pem, key_pem = make_test_ca()
    return CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem)


def _spec(host_id: str = "node-2") -> BundleSpec:
    return BundleSpec(
        host_id=host_id,
        ingest_url="https://proxy:9443/api/v1/agents/ingest",
        image="fathom:local",
        mounts=(ScopeMount("/scan/data", "/mnt/data", fullbit=True),),
        proxy_host_ip="203.0.113.10",
    )


def _request(host_id: str = "node-2", target: str = "10.0.0.9") -> HostDeployRequest:
    return HostDeployRequest(
        target=target,
        port=22,
        credential=SshCredential(username="deployer", private_key="KEY"),
        spec=_spec(host_id),
    )


async def test_deploy_one_happy_path() -> None:
    client = FakeSshClient()
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    status = HostStatus(host_id="node-2", target="10.0.0.9")

    await engine.deploy_one(_request(), status)

    assert status.phase is DeployPhase.SUCCEEDED
    assert status.fingerprint is not None and len(status.fingerprint) == 40
    assert status.host_key == "SHA256:fakehostkey"
    # The full bundle was uploaded, with the key written 0600.
    assert f"{'/opt/fathom-agent'}/certs/client.key" in client.written
    assert client.written["/opt/fathom-agent/certs/client.key"][1] == 0o600
    assert "/opt/fathom-agent/agent.config.yaml" in client.written
    # compose up was invoked under sudo.
    assert any("docker compose up -d agent" in cmd and sudo for cmd, sudo in client.commands)
    # The bundle dir is sudo-created + chowned before the unprivileged SFTP upload (so a root-only
    # path like /opt works) — regression guard for the live-smoke finding.
    assert any("mkdir -p" in cmd and "chown" in cmd and sudo for cmd, sudo in client.commands)
    assert client.closed


async def test_deploy_one_loads_image_when_missing() -> None:
    # `docker image inspect` fails → the archive is streamed + loaded before compose up.
    client = FakeSshClient(fail=("docker image inspect",))
    engine = DeployEngine(
        connector=FakeSshConnector(client=client),
        ca=_ca(),
        cert_days=10,
        image_archive_path="/srv/agent-image.tgz",
    )
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(_request(), status)
    assert status.phase is DeployPhase.SUCCEEDED
    assert client.uploaded == [("/srv/agent-image.tgz", "/opt/fathom-agent/agent-image.tgz", 0o644)]
    assert any("docker load -i" in cmd and sudo for cmd, sudo in client.commands)
    assert any(cmd.startswith("rm -f") for cmd, _ in client.commands)


async def test_deploy_one_skips_image_when_present() -> None:
    # `docker image inspect` succeeds (default) → no upload/load even with an archive configured.
    client = FakeSshClient()
    engine = DeployEngine(
        connector=FakeSshConnector(client=client),
        ca=_ca(),
        cert_days=10,
        image_archive_path="/srv/agent-image.tgz",
    )
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(_request(), status)
    assert status.phase is DeployPhase.SUCCEEDED
    assert client.uploaded == []
    assert not any("docker load" in cmd for cmd, _ in client.commands)


async def test_deploy_one_no_archive_never_touches_image() -> None:
    # No archive configured → image is assumed present; inspect is never even run.
    client = FakeSshClient()
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(_request(), status)
    assert status.phase is DeployPhase.SUCCEEDED
    assert not any("docker image inspect" in cmd for cmd, _ in client.commands)


async def test_deploy_one_fails_when_container_absent() -> None:
    # docker inspect exits non-zero for a missing container → verify must FAIL (round-1 P1: the
    # old code string-matched "No such object" and passed missing containers on Docker >=25).
    client = FakeSshClient(fail=("docker inspect",))
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(_request(), status)
    assert status.phase is DeployPhase.FAILED
    assert "container was not created" in status.detail


async def test_deploy_batch_handles_duplicate_targets() -> None:
    # Two hosts sharing a target must each get their own terminal status (round-1 P1: keying by
    # target collapsed them, leaving one PENDING so the run never completed).
    engine = DeployEngine(connector=FakeSshConnector(), ca=_ca(), cert_days=10)
    registry = DeployRunRegistry()
    statuses = [
        HostStatus(host_id="a", target="10.0.0.9"),
        HostStatus(host_id="b", target="10.0.0.9"),
    ]
    run = registry.create(created_by="admin", hosts=statuses)
    requests = [_request("a", "10.0.0.9"), _request("b", "10.0.0.9")]
    await engine.deploy_batch(run, requests)
    assert run.complete
    assert all(h.phase is DeployPhase.SUCCEEDED for h in run.hosts)


async def test_deploy_one_aborts_on_host_key_mismatch() -> None:
    # A pinned host key that doesn't match the server aborts the connect → FAILED, nothing uploaded
    # (round-7 P1: the host-key TOFU enforcement was previously untested at any layer).
    client = FakeSshClient(fingerprint="SHA256:real")
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    request = HostDeployRequest(
        target="10.0.0.9",
        port=22,
        credential=SshCredential(username="deployer", private_key="KEY"),
        spec=_spec(),
        expected_host_key="SHA256:WRONG",
    )
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(request, status)
    assert status.phase is DeployPhase.FAILED
    assert "host key" in status.detail
    assert client.written == {}


async def test_deploy_one_accepts_matching_host_key() -> None:
    client = FakeSshClient(fingerprint="SHA256:real")
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    request = HostDeployRequest(
        target="10.0.0.9",
        port=22,
        credential=SshCredential(username="deployer", private_key="KEY"),
        spec=_spec(),
        expected_host_key="SHA256:real",
    )
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(request, status)
    assert status.phase is DeployPhase.SUCCEEDED


async def test_deploy_one_docker_load_failure_fails(  # round-7 P2: load-failure branch
) -> None:
    client = FakeSshClient(fail=("docker image inspect", "docker load"))
    engine = DeployEngine(
        connector=FakeSshConnector(client=client),
        ca=_ca(),
        cert_days=10,
        image_archive_path="/srv/agent-image.tgz",
    )
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(_request(), status)
    assert status.phase is DeployPhase.FAILED
    assert "docker load failed" in status.detail


async def test_deploy_one_compose_up_failure_fails() -> None:  # round-7 P2
    client = FakeSshClient(fail=("docker compose up",))
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(_request(), status)
    assert status.phase is DeployPhase.FAILED
    assert "compose up failed" in status.detail


async def test_deploy_one_prep_chown_failure_fails() -> None:  # round-7 P2
    client = FakeSshClient(fail=("chown",))
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    await engine.deploy_one(_request(), status)
    assert status.phase is DeployPhase.FAILED
    assert "could not prepare" in status.detail
    assert client.written == {}  # never uploaded the bundle after prep failed


async def test_deploy_one_connect_failure_is_recorded_not_raised() -> None:
    engine = DeployEngine(
        connector=FakeSshConnector(raise_on_connect=DeploymentError("unreachable")),
        ca=_ca(),
        cert_days=10,
    )
    status = HostStatus(host_id="h1", target="10.0.0.9")
    await engine.deploy_one(_request("h1"), status)
    assert status.phase is DeployPhase.FAILED
    assert "unreachable" in status.detail


async def test_deploy_one_missing_docker_fails_in_preflight() -> None:
    client = FakeSshClient(fail=("docker --version",))
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)
    status = HostStatus(host_id="h1", target="10.0.0.9")
    await engine.deploy_one(_request("h1"), status)
    assert status.phase is DeployPhase.FAILED
    assert "docker" in status.detail
    # Nothing was uploaded — we fail before minting/upload.
    assert client.written == {}


async def test_preflight_reports_reachability() -> None:
    engine = DeployEngine(connector=FakeSshConnector(), ca=_ca(), cert_days=10)
    report = await engine.preflight(
        "10.0.0.9", 22, SshCredential(username="deployer", password="pw"), proxy_host_ip="1.2.3.4"
    )
    assert report.ok
    assert report.docker_present and report.proxy_reachable
    assert report.host_key_fingerprint == "SHA256:fakehostkey"


async def test_preflight_connect_failure_is_not_reachable() -> None:
    engine = DeployEngine(
        connector=FakeSshConnector(raise_on_connect=DeploymentError("no route")),
        ca=_ca(),
        cert_days=10,
    )
    report = await engine.preflight(
        "10.0.0.9", 22, SshCredential(username="x", password="pw"), proxy_host_ip="1.2.3.4"
    )
    assert not report.reachable and not report.ok
    assert "no route" in report.notes[0]


async def test_deploy_batch_isolates_failures() -> None:
    # One reachable host (succeeds) + one unreachable (fails) — both terminal, batch completes.
    good = FakeSshConnector(client=FakeSshClient())
    engine = DeployEngine(connector=good, ca=_ca(), cert_days=10, max_concurrent=2)
    registry = DeployRunRegistry()
    statuses = [
        HostStatus(host_id="good", target="10.0.0.1"),
        HostStatus(host_id="bad", target="10.0.0.2"),
    ]
    run = registry.create(created_by="admin", hosts=statuses)
    # Make the 'bad' host fail by giving it a connector that raises only for it: simulate via a
    # request whose credential is invalid (validate() raises inside deploy_one → FAILED).
    requests = [
        _request("good", "10.0.0.1"),
        HostDeployRequest(
            target="10.0.0.2",
            port=22,
            credential=SshCredential(username="deployer"),  # no auth method → fails validate()
            spec=_spec("bad"),
        ),
    ]
    await engine.deploy_batch(run, requests)

    assert run.complete
    by_id = {h.host_id: h for h in run.hosts}
    assert by_id["good"].phase is DeployPhase.SUCCEEDED
    assert by_id["bad"].phase is DeployPhase.FAILED


def test_run_registry_get_unknown_is_none() -> None:
    assert DeployRunRegistry().get("nope") is None


def test_run_registry_evicts_oldest_complete_over_cap() -> None:
    reg = DeployRunRegistry(max_runs=2)
    a = reg.create(created_by="admin", hosts=[HostStatus(host_id="a", target="1")])
    a.hosts[0].phase = DeployPhase.SUCCEEDED  # complete → evictable
    b = reg.create(created_by="admin", hosts=[HostStatus(host_id="b", target="2")])
    c = reg.create(created_by="admin", hosts=[HostStatus(host_id="c", target="3")])
    assert reg.get(a.run_id) is None  # oldest *complete* run evicted
    assert reg.get(b.run_id) is not None
    assert reg.get(c.run_id) is not None


def test_run_registry_never_evicts_incomplete_run() -> None:
    # An in-flight (incomplete) run must survive over-cap, else a live status poll would 404 and
    # the UI loop forever (round-1 P3).
    reg = DeployRunRegistry(max_runs=1)
    a = reg.create(created_by="admin", hosts=[HostStatus(host_id="a", target="1")])  # PENDING
    b = reg.create(created_by="admin", hosts=[HostStatus(host_id="b", target="2")])  # PENDING
    assert reg.get(a.run_id) is not None and reg.get(b.run_id) is not None  # neither evicted
    a.hosts[0].phase = DeployPhase.FAILED  # now complete → evictable on the next create
    reg.create(created_by="admin", hosts=[HostStatus(host_id="c", target="3")])
    assert reg.get(a.run_id) is None and reg.get(b.run_id) is not None


class _PhaseRecordingClient(FakeSshClient):
    """A fake client that snapshots the live ``HostStatus.phase`` on every SSH interaction.

    The existing happy-path tests only assert the *terminal* phase. This double proves the engine
    actually walks the documented orchestration order (connect → preflight → upload → start →
    verify) rather than jumping straight to SUCCEEDED.
    """

    def __init__(self, status: HostStatus) -> None:
        super().__init__()
        self._status = status
        self.phase_trace: list[DeployPhase] = []

    async def run(self, command: str, *, sudo: bool = False) -> CommandResult:
        self.phase_trace.append(self._status.phase)
        return await super().run(command, sudo=sudo)

    async def write_file(self, remote_path: str, content: bytes, *, mode: int = 0o644) -> None:
        self.phase_trace.append(self._status.phase)
        await super().write_file(remote_path, content, mode=mode)


async def test_deploy_one_walks_phases_in_documented_order() -> None:
    # Orchestration sequence guard: the engine drives the host through preflight → upload → start →
    # verify (in that order) over the fake — not just into the SUCCEEDED end-state.
    status = HostStatus(host_id="node-2", target="10.0.0.9")
    client = _PhaseRecordingClient(status)
    engine = DeployEngine(connector=FakeSshConnector(client=client), ca=_ca(), cert_days=10)

    await engine.deploy_one(_request(), status)

    assert status.phase is DeployPhase.SUCCEEDED
    assert status.host_key is not None  # set right after a successful connect → CONNECTING ran
    assert status.fingerprint is not None  # the cert was minted → MINTING ran
    # Collapse consecutive duplicates (several SSH calls share a phase) to the ordered sequence of
    # phases under which SSH work happened. MINTING does no SSH (it is a local CA call), so the
    # observable SSH phases are exactly these four, in order.
    observed: list[DeployPhase] = []
    for phase in client.phase_trace:
        if not observed or observed[-1] is not phase:
            observed.append(phase)
    assert observed == [
        DeployPhase.PREFLIGHT,
        DeployPhase.UPLOADING,
        DeployPhase.STARTING,
        DeployPhase.VERIFYING,
    ]


async def test_deploy_batch_mints_distinct_identity_per_host() -> None:
    # A clean multi-host fan-out: every host reaches a terminal SUCCEEDED AND gets its OWN minted
    # cert fingerprint (the agent's mTLS identity). The batch must never reuse one identity across
    # hosts (the duplicate-target test proves both terminate; this proves per-host identities).
    engine = DeployEngine(connector=FakeSshConnector(), ca=_ca(), cert_days=10, max_concurrent=3)
    registry = DeployRunRegistry()
    statuses = [HostStatus(host_id=f"node-{i}", target=f"10.0.0.{i}") for i in range(3)]
    run = registry.create(created_by="admin", hosts=statuses)
    requests = [_request(f"node-{i}", f"10.0.0.{i}") for i in range(3)]

    await engine.deploy_batch(run, requests)

    assert run.complete
    assert all(h.phase is DeployPhase.SUCCEEDED for h in run.hosts)
    fingerprints = {h.fingerprint for h in run.hosts}
    assert len(fingerprints) == 3  # one distinct identity per host
    assert all(fp is not None and len(fp) == 40 for fp in fingerprints)
