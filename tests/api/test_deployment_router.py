"""Router tests for the deploy surface (ADR-026): gating, enroll/redeem, preflight, batch."""

from __future__ import annotations

import asyncio
import io
import tarfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.api.deploy_runtime import build_deploy_runtime
from fathom.auth.principal import Role
from fathom.core import db
from fathom.core.settings import Settings
from tests.api.conftest import seed_principal
from tests.deploy.fakes import FakeSshConnector, make_test_ca


@pytest.fixture
async def deploy_client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    """A client whose app has a provisioned deploy runtime backed by a fake SSH connector."""
    await db.dispose_engine()
    # Deployment stays disabled at app build (no real connector); the runtime is injected below.
    # The proxy/core defaults exercise the settings-fallback path for requests that omit them.
    app = create_app(
        settings.model_copy(
            update={
                "agent_deployment_proxy_host_ip": "203.0.113.10",
                "agent_deployment_core_base_url": "https://core.example.com:18088",
            }
        )
    )
    async with LifespanManager(app):
        cert_pem, key_pem = make_test_ca()
        app.state.deploy_runtime = build_deploy_runtime(
            settings.model_copy(
                update={
                    "agent_deployment_enabled": True,
                    "agent_deployment_ca_cert_ref": "CA_CERT",
                    "agent_deployment_ca_key_ref": "CA_KEY",
                }
            ),
            secret_provider=lambda ref: {"CA_CERT": cert_pem, "CA_KEY": key_pem}[ref],
            connector=FakeSshConnector(),
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


def _cred() -> dict[str, str]:
    # Key auth: deploy with a key needs no pinned host key (only password auth does), so this is
    # the right default for the deploy/preflight happy-path tests. The FakeSshConnector ignores the
    # material; the dedicated pin test below exercises the password path.
    return {"username": "deployer", "private_key": "KEY"}


async def test_deploy_503_when_not_provisioned(api_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await api_client.post(
        "/api/v1/deployment/preflight",
        json={"target": "10.0.0.9", "credential": _cred()},
        headers=headers,
    )
    assert resp.status_code == 503


async def test_preflight_requires_deploy_capability(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.VIEWER, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/preflight",
        json={"target": "10.0.0.9", "credential": _cred()},
        headers=headers,
    )
    assert resp.status_code == 403


async def test_deploy_requires_global_scope(deploy_client: httpx.AsyncClient) -> None:
    # A host-scoped admin cannot deploy (a brand-new target isn't in any scope) — fail-closed
    # global-only gate (round-1 F-3, untested until round-7 P1).
    headers = await seed_principal(role=Role.ADMIN, scope_kind="host", host_id=1, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy",
        json={"hosts": [{"target": "10.0.0.9", "host_id": "h1", "credential": _cred()}]},
        headers=headers,
    )
    assert resp.status_code == 403
    assert "global" in resp.json()["detail"]


async def test_deploy_rejects_traversal_remote_dir(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy",
        json={
            "hosts": [
                {
                    "target": "10.0.0.9",
                    "host_id": "h1",
                    "credential": _cred(),
                    "remote_dir": "/opt/../etc/cron.d",
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 422


async def test_preflight_ok(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/preflight",
        json={"target": "10.0.0.9", "credential": _cred(), "proxy_host_ip": "1.2.3.4"},
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["docker_present"] and body["proxy_reachable"]


async def test_deploy_requires_step_up_mfa(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=False)
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy",
        json={"hosts": [{"target": "10.0.0.9", "host_id": "h1", "credential": _cred()}]},
        headers=headers,
    )
    assert resp.status_code == 401


async def test_deploy_batch_runs_to_success(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy",
        json={"hosts": [{"target": "10.0.0.9", "host_id": "node-2", "credential": _cred()}]},
        headers=headers,
    )
    assert resp.status_code == 202
    run_id = resp.json()["run_id"]

    # The deploy runs as a background task; poll the status until terminal (fake SSH is instant).
    # Budget generously (~5s): under full-suite load the event loop is contended, so a 1s budget
    # flaked even though the deploy completes within a second in isolation.
    for _ in range(250):
        status = await deploy_client.get(f"/api/v1/deployment/runs/{run_id}", headers=headers)
        assert status.status_code == 200
        body = status.json()
        if body["complete"]:
            break
        await asyncio.sleep(0.02)
    assert body["complete"] is True
    assert body["hosts"][0]["phase"] == "succeeded"
    assert body["hosts"][0]["fingerprint"]

    # Durable history: the per-host terminal result is spliced onto the hash-chained audit.
    audit = await deploy_client.get("/api/v1/audit?limit=50", headers=headers)
    assert audit.status_code == 200
    actions = [(r["action"], r["result"]) for r in audit.json()["items"]]
    assert ("deployment.initiated", "queued") in actions
    assert ("deployment.host.result", "succeeded") in actions


async def test_enroll_then_redeem_bundle_single_use(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    issued = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={"host_id": "node-2", "core_base_url": "http://core:18088"},
        headers=headers,
    )
    assert issued.status_code == 201
    payload = issued.json()
    token = payload["token"]
    assert "node-2-agent" not in payload["command"]  # command carries the token, not the CN
    assert token in payload["command"]

    # The target redeems with the bearer token (no human session).
    hdr = {"Authorization": f"Bearer {token}"}
    bundle = await deploy_client.get("/api/v1/deployment/enroll/bundle", headers=hdr)
    assert bundle.status_code == 200
    assert bundle.headers["content-type"] == "application/gzip"
    with tarfile.open(fileobj=io.BytesIO(bundle.content), mode="r:gz") as tar:
        names = tar.getnames()
    assert "agent.config.yaml" in names
    assert "certs/client.key" in names

    # Single-use: a second redemption is refused.
    again = await deploy_client.get("/api/v1/deployment/enroll/bundle", headers=hdr)
    assert again.status_code == 403

    # The redeem (handing out a minted identity) is on the durable audit chain (R-1).
    audit = await deploy_client.get("/api/v1/audit?limit=50", headers=headers)
    actions = [r["action"] for r in audit.json()["items"]]
    assert "deployment.enroll.redeemed" in actions


async def test_redeemed_bundle_cert_is_minted_off_the_provisioned_ca(
    deploy_client: httpx.AsyncClient,
) -> None:
    # PULL path, end to end without SSH: the bundle the target redeems carries a *real* agent
    # identity — its client cert was minted off the provisioned (test) CA. Prove it chains to the
    # bundled CA cert and carries the CN=<host>-agent + clientAuth EKU the mTLS proxy keys on. The
    # existing single-use test only checks file *names*; this proves the cert mint actually ran.
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    issued = await deploy_client.post(
        "/api/v1/deployment/enroll", json={"host_id": "node-2"}, headers=headers
    )
    assert issued.status_code == 201
    token = issued.json()["token"]

    bundle = await deploy_client.get(
        "/api/v1/deployment/enroll/bundle", headers={"Authorization": f"Bearer {token}"}
    )
    assert bundle.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(bundle.content), mode="r:gz") as tar:
        client_crt = tar.extractfile("certs/client.crt").read()  # type: ignore[union-attr]
        ca_crt = tar.extractfile("certs/fathom-ca.crt").read()  # type: ignore[union-attr]

    leaf = x509.load_pem_x509_certificate(client_crt)
    ca = x509.load_pem_x509_certificate(ca_crt)
    leaf.verify_directly_issued_by(ca)  # raises unless the CA actually signed the leaf
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "node-2-agent"
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


async def test_windows_enroll_redeems_zip_bundle(deploy_client: httpx.AsyncClient) -> None:
    # ADR-027 W1: platform=windows → PowerShell bootstrap + a native (no-Docker) zip bundle.
    import zipfile

    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    issued = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={
            "host_id": "win-1",
            "platform": "windows",
            "windows_scan_paths": ["C:\\Data", "D:\\Media"],
        },
        headers=headers,
    )
    assert issued.status_code == 201
    payload = issued.json()
    token = payload["token"]
    # The pasted command is PowerShell, carries the token in a header, and is Docker-free.
    cmd = payload["command"]
    assert "Expand-Archive" in cmd and "Tls12" in cmd
    assert token in cmd and "docker" not in cmd

    hdr = {"Authorization": f"Bearer {token}"}
    bundle = await deploy_client.get("/api/v1/deployment/enroll/bundle", headers=hdr)
    assert bundle.status_code == 200
    assert bundle.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(bundle.content), "r") as zf:
        names = zf.namelist()
        assert zf.testzip() is None
        config = zf.read("agent.config.yaml").decode()
    assert "install-agent.ps1" in names and "docker-compose.yml" not in names
    assert "  - 'C:\\Data'" in config
    # IP-based ingest_url (no compose extra_hosts on native Windows).
    assert "ingest_url: https://203.0.113.10:9443/api/v1/agents/ingest" in config


async def test_windows_enroll_requires_scan_paths(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={"host_id": "win-1", "platform": "windows", "windows_scan_paths": []},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_windows_enroll_rejects_unsafe_scan_path(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={
            "host_id": "win-1",
            "platform": "windows",
            "windows_scan_paths": ["C:\\report.txt:ads"],  # alternate data stream
        },
        headers=headers,
    )
    assert resp.status_code == 422


async def test_windows_enroll_emits_fullbit_scope_for_flagged_paths(
    deploy_client: httpx.AsyncClient,
) -> None:
    # ADR-027 W2: a path listed in windows_fullbit_paths lands in the bundle's fullbit_scope
    # (content hashing); an unflagged one stays metadata-only.
    import zipfile

    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    issued = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={
            "host_id": "win-1",
            "platform": "windows",
            "windows_scan_paths": ["C:\\Data", "D:\\Media"],
            "windows_fullbit_paths": ["D:\\Media"],
        },
        headers=headers,
    )
    assert issued.status_code == 201
    hdr = {"Authorization": f"Bearer {issued.json()['token']}"}
    bundle = await deploy_client.get("/api/v1/deployment/enroll/bundle", headers=hdr)
    with zipfile.ZipFile(io.BytesIO(bundle.content), "r") as zf:
        config = zf.read("agent.config.yaml").decode()
    assert "fullbit_scope:\n  - 'D:\\Media'" in config
    assert "fullbit_scope: []" not in config


async def test_windows_enroll_rejects_fullbit_outside_scan_scope(
    deploy_client: httpx.AsyncClient,
) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={
            "host_id": "win-1",
            "platform": "windows",
            "windows_scan_paths": ["C:\\Data"],
            "windows_fullbit_paths": ["E:\\Other"],  # not in scan_scope
        },
        headers=headers,
    )
    assert resp.status_code == 422


async def test_enroll_rejects_injecting_core_base_url(deploy_client: httpx.AsyncClient) -> None:
    # core_base_url is interpolated into the pasted bootstrap command — reject shell metachars.
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    bad = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={"host_id": "h1", "core_base_url": 'http://x"; rm -rf / #'},
        headers=headers,
    )
    assert bad.status_code == 422


async def test_enroll_core_base_url_path_is_stripped(deploy_client: httpx.AsyncClient) -> None:
    # A path/query on the URL is dropped (rebuilt from scheme://host:port) so it can't smuggle in
    # a different endpoint or extra command text.
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    ok = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={"host_id": "h1", "core_base_url": "http://1.2.3.4:9000/evil?x=1"},
        headers=headers,
    )
    assert ok.status_code == 201
    cmd = ok.json()["command"]
    assert "http://1.2.3.4:9000/api/v1/deployment/enroll/bundle" in cmd
    assert "/evil" not in cmd


def test_proxy_and_core_url_fail_loud_when_unset(settings: Settings) -> None:
    # No request value and no FATHOM_AGENT_DEPLOYMENT_* setting → 422; the product ships no
    # baked-in address. The settings fallback path resolves and re-validates.
    from fastapi import HTTPException

    from fathom.api.routers.deployment import _resolve_core_base_url, _resolve_proxy_host_ip

    with pytest.raises(HTTPException) as proxy_err:
        _resolve_proxy_host_ip(settings, None)
    assert proxy_err.value.status_code == 422
    with pytest.raises(HTTPException) as core_err:
        _resolve_core_base_url(settings, None)
    assert core_err.value.status_code == 422

    configured = settings.model_copy(
        update={
            "agent_deployment_proxy_host_ip": "203.0.113.10",
            "agent_deployment_core_base_url": "https://core.example.com:18088",
        }
    )
    assert _resolve_proxy_host_ip(configured, None) == "203.0.113.10"
    assert _resolve_core_base_url(configured, None) == "https://core.example.com:18088"
    # An invalid settings-sourced value still fails loud (it bypassed the request validator).
    tainted = settings.model_copy(update={"agent_deployment_proxy_host_ip": "1.2.3.4; rm"})
    with pytest.raises(HTTPException) as tainted_err:
        _resolve_proxy_host_ip(tainted, None)
    assert tainted_err.value.status_code == 422


async def test_enroll_requires_step_up_mfa(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=False)
    resp = await deploy_client.post(
        "/api/v1/deployment/enroll", json={"host_id": "h1"}, headers=headers
    )
    assert resp.status_code == 401


async def test_deploy_rejects_injecting_host_id(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy",
        json={"hosts": [{"target": "10.0.0.9", "host_id": "h;rm -rf /", "credential": _cred()}]},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_preflight_rejects_injecting_proxy(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/preflight",
        json={"target": "10.0.0.9", "credential": _cred(), "proxy_host_ip": "1.2.3.4; rm"},
        headers=headers,
    )
    assert resp.status_code == 422


async def test_image_endpoint_404_without_archive(deploy_client: httpx.AsyncClient) -> None:
    # No archive configured on this app → image endpoint 404s (command also omits the load step).
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    issued = await deploy_client.post(
        "/api/v1/deployment/enroll", json={"host_id": "h1"}, headers=headers
    )
    token = issued.json()["token"]
    assert "/image" not in issued.json()["command"]
    resp = await deploy_client.get(
        "/api/v1/deployment/enroll/image", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 404


async def test_enroll_bundle_requires_bearer_token(deploy_client: httpx.AsyncClient) -> None:
    # No token at all → 403 (the deploy surface never advertises an auth challenge).
    resp = await deploy_client.get("/api/v1/deployment/enroll/bundle")
    assert resp.status_code == 403


async def test_enroll_bundle_rejects_non_bearer_and_empty_token(
    deploy_client: httpx.AsyncClient,
) -> None:
    # The token gate accepts ONLY a non-empty `Bearer` scheme (EC-enroll-3). A wrong scheme, an
    # empty/whitespace token, or a bare scheme word are all 403 — never a different status that
    # would leak which part was wrong, and never an auth challenge to an anonymous caller.
    for header in (
        {"Authorization": "Basic dXNlcjpwdw=="},  # wrong scheme
        {"Authorization": "Bearer "},  # empty token
        {"Authorization": "Bearer    "},  # whitespace-only token
        {"Authorization": "Bearer"},  # scheme word only, no token
        {"Authorization": "token-without-scheme"},  # no scheme at all
    ):
        resp = await deploy_client.get("/api/v1/deployment/enroll/bundle", headers=header)
        assert resp.status_code == 403, f"{header} -> {resp.status_code}"
    # The same gate fronts the image route.
    img = await deploy_client.get(
        "/api/v1/deployment/enroll/image", headers={"Authorization": "Basic x"}
    )
    assert img.status_code == 403


async def test_deploy_empty_batch_is_422(deploy_client: httpx.AsyncClient) -> None:
    # An empty hosts list is a malformed request (min_length=1), refused at the wire model before
    # any deploy work — 422, not a 200 no-op run (EC-deploy-1).
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy", json={"hosts": []}, headers=headers
    )
    assert resp.status_code == 422


async def test_deploy_over_64_hosts_is_422(deploy_client: httpx.AsyncClient) -> None:
    # The batch is capped at 64 hosts (max_length); 65 is refused at the wire model (EC-deploy-2):
    # an operator cannot fan out an unbounded SSH storm in one call.
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    hosts = [
        {"target": f"10.0.0.{i}", "host_id": f"h{i}", "credential": _cred()} for i in range(65)
    ]
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy", json={"hosts": hosts}, headers=headers
    )
    assert resp.status_code == 422


async def test_image_endpoint_serves_archive_without_consuming_token(
    settings: Settings, tmp_path: Path
) -> None:
    # A separate app whose settings point at a real archive file; the image fetch must NOT spend
    # the token (the bundle fetch still works afterward).
    archive = tmp_path / "agent-image.tgz"
    archive.write_bytes(b"\x1f\x8b\x08\x00fake-gzip-image")
    cert_pem, key_pem = make_test_ca()
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        s = settings.model_copy(
            update={
                "agent_deployment_enabled": True,
                "agent_deployment_ca_cert_ref": "CA_CERT",
                "agent_deployment_ca_key_ref": "CA_KEY",
                "agent_deployment_image_archive_path": str(archive),
                "agent_deployment_proxy_host_ip": "203.0.113.10",
                "agent_deployment_core_base_url": "https://core.example.com:18088",
            }
        )
        app.state.settings = s  # the image route reads the archive path off app.state.settings
        app.state.deploy_runtime = build_deploy_runtime(
            s,
            secret_provider=lambda ref: {"CA_CERT": cert_pem, "CA_KEY": key_pem}[ref],
            connector=FakeSshConnector(),
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
            issued = await client.post(
                "/api/v1/deployment/enroll", json={"host_id": "h1"}, headers=headers
            )
            token = issued.json()["token"]
            assert "/enroll/" in issued.json()["command"] and "/image" in issued.json()["command"]
            hdr = {"Authorization": f"Bearer {token}"}
            img = await client.get("/api/v1/deployment/enroll/image", headers=hdr)
            assert img.status_code == 200
            assert img.headers["content-type"] == "application/gzip"
            assert img.content.startswith(b"\x1f\x8b")
            # Token NOT consumed by the image fetch → the bundle is still redeemable.
            bundle = await client.get("/api/v1/deployment/enroll/bundle", headers=hdr)
            assert bundle.status_code == 200
            # Now the token is spent → a second image fetch is refused.
            again = await client.get("/api/v1/deployment/enroll/image", headers=hdr)
            assert again.status_code == 403
    await db.dispose_engine()


async def test_deploy_password_auth_requires_pinned_host_key(
    deploy_client: httpx.AsyncClient,
) -> None:
    # Password auth without a pinned host key is refused (round-1 F-1/T-1).
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/deploy",
        json={
            "hosts": [
                {
                    "target": "10.0.0.9",
                    "host_id": "h1",
                    "credential": {"username": "x", "password": "pw"},
                }
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 422
    # With a pinned key it is accepted.
    ok = await deploy_client.post(
        "/api/v1/deployment/deploy",
        json={
            "hosts": [
                {
                    "target": "10.0.0.9",
                    "host_id": "h1",
                    "credential": {"username": "x", "password": "pw"},
                    "expected_host_key": "SHA256:fakehostkey",
                }
            ]
        },
        headers=headers,
    )
    assert ok.status_code == 202


async def test_enroll_bundle_includes_remote_targets(deploy_client: httpx.AsyncClient) -> None:
    # ADR-029: the wizard can enrol a remote/cloud-scanning agent — remote_targets land in the
    # generated agent.config.yaml (which the agent re-validates).
    import tarfile as _tf

    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    issued = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={
            "host_id": "cloud-1",
            "mounts": [],
            "remote_targets": [
                {"protocol": "rclone", "host": "gdrive", "remote_path": "/Backups"},
                {"protocol": "smb", "host": "nas-1", "share": "media", "password_ref": "SMB_PW"},
            ],
        },
        headers=headers,
    )
    assert issued.status_code == 201, issued.text
    token = issued.json()["token"]
    bundle = await deploy_client.get(
        "/api/v1/deployment/enroll/bundle", headers={"Authorization": f"Bearer {token}"}
    )
    assert bundle.status_code == 200
    with _tf.open(fileobj=io.BytesIO(bundle.content), mode="r:gz") as tar:
        cfg = tar.extractfile("agent.config.yaml").read().decode()  # type: ignore[union-attr]
    assert "protocol: rclone" in cfg and "'gdrive'" in cfg
    assert "protocol: smb" in cfg and "password_ref: 'SMB_PW'" in cfg


async def test_enroll_rejects_unsafe_remote_target(deploy_client: httpx.AsyncClient) -> None:
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={
            "host_id": "cloud-1",
            "remote_targets": [{"protocol": "rclone", "host": "g", "remote_path": "/a'b"}],
        },
        headers=headers,
    )
    assert resp.status_code == 422  # quote in remote_path → fail-closed before it reaches YAML


async def test_enroll_pending_cap_returns_429(
    deploy_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Back-pressure, not a server fault: when EnrollmentRegistry.issue() hits its pending-token cap
    # it raises DeploymentError — the route must map that to 429 (with the retry hint), never a 500.
    # Regression for the adversarial-review finding (issue() was called outside try/except).
    from fathom.core.deploy import DeploymentError
    from fathom.core.deploy.enrollment import EnrollmentRegistry

    def _full(*_a: object, **_k: object) -> None:
        raise DeploymentError("too many pending enrollment tokens; retry shortly")

    monkeypatch.setattr(EnrollmentRegistry, "issue", _full)
    headers = await seed_principal(role=Role.ADMIN, mfa_fresh=True)
    resp = await deploy_client.post(
        "/api/v1/deployment/enroll",
        json={"host_id": "node-2", "core_base_url": "http://core:18088"},
        headers=headers,
    )
    assert resp.status_code == 429
    assert "retry" in resp.text.lower()
