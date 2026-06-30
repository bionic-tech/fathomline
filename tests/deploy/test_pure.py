"""Unit tests for the pure deploy modules: certs, bundle, credentials, enrollment."""

from __future__ import annotations

import datetime as _dt

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.bundle import BundleSpec, ScopeMount, build_agent_bundle
from fathom.core.deploy.certs import CertificateAuthority
from fathom.core.deploy.credentials import SshCredential
from fathom.core.deploy.enrollment import EnrollmentRegistry, bootstrap_command
from tests.deploy.fakes import make_test_ca

# --------------------------------------------------------------------------- certs


def test_mint_client_cert_is_ca_signed_clientauth() -> None:
    cert_pem, key_pem = make_test_ca()
    ca = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem)
    minted = ca.mint_client_cert("node-2-agent", days=825)

    cert = x509.load_pem_x509_certificate(minted.cert_pem.encode())
    ca_cert = x509.load_pem_x509_certificate(cert_pem.encode())
    # Chains to the CA (signature verifies against the issuer).
    cert.verify_directly_issued_by(ca_cert)
    # Identity + constraints.
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "node-2-agent"
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    # Fingerprint is lowercase, colon-free SHA-1 hex (the ingest host identity).
    assert len(minted.fingerprint_sha1) == 40
    assert minted.fingerprint_sha1 == minted.fingerprint_sha1.lower()
    assert minted.ca_cert_pem == ca.ca_cert_pem


def test_mint_two_certs_have_distinct_fingerprints() -> None:
    cert_pem, key_pem = make_test_ca()
    ca = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem)
    a = ca.mint_client_cert("h1-agent", days=10)
    b = ca.mint_client_cert("h2-agent", days=10)
    assert a.fingerprint_sha1 != b.fingerprint_sha1


def test_from_pem_rejects_garbage() -> None:
    with pytest.raises(DeploymentError):
        CertificateAuthority.from_pem(cert_pem="not a cert", key_pem="nope")


def test_from_pem_rejects_non_ca_cert() -> None:
    # A mis-pointed leaf/client cert (CA:false) must fail loud, not silently mint unverifiable
    # agent certs (round-3 P3). Mint a leaf off a real CA, then try to load IT as the CA.
    ca_cert_pem, ca_key_pem = make_test_ca()
    leaf = CertificateAuthority.from_pem(cert_pem=ca_cert_pem, key_pem=ca_key_pem).mint_client_cert(
        "leaf-agent", days=10
    )
    with pytest.raises(DeploymentError, match="not a CA"):
        CertificateAuthority.from_pem(cert_pem=leaf.cert_pem, key_pem=leaf.key_pem)


def test_mint_rejects_overlong_cn() -> None:
    # host_id is capped so <host_id>-agent stays <=64 chars; the mint also guards directly so the
    # one-time pull token can't be burned by a late ValueError (round-3 P1).
    cert_pem, key_pem = make_test_ca()
    ca = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem)
    with pytest.raises(DeploymentError, match="CN too long"):
        ca.mint_client_cert("x" * 65, days=10)
    # A 57-char host_id (the new max) → 63-char CN → mints fine.
    assert ca.mint_client_cert("a" * 57 + "-agent", days=10).common_name.endswith("-agent")


@pytest.mark.parametrize("n", [58, 60, 63])
def test_validate_host_id_rejects_cn_overflowing_length(n: int) -> None:
    from fathom.core.deploy.bundle import validate_host_id

    with pytest.raises(DeploymentError):
        validate_host_id("a" * n)  # would make <host_id>-agent exceed 64


# --------------------------------------------------------------------------- bundle


def _spec(**over: object) -> BundleSpec:
    base: dict[str, object] = {
        "host_id": "node-2",
        "ingest_url": "https://proxy:9443/api/v1/agents/ingest",
        "image": "fathom:local",
        "mounts": (
            ScopeMount("/scan/data", "/mnt/data", fullbit=True),
            ScopeMount("/scan/logs", "/var/log", fullbit=False),
        ),
        "proxy_host_ip": "203.0.113.10",
    }
    base.update(over)
    return BundleSpec(**base)  # type: ignore[arg-type]


def test_build_agent_bundle_templates_config_and_compose() -> None:
    cert_pem, key_pem = make_test_ca()
    minted = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem).mint_client_cert(
        "node-2-agent", days=10
    )
    bundle = build_agent_bundle(_spec(), minted)

    assert set(bundle.files) == {
        "agent.config.yaml",
        "docker-compose.yml",
        "certs/client.crt",
        "certs/client.key",
        "certs/fathom-ca.crt",
    }
    config = bundle.files["agent.config.yaml"].decode()
    assert "host_id: node-2" in config
    assert "https://proxy:9443/api/v1/agents/ingest" in config
    assert "  - /scan/data" in config and "  - /scan/logs" in config
    # fullbit scope contains only the fullbit mount (parse up to the next block, scope_labels).
    fullbit_section = config.split("fullbit_scope:")[1].split("scope_labels:")[0]
    assert "/scan/data" in fullbit_section and "/scan/logs" not in fullbit_section
    # ADR-029 relabel: each scan root maps to its real host path (the UI display_name).
    labels_section = config.split("scope_labels:")[1].split("remote_targets:")[0]
    assert "'/scan/data': '/mnt/data'" in labels_section
    assert "'/scan/logs': '/var/log'" in labels_section
    compose = bundle.files["docker-compose.yml"].decode()
    assert "fathom-agent-node-2" in compose
    assert "/mnt/data:/scan/data:ro" in compose
    assert bundle.files["certs/client.key"] == minted.key_pem.encode()


def test_bundlespec_rejects_empty_mounts_and_relative_paths() -> None:
    with pytest.raises(DeploymentError):
        _spec(mounts=())
    with pytest.raises(DeploymentError):
        _spec(mounts=(ScopeMount("scan/data", "/mnt/data"),))


@pytest.mark.parametrize(
    "bad",
    ["a;rm -rf /", "a b", "", "-leading", "a/b", "x" * 64, "host$(id)", "a\nb"],
)
def test_bundlespec_rejects_injecting_host_id(bad: str) -> None:
    # host_id becomes a container name, YAML value, and cert CN — reject metacharacters (E-2).
    with pytest.raises(DeploymentError):
        _spec(host_id=bad)


@pytest.mark.parametrize("bad", ["1.2.3.4; rm", "$(whoami)", "a b", "a'b", "x" * 256])
def test_bundlespec_rejects_injecting_proxy(bad: str) -> None:
    with pytest.raises(DeploymentError):
        _spec(proxy_host_ip=bad)


def test_bundlespec_rejects_path_with_yaml_metachars() -> None:
    with pytest.raises(DeploymentError):
        _spec(mounts=(ScopeMount("/scan/data", "/mnt/data\n  privileged: true"),))


@pytest.mark.parametrize(
    "bad",
    ["http://proxy/ingest", "https://proxy/ingest\n  evil: true", 'https://p"x', "ftp://p"],
)
def test_bundlespec_rejects_bad_ingest_url(bad: str) -> None:
    # ingest_url is interpolated into the generated config YAML — https + no metachars (round-5 F3).
    with pytest.raises(DeploymentError):
        _spec(ingest_url=bad)


@pytest.mark.parametrize("bad", ['fathom:local"; rm', "img\nx", ""])
def test_bundlespec_rejects_bad_image(bad: str) -> None:
    with pytest.raises(DeploymentError):
        _spec(image=bad)


def test_validate_helpers() -> None:
    from fathom.core.deploy.bundle import validate_host_id, validate_host_or_ip

    assert validate_host_id("node-2") == "node-2"
    assert validate_host_or_ip("203.0.113.86") == "203.0.113.86"
    with pytest.raises(DeploymentError):
        validate_host_id("a;b")
    with pytest.raises(DeploymentError):
        validate_host_or_ip("a b")


# --------------------------------------------------------------------------- credentials


def test_credential_validate_accepts_key_or_password() -> None:
    SshCredential(username="deployer", private_key="KEY").validate()
    SshCredential(username="deployer", password="pw").validate()


@pytest.mark.parametrize(
    "cred",
    [
        SshCredential(username="deployer"),  # no method
        SshCredential(username="deployer", private_key="K", password="pw"),  # both
        SshCredential(username="deployer", passphrase="p"),  # passphrase, no key
        SshCredential(username="", private_key="K"),  # no username
    ],
)
def test_credential_validate_rejects_bad_combos(cred: SshCredential) -> None:
    with pytest.raises(DeploymentError):
        cred.validate()


def test_credential_repr_is_redacted() -> None:
    cred = SshCredential(
        username="deployer", private_key="SECRET-KEY", passphrase="p", sudo_password="s"
    )
    text = repr(cred)
    assert "SECRET-KEY" not in text
    assert "deployer" in text
    assert "auth=key" in text
    assert "<set>" in text  # passphrase/sudo render as presence flags


# --------------------------------------------------------------------------- enrollment


def test_enrollment_token_is_single_use() -> None:
    reg = EnrollmentRegistry(ttl_seconds=900)
    token, _ = reg.issue("node-2", _spec())
    grant = reg.redeem(token)
    assert grant.host_id == "node-2"
    with pytest.raises(DeploymentError):
        reg.redeem(token)  # already used


def test_enrollment_token_expires() -> None:
    clock = {"t": _dt.datetime(2026, 6, 10, tzinfo=_dt.UTC)}
    reg = EnrollmentRegistry(ttl_seconds=60, now=lambda: clock["t"])
    token, _ = reg.issue("h1", _spec())
    clock["t"] = clock["t"] + _dt.timedelta(seconds=61)
    with pytest.raises(DeploymentError, match="expired"):
        reg.redeem(token)


def test_enrollment_invalid_token_rejected() -> None:
    reg = EnrollmentRegistry(ttl_seconds=900)
    with pytest.raises(DeploymentError):
        reg.redeem("never-issued")


def test_enrollment_registry_caps_pending() -> None:
    # Refuse over max_pending live tokens so a buggy issue-loop can't grow memory (round-5 F4).
    reg = EnrollmentRegistry(ttl_seconds=900, max_pending=2)
    reg.issue("h1", _spec())
    reg.issue("h2", _spec())
    with pytest.raises(DeploymentError, match="too many"):
        reg.issue("h3", _spec())


def test_bootstrap_command_targets_redeem_url() -> None:
    cmd = bootstrap_command("http://core:18088/", "TOK", image="fathom:local", serve_image=False)
    assert "http://core:18088/api/v1/deployment/enroll/bundle" in cmd
    assert "docker compose up -d agent" in cmd
    # Token rides an Authorization header (held in $T), not the URL path (F-2).
    assert 'T="TOK"' in cmd
    assert "Authorization: Bearer $T" in cmd
    assert "/enroll/TOK/" not in cmd  # token is never in the URL
    # Hardened extraction (round-2): pipefail, mktemp tarball, safe tar flags.
    assert "set -eo pipefail" in cmd
    assert "$(mktemp)" in cmd
    assert "--no-same-owner" in cmd
    assert "/tmp/fathom-bundle.tgz" not in cmd  # no predictable temp path
    # No archive configured → no image-load step.
    assert "/enroll/image" not in cmd


def test_bootstrap_command_loads_image_when_served() -> None:
    cmd = bootstrap_command("http://core:18088", "TOK", image="fathom:local", serve_image=True)
    # Image is fetched (only if missing) before the bundle is redeemed (token spent last).
    assert 'docker image inspect "fathom:local"' in cmd
    assert "/enroll/image" in cmd
    assert cmd.index("/enroll/image") < cmd.index("/enroll/bundle")


def test_enrollment_verify_does_not_consume() -> None:
    from fathom.core.deploy.enrollment import EnrollmentRegistry

    reg = EnrollmentRegistry(ttl_seconds=900)
    token, _ = reg.issue("h1", _spec())
    # verify twice (non-consuming) then redeem once (consuming) then verify fails.
    assert reg.verify(token).host_id == "h1"
    assert reg.verify(token).host_id == "h1"
    assert reg.redeem(token).host_id == "h1"
    with pytest.raises(DeploymentError):
        reg.verify(token)


# ------------------------------------------------- remote_targets in the bundle (ADR-029)


def _render_cfg(spec: BundleSpec) -> str:
    cert_pem, key_pem = make_test_ca()
    minted = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem).mint_client_cert(
        "node-2-agent", days=10
    )
    return build_agent_bundle(spec, minted).files["agent.config.yaml"].decode()


def test_bundle_remote_targets_render_and_load_as_agent_config() -> None:
    # The generated agent.config.yaml with remote targets must PARSE back as a valid AgentConfig
    # (the agent re-validates it) — proving rclone/SMB/SFTP targets are deployable via the bundle.
    import yaml

    from fathom.agent.config import AgentConfig
    from fathom.core.deploy.bundle import RemoteTargetSpec

    spec = _spec(
        remote_targets=(
            RemoteTargetSpec(protocol="rclone", host="gdrive", remote_path="/Backups"),
            RemoteTargetSpec(
                protocol="smb",
                host="nas-1",
                share="media",
                remote_path="/",
                username="scanner",
                password_ref="SMB_PW",
            ),
            RemoteTargetSpec(protocol="sftp", host="nas-1", remote_path="/srv", port=2222),
        )
    )
    cfg = AgentConfig.model_validate(yaml.safe_load(_render_cfg(spec)))
    assert [t.protocol for t in cfg.remote_targets] == ["rclone", "smb", "sftp"]
    assert cfg.remote_targets[0].mount_key == "rclone://gdrive/Backups"
    assert cfg.remote_targets[1].share == "media" and cfg.remote_targets[1].password_ref == "SMB_PW"
    assert cfg.remote_targets[2].port == 2222


def test_remote_only_bundle_has_empty_scan_scope_but_loads() -> None:
    # A cloud-only agent: remote targets, no local mounts → empty scan_scope, still valid.
    import yaml

    from fathom.agent.config import AgentConfig
    from fathom.core.deploy.bundle import RemoteTargetSpec

    spec = _spec(
        mounts=(),
        remote_targets=(RemoteTargetSpec(protocol="rclone", host="gdrive", remote_path="/B"),),
    )
    cfg = AgentConfig.model_validate(yaml.safe_load(_render_cfg(spec)))
    assert cfg.scan_scope == [] and len(cfg.remote_targets) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"protocol": "ftp", "host": "h"},  # unknown protocol
        {"protocol": "rclone", "host": "scheme://x"},  # scheme in host
        {"protocol": "rclone", "host": "a/b"},  # slash in host
        {"protocol": "rclone", "host": "g", "remote_path": "/a'b"},  # quote -> YAML breakout
        {"protocol": "rclone", "host": "g", "remote_path": "/a\nb"},  # newline
        {"protocol": "rclone", "host": "g", "remote_path": "/a\x7fb"},  # DEL -> PyYAML ReaderError
        {"protocol": "rclone", "host": "g", "remote_path": "/a\x80b"},  # C1 control char
        {"protocol": "rclone", "host": "g", "remote_path": ""},  # empty -> agent rejects at load
        {"protocol": "rclone", "host": "g", "remote_path": "/a/../../etc"},  # .. traversal
        {"protocol": "smb", "host": "h", "share": "../../mnt", "remote_path": "/m"},  # share .. esc
        {"protocol": "sftp", "host": "h", "remote_path": "/a\\b"},  # backslash
        {"protocol": "smb", "host": "h"},  # smb without share
        {"protocol": "rclone", "host": "g", "password_ref": "X"},  # rclone takes no creds
        {"protocol": "sftp", "host": "h", "password_ref": "bad/ref"},  # ref not a bare name
        {"protocol": "sftp", "host": "h", "verify": False},  # verify off without lab_insecure
    ],
)
def test_remote_target_spec_rejects_unsafe(kwargs: dict) -> None:
    from fathom.core.deploy.bundle import RemoteTargetSpec

    with pytest.raises(DeploymentError):
        RemoteTargetSpec(**kwargs)


def test_bundle_with_no_mounts_and_no_remote_targets_is_rejected() -> None:
    with pytest.raises(DeploymentError, match="scan scope mount or remote target"):
        _spec(mounts=(), remote_targets=())
