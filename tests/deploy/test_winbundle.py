"""Windows agent bundle + PowerShell bootstrap (ADR-027 W1) — pure logic, runs anywhere.

Adversarial in spirit: every value that reaches a generated .ps1 or YAML document is
charset-validated, and the bundle must be a self-consistent native (non-Docker) install.
"""

from __future__ import annotations

import zipfile

import pytest

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.certs import CertificateAuthority
from fathom.core.deploy.enrollment import (
    PLATFORM_WINDOWS,
    EnrollmentRegistry,
    windows_powershell_bootstrap,
)
from fathom.core.deploy.winbundle import (
    WindowsBundleSpec,
    WindowsScanPath,
    build_windows_agent_bundle,
    windows_ingest_url,
)
from tests.deploy.fakes import make_test_ca


def _wspec(**over: object) -> WindowsBundleSpec:
    base: dict[str, object] = {
        "host_id": "win-1",
        "ingest_url": "https://203.0.113.10:9443/api/v1/agents/ingest",
        "proxy_host_ip": "203.0.113.10",
        "scan_paths": (WindowsScanPath("C:\\Data"), WindowsScanPath("D:\\Media")),
    }
    base.update(over)
    return WindowsBundleSpec(**base)  # type: ignore[arg-type]


# ----------------------------------------------------------------- ingest URL rewrite


def test_windows_ingest_url_swaps_host_keeps_port_and_path() -> None:
    out = windows_ingest_url("https://proxy:9443/api/v1/agents/ingest", "203.0.113.10")
    assert out == "https://203.0.113.10:9443/api/v1/agents/ingest"


def test_windows_ingest_url_rejects_non_https() -> None:
    with pytest.raises(DeploymentError):
        windows_ingest_url("http://proxy:9443/x", "203.0.113.10")


def test_windows_ingest_url_rejects_bad_proxy_ip() -> None:
    with pytest.raises(DeploymentError):
        windows_ingest_url("https://proxy:9443/x", "1.2.3.4; rm -rf /")


# ----------------------------------------------------------------- bundle contents


def test_build_windows_bundle_shape_and_no_docker() -> None:
    cert_pem, key_pem = make_test_ca()
    minted = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem).mint_client_cert(
        "win-1-agent", days=10
    )
    bundle = build_windows_agent_bundle(_wspec(), minted)

    assert set(bundle.files) == {
        "agent.config.yaml",
        "run-scan.ps1",
        "install-agent.ps1",
        "README.txt",
        "certs/client.crt",
        "certs/client.key",
        "certs/fathom-ca.crt",
    }
    # No Docker artifacts in a native Windows bundle.
    assert "docker-compose.yml" not in bundle.files

    config = bundle.files["agent.config.yaml"].decode()
    assert "host_id: win-1" in config
    assert "ingest_url: https://203.0.113.10:9443/api/v1/agents/ingest" in config
    # Windows scan paths are single-quoted YAML scalars (backslashes literal).
    assert "  - 'C:\\Data'" in config
    assert "  - 'D:\\Media'" in config
    # Cert paths point inside the install dir, also single-quoted.
    assert "'C:\\ProgramData\\Fathomline\\certs\\client.crt'" in config
    assert "write_enabled: false" in config
    assert "fullbit_scope: []" in config  # no fullbit paths here → metadata-only

    install = bundle.files["install-agent.ps1"].decode()
    assert "Register-ScheduledTask" in install
    assert "Fathomline Agent Scan (win-1)" in install
    assert "-At '02:30'" in install
    assert "SYSTEM" in install and "RunLevel Highest" in install

    runner = bundle.files["run-scan.ps1"].decode()
    assert "FATHOM_AGENT_CONFIG" in runner
    assert "fathom.agent" in runner

    assert bundle.files["certs/client.key"] == minted.key_pem.encode()


def test_build_windows_bundle_emits_fullbit_scope_for_flagged_paths() -> None:
    # A scan path flagged ``fullbit`` lands in fullbit_scope (ADR-027 W2 content hashing); an
    # unflagged one stays metadata-only — so the two scopes can differ within one bundle.
    cert_pem, key_pem = make_test_ca()
    minted = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem).mint_client_cert(
        "win-1-agent", days=10
    )
    spec = _wspec(
        scan_paths=(
            WindowsScanPath("D:\\Media", fullbit=True),
            WindowsScanPath("C:\\Windows"),  # metadata-only
        )
    )
    config = build_windows_agent_bundle(spec, minted).files["agent.config.yaml"].decode()
    assert "fullbit_scope:\n  - 'D:\\Media'" in config
    assert "fullbit_scope: []" not in config
    # The metadata-only path is in scan_scope but NOT fullbit_scope.
    assert "  - 'C:\\Windows'" in config
    assert "  - 'C:\\Windows'" not in config.split("fullbit_scope:")[1]


# ----------------------------------------------------------------- spec validation (fail-closed)


@pytest.mark.parametrize("bad", ["a;rm", "$(whoami)", "a b", "-leading", "x" * 64])
def test_wspec_rejects_injecting_host_id(bad: str) -> None:
    with pytest.raises(DeploymentError):
        _wspec(host_id=bad)


@pytest.mark.parametrize(
    "bad",
    [
        "relative\\path",  # not absolute
        "C:data",  # drive-relative
        "C:\\report.txt:ads",  # alternate data stream
        "C:\\CON\\logs",  # reserved device
        "C:\\bad<name>",  # forbidden char
    ],
)
def test_wspec_rejects_unsafe_scan_paths(bad: str) -> None:
    with pytest.raises(DeploymentError):
        _wspec(scan_paths=(WindowsScanPath(bad),))


def test_wspec_rejects_empty_scan_paths() -> None:
    with pytest.raises(DeploymentError):
        _wspec(scan_paths=())


@pytest.mark.parametrize("bad", ["2:30", "24:00", "noon", "02:60", "2:300"])
def test_wspec_rejects_bad_start_time(bad: str) -> None:
    with pytest.raises(DeploymentError):
        _wspec(start_time=bad)


def test_wspec_rejects_non_https_ingest() -> None:
    with pytest.raises(DeploymentError):
        _wspec(ingest_url="http://203.0.113.10:9443/x")


def test_scan_path_with_single_quote_is_escaped_in_yaml() -> None:
    # A legitimate (if odd) directory name containing a quote must be YAML-escaped, not break out.
    cert_pem, key_pem = make_test_ca()
    minted = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem).mint_client_cert(
        "win-1-agent", days=10
    )
    spec = _wspec(scan_paths=(WindowsScanPath("C:\\O'Brien"),))
    config = build_windows_agent_bundle(spec, minted).files["agent.config.yaml"].decode()
    assert "  - 'C:\\O''Brien'" in config  # doubled single-quote = literal quote in YAML


# ----------------------------------------------------------------- PowerShell bootstrap


def test_powershell_bootstrap_token_in_header_not_url() -> None:
    cmd = windows_powershell_bootstrap(
        "https://core.example.com:18088/", "TOK123", install_dir="C:\\ProgramData\\Fathomline"
    )
    assert "https://core.example.com:18088/api/v1/deployment/enroll/bundle" in cmd
    assert '$T="TOK123"' in cmd
    assert "Authorization=('Bearer '+$T)" in cmd
    assert "/enroll/TOK123/" not in cmd  # token never in the URL
    # Hardened: TLS 1.2 forced, unique temp file, Expand-Archive, runs the installer.
    assert "Tls12" in cmd
    assert "[guid]::NewGuid()" in cmd
    assert "Expand-Archive" in cmd
    assert "install-agent.ps1" in cmd
    assert "docker" not in cmd  # native install, no Docker


def test_powershell_bootstrap_locks_install_dir_before_extraction() -> None:
    # Win-review HIGH: the install dir must be locked to SYSTEM+Administrators BEFORE the bundle
    # (with the private key) is extracted, defeating ProgramData squatting / key disclosure.
    cmd = windows_powershell_bootstrap(
        "https://core.example.com:18088", "TOK", install_dir="C:\\ProgramData\\Fathomline"
    )
    # Squat detection: refuse a pre-existing dir not owned by SYSTEM/Administrators.
    assert "Get-Acl $D" in cmd and "throw" in cmd
    assert "S-1-5-18" in cmd and "S-1-5-32-544" in cmd  # SYSTEM + Administrators SIDs
    assert "/inheritance:r" in cmd
    # The lock (icacls grant) must come before the download/extract of the bundle.
    assert cmd.index("/inheritance:r") < cmd.index("Invoke-WebRequest")
    assert cmd.index("icacls") < cmd.index("Expand-Archive")


def test_wspec_rejects_control_char_in_ingest_url() -> None:
    with pytest.raises(DeploymentError):
        _wspec(ingest_url="https://203.0.113.10:9443/api\x01/ingest")


# ------------------------------------------------------- enrollment grant carries platform


def test_enrollment_records_windows_platform_and_spec() -> None:
    reg = EnrollmentRegistry(ttl_seconds=900)
    spec = _wspec()
    token, _ = reg.issue("win-1", spec, platform=PLATFORM_WINDOWS)
    grant = reg.redeem(token)
    assert grant.platform == PLATFORM_WINDOWS
    assert isinstance(grant.spec, WindowsBundleSpec)
    assert grant.spec.host_id == "win-1"


# ----------------------------------------------------------------- zip is well-formed


def test_windows_bundle_packs_into_valid_zip() -> None:
    import io

    cert_pem, key_pem = make_test_ca()
    minted = CertificateAuthority.from_pem(cert_pem=cert_pem, key_pem=key_pem).mint_client_cert(
        "win-1-agent", days=10
    )
    files = build_windows_agent_bundle(_wspec(), minted).files
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in sorted(files.items()):
            zf.writestr(path, content)
    buf.seek(0)
    with zipfile.ZipFile(buf, "r") as zf:
        assert zf.testzip() is None
        assert "install-agent.ps1" in zf.namelist()
