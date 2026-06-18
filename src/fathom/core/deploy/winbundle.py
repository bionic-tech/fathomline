"""Windows agent bundle generation (ADR-027 phase W1; sibling of :mod:`bundle`).

The Linux bundle is Docker-shaped (``docker-compose.yml`` + ``docker compose up``). The Windows
W1 agent runs **natively** — no container — so its bundle is a different shape and lives here,
isolated from the adversarially-hardened Linux ``bundle.py`` so that file stays untouched:

    agent.config.yaml      # Windows scan paths, IP-based ingest_url, Windows cert paths
    certs\\client.crt
    certs\\client.key
    certs\\fathom-ca.crt
    run-scan.ps1           # the launcher a scheduled task invokes (sets env, runs one scan pass)
    install-agent.ps1      # registers the daily Scheduled Task (run as SYSTEM, highest privileges)
    README.txt

Two deliberate W1 choices, recorded in ADR-027:

* **Scheduled Task, not a Windows service.** The W1 scan agent is a one-shot pass (mirrors the
  Linux cron ``run-scan.sh`` / ``restart: "no"``). A long-running *service* is only needed for the
  later always-on listen daemon, which W1 does not ship.
* **IP-based ``ingest_url``, no hosts-file mutation.** The Linux container maps ``proxy`` via
  compose ``extra_hosts``; rather than mutate the global Windows ``hosts`` file (a system-wide side
  effect), the Windows agent connects to the proxy by IP. This requires the proxy server cert SAN
  to include that IP — which the multi-host deployment guide's ``server.ext`` already does.

All inputs are charset-validated before they reach a generated ``.ps1`` or YAML document, exactly
as the Linux path validates before YAML/compose interpolation (threat-model E-2 discipline).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.bundle import AgentBundle, validate_host_id, validate_host_or_ip
from fathom.core.deploy.certs import MintedCert
from fathom.security.winpaths import validate_windows_config_path

# A daily start time, 24h "HH:MM" — interpolated into the scheduled-task trigger.
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DEFAULT_INSTALL_DIR = "C:\\ProgramData\\Fathomline"


def _reject_control_chars(value: str, *, what: str) -> None:
    if any(ord(ch) < 32 for ch in value):
        raise DeploymentError(f"control character in {what}: {value!r}")


def windows_ingest_url(ingest_url: str, proxy_host_ip: str) -> str:
    """Rewrite ``ingest_url``'s host to ``proxy_host_ip``, preserving scheme/port/path.

    The Windows agent has no compose ``extra_hosts`` to map ``proxy`` → the proxy IP, so it
    dials the proxy by address. Scheme, port and path are preserved so the only change from the
    Linux ingest URL is the host (the proxy cert SAN must therefore include the IP). Fails closed
    on a non-https or malformed result.
    """
    parts = urlsplit(ingest_url)
    if parts.scheme != "https":
        raise DeploymentError(f"ingest_url must be https://: {ingest_url!r}")
    validate_host_or_ip(proxy_host_ip)
    netloc = f"{proxy_host_ip}:{parts.port}" if parts.port else proxy_host_ip
    rebuilt = urlunsplit(("https", netloc, parts.path, parts.query, parts.fragment))
    if any(c in rebuilt for c in '\n\r" '):
        raise DeploymentError(f"invalid ingest_url after rewrite: {rebuilt!r}")
    return rebuilt


@dataclass(frozen=True, slots=True)
class WindowsScanPath:
    """One Windows scan root. ``fullbit`` is carried for forward-compat; W1 is metadata-only."""

    path: str
    fullbit: bool = False


@dataclass(frozen=True, slots=True)
class WindowsBundleSpec:
    """Everything the Windows bundle templater needs that is not the cert (ADR-027 W1)."""

    host_id: str
    ingest_url: str
    proxy_host_ip: str
    scan_paths: tuple[WindowsScanPath, ...]
    install_dir: str = _DEFAULT_INSTALL_DIR
    start_time: str = "02:30"

    def __post_init__(self) -> None:
        validate_host_id(self.host_id)
        validate_host_or_ip(self.proxy_host_ip)
        # ingest_url: https-only, no metacharacters (it lands in a generated YAML document). Same
        # contract as the Linux BundleSpec, inlined so the hardened bundle.py stays untouched.
        if not self.ingest_url.startswith("https://") or any(
            c in self.ingest_url for c in '\n\r" '
        ):
            raise DeploymentError(f"invalid ingest_url {self.ingest_url!r} (https, no metachars)")
        if not self.scan_paths:
            raise DeploymentError("Windows bundle requires at least one scan path")
        for sp in self.scan_paths:
            # Strict Windows path rules (long-path prefixes, ADS, reserved devices, drive-rooted /
            # UNC only). PathSafetyError → DeploymentError so callers see one bundle-error type.
            try:
                validate_windows_config_path(sp.path)
            except ValueError as exc:
                raise DeploymentError(f"invalid Windows scan path {sp.path!r}: {exc}") from exc
        _reject_control_chars(self.ingest_url, what="ingest_url")
        if not _TIME_RE.match(self.start_time):
            raise DeploymentError(f"invalid start_time {self.start_time!r} (expected HH:MM 24h)")
        try:
            validate_windows_config_path(self.install_dir)
        except ValueError as exc:
            raise DeploymentError(f"invalid install_dir {self.install_dir!r}: {exc}") from exc
        _reject_control_chars(self.host_id, what="host_id")


def _yaml_sq(value: str) -> str:
    """A YAML single-quoted scalar: backslashes are literal (right for Windows paths); ' → ''."""
    return "'" + value.replace("'", "''") + "'"


def _ps_sq(value: str) -> str:
    """A PowerShell single-quoted string literal: ' → '' (no other escapes apply)."""
    return "'" + value.replace("'", "''") + "'"


def _render_config(spec: WindowsBundleSpec) -> str:
    scan_block = "\n".join(f"  - {_yaml_sq(sp.path)}" for sp in spec.scan_paths)
    certs = spec.install_dir.rstrip("\\") + "\\certs"
    return f"""# Fathomline Windows agent config for {spec.host_id} — generated (ADR-027 W1).
# Read-only, metadata-only (full-bit is phase W2); pushes to core over CA-pinned mTLS.
host_id: {spec.host_id}
ingest_url: {spec.ingest_url}
client_cert_path: {_yaml_sq(certs + chr(92) + "client.crt")}
client_key_path:  {_yaml_sq(certs + chr(92) + "client.key")}
server_ca_path:   {_yaml_sq(certs + chr(92) + "fathom-ca.crt")}
scan_scope:
{scan_block}
fullbit_scope: []
write_enabled: false
cross_mounts: false
throttle:
  io_class: idle
  io_max_mbps: 200
  cpu_max_percent: 40.0
  walk_concurrency: 4
  hash_concurrency: 2
  pause_when:
    load1_above: 20.0
    iowait_above_percent: 25.0
  resume_when:
    load1_below: 12.0
  hard_rules:
    block_fullbit_during_raid_resync: true
"""


def _render_run_scan() -> str:
    """The launcher the scheduled task invokes: set env, run one scan pass, propagate the code.

    Prefers the bundled frozen exe (``fathomline-agent.exe``, when packaging ships it); falls back
    to ``py -3 -m fathom.agent`` for a Python-on-host install. No interpolated values — fully
    static — so it carries no injection surface.
    """
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "$Root = $PSScriptRoot\n"
        "$env:FATHOM_AGENT_CONFIG = Join-Path $Root 'agent.config.yaml'\n"
        "$env:FATHOM_AGENT_STAGING = Join-Path $Root 'staging.sqlite'\n"
        "$env:FATHOM_AGENT_OPERATOR = 'fathomline-agent'\n"
        "$exe = Join-Path $Root 'fathomline-agent.exe'\n"
        "if (Test-Path $exe) { & $exe scan } else { & py -3 -m fathom.agent scan }\n"
        "exit $LASTEXITCODE\n"
    )


def _render_install(spec: WindowsBundleSpec) -> str:
    """The installer: register a daily Scheduled Task running the launcher as SYSTEM.

    Idempotent (``-Force`` replaces an existing task of the same name). Requires admin — which
    installing a system-wide scheduled task needs anyway. ``host_id`` and ``start_time`` are the
    only interpolated values and are both charset-validated to a set with no PowerShell
    metacharacters; ``host_id`` is additionally single-quoted where it appears in a string literal.
    """
    task_name = f"Fathomline Agent Scan ({spec.host_id})"
    return f"""#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Runner = Join-Path $Root 'run-scan.ps1'
$TaskName = {_ps_sq(task_name)}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $Runner + '"')
$trigger = New-ScheduledTaskTrigger -Daily -At '{spec.start_time}'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount `
  -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
  -ExecutionTimeLimit (New-TimeSpan -Hours 12)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null
Write-Host ('Fathomline agent scheduled task installed: ' + {_ps_sq(spec.host_id)})
Write-Host 'It runs read-only, daily at {spec.start_time}. Remove with: Unregister-ScheduledTask'
"""


def _render_readme(spec: WindowsBundleSpec) -> str:
    return (
        f"Fathomline Windows agent — host {spec.host_id} (ADR-027 W1, read-only).\n\n"
        "Installed by install-agent.ps1 as a daily Scheduled Task running run-scan.ps1 as SYSTEM.\n"
        "It scans the configured paths (metadata only) and pushes to core over CA-pinned mTLS.\n\n"
        f"Config:     agent.config.yaml\n"
        f"Certs:      certs\\\n"
        f"Run now:    powershell -ExecutionPolicy Bypass -File run-scan.ps1\n"
        f"Uninstall:  Unregister-ScheduledTask -TaskName 'Fathomline Agent Scan ({spec.host_id})'\n"
    )


def build_windows_agent_bundle(spec: WindowsBundleSpec, minted: MintedCert) -> AgentBundle:
    """Render the Windows bundle (config + certs + PowerShell installer/launcher) as path→bytes.

    Returns the same :class:`~fathom.core.deploy.bundle.AgentBundle` container as the Linux builder;
    the route packs it as a **zip** (PowerShell ``Expand-Archive``; Server 2016 has no ``tar.exe``).
    """
    files: dict[str, bytes] = {
        "agent.config.yaml": _render_config(spec).encode("utf-8"),
        "run-scan.ps1": _render_run_scan().encode("utf-8"),
        "install-agent.ps1": _render_install(spec).encode("utf-8"),
        "README.txt": _render_readme(spec).encode("utf-8"),
        "certs/client.crt": minted.cert_pem.encode("utf-8"),
        "certs/client.key": minted.key_pem.encode("utf-8"),
        "certs/fathom-ca.crt": minted.ca_cert_pem.encode("utf-8"),
    }
    return AgentBundle(files=files)
