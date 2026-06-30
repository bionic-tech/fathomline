"""Agent bundle generation (ADR-026 §bundle).

Produces the exact file set a fleet host needs to run a scan agent — the same shape as the
hand-rolled ``deploy/<host>/`` bundles, but templated from the deploy request and the freshly
minted cert:

    docker-compose.yml      # read-only, cap-dropped scan agent, mem-capped
    agent.config.yaml       # host_id + ingest_url + scan/fullbit scope + throttle
    certs/client.crt
    certs/client.key
    certs/fathom-ca.crt

The push engine uploads these over SFTP; the pull bootstrap reconstructs them from the served
archive. Mount paths default to ``/scan/data`` → host ``/mnt/data`` (the fleet convention) but are
overridable per request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from fathom.core.deploy import DeploymentError
from fathom.core.deploy.certs import MintedCert

# host_id becomes a container name, a YAML value, and the agent's cert CN — constrain it to a safe
# charset so a crafted value cannot inject compose/YAML directives or shell metacharacters
# (threat-model E-2, defence-in-depth even though the operator is an authenticated admin). Capped at
# 57 chars so ``<host_id>-agent`` (the cert CN) stays within X.509's 64-char limit (round-3 P1).
_HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,56}$")
# proxy_host_ip is interpolated into a remote shell test and the compose extra_hosts — a hostname
# or IP literal only (no shell metacharacters / quotes / whitespace).
_HOST_OR_IP_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")


def validate_host_id(host_id: str) -> str:
    """Return ``host_id`` if it is a safe identifier, else raise :class:`DeploymentError`."""
    if not _HOST_ID_RE.match(host_id):
        raise DeploymentError(
            f"invalid host_id {host_id!r} (letters/digits/._- only, ≤63 chars, "
            "must start alphanumeric)"
        )
    return host_id


def validate_host_or_ip(value: str) -> str:
    """Return ``value`` if it is a safe hostname/IP literal, else raise :class:`DeploymentError`."""
    if not _HOST_OR_IP_RE.match(value):
        raise DeploymentError(f"invalid host/IP {value!r} (no shell metacharacters)")
    return value


@dataclass(frozen=True, slots=True)
class ScopeMount:
    """One scanned tree: the agent-visible path, the host source dir, and whether to full-bit it."""

    container_path: str
    host_path: str
    fullbit: bool = True


# A remote-target value lands in the generated agent.config.yaml (single-quoted) and the agent
# re-validates it as a RemoteBackendConfig. Reject anything that could break the YAML scalar or
# carry a control character before it ever reaches the file (defence-in-depth, ADR-026 E-2 style).
_REMOTE_PROTOCOLS = frozenset({"rclone", "smb", "sftp"})
_SECRET_REF_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")  # a bare secret name (no path), ADR-010


def _reject_yaml_unsafe(value: str, *, field: str) -> None:
    # C0 (<32), DEL (127) and the C1 range (128-159) are all rejected: besides breaking the
    # single-quoted scalar / smuggling a newline-directive, DEL and C1 bytes are outside PyYAML's
    # "printable" set and make the agent's yaml.safe_load raise a hard ReaderError — i.e. they would
    # produce a bundle the agent cannot parse, defeating fail-closed-at-request-time. We also forbid
    # the single quote (which YAML would otherwise escape by doubling).
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value) or "'" in value:
        raise DeploymentError(f"unsafe character in remote target {field}: {value!r}")


@dataclass(frozen=True, slots=True)
class RemoteTargetSpec:
    """One remote scan target generated into the bundle's agent config (ADR-026 + ADR-028/029).

    Mirrors the safe subset of :class:`~fathom.agent.config.RemoteBackendConfig`. Credentials are
    *references* only (ADR-010) and apply to SMB/SFTP; rclone auth lives in the host's rclone.conf
    (a credential reference on an rclone target is rejected). The agent re-validates the rendered
    config, so this is the first (fail-closed) line of defence, not the only one.
    """

    protocol: str
    host: str
    remote_path: str = "/"
    share: str | None = None
    port: int | None = None
    username: str | None = None
    password_ref: str | None = None
    private_key_ref: str | None = None
    verify: bool = True
    lab_insecure: bool = False

    def __post_init__(self) -> None:
        if self.protocol not in _REMOTE_PROTOCOLS:
            raise DeploymentError(f"unknown remote protocol {self.protocol!r}")
        if not self.host or "://" in self.host or any(c in self.host for c in "/\\"):
            raise DeploymentError(f"invalid remote host {self.host!r} (bare hostname/remote name)")
        # The agent's RemoteBackendConfig enforces remote_path min_length=1; an explicit "" beats
        # the "/" default and would pass the bundle but crash the agent at config-load. Reject here
        # so the bundle stays a true superset of the agent's validation (fail-closed-at-request).
        if not self.remote_path:
            raise DeploymentError("remote target remote_path must not be empty (use '/')")
        _reject_yaml_unsafe(self.host, field="host")
        _reject_yaml_unsafe(self.remote_path, field="remote_path")
        if self.protocol == "smb" and not self.share:
            raise DeploymentError("smb remote target requires a share")
        if self.share is not None:
            _reject_yaml_unsafe(self.share, field="share")
        # Path-containment (ADR-029): a ``..`` segment in remote_path/share would, once the agent
        # builds catalogue_mount, normalise out of the synthetic namespace into a real local path
        # (e.g. /sftp/h/../../etc → /etc) and alias another volume's entries. The agent config
        # re-validates this too, but the bundle is the first fail-closed line of defence.
        for _label, _val in (("remote_path", self.remote_path), ("share", self.share)):
            if not _val:
                continue
            if "\\" in _val:
                raise DeploymentError(f"remote target {_label} must not contain a backslash")
            if ".." in _val.split("/"):
                raise DeploymentError(f"remote target {_label} must not contain a '..' segment")
        if self.username is not None:
            _reject_yaml_unsafe(self.username, field="username")
        if self.protocol == "rclone" and (self.password_ref or self.private_key_ref):
            raise DeploymentError("rclone target takes no credential references (uses rclone.conf)")
        for ref in (self.password_ref, self.private_key_ref):
            if ref is not None and not _SECRET_REF_RE.match(ref):
                raise DeploymentError(f"invalid secret reference {ref!r} (bare name, ADR-010)")
        if self.port is not None and not (1 <= self.port <= 65535):
            raise DeploymentError(f"invalid port {self.port!r}")
        if not self.verify and not self.lab_insecure:
            raise DeploymentError("verify=False requires lab_insecure=True (security_constraints)")


@dataclass(frozen=True, slots=True)
class BundleSpec:
    """Everything the bundle templater needs that is not the cert."""

    host_id: str
    ingest_url: str
    image: str
    mounts: tuple[ScopeMount, ...]
    # The IP/hostname the target maps "proxy" to (compose extra_hosts) — deployment-specific,
    # resolved by the caller from the request or FATHOM_AGENT_DEPLOYMENT_PROXY_HOST_IP.
    proxy_host_ip: str
    # Optional remote scan targets (rclone/SMB/SFTP) generated into the agent config (ADR-029).
    remote_targets: tuple[RemoteTargetSpec, ...] = ()
    mem_limit: str = "3g"
    cpus: float = 4.0

    def __post_init__(self) -> None:
        validate_host_id(self.host_id)
        if not _HOST_OR_IP_RE.match(self.proxy_host_ip):
            raise DeploymentError(f"invalid proxy_host_ip {self.proxy_host_ip!r}")
        # ingest_url + image are interpolated into the generated YAML config/compose and the image
        # into a shell `docker image inspect` — validate them too (round-5 F3; they had escaped the
        # injection sweep). ingest_url must be https (the agent is https-only; fail-closed).
        if not self.ingest_url.startswith("https://") or any(
            c in self.ingest_url for c in '\n\r" '
        ):
            raise DeploymentError(f"invalid ingest_url {self.ingest_url!r} (https, no metachars)")
        if not self.image or any(c in self.image for c in '\n\r" '):
            raise DeploymentError(f"invalid image {self.image!r}")
        # A bundle must scan *something* — local mounts or remote targets (ADR-029).
        if not self.mounts and not self.remote_targets:
            raise DeploymentError("bundle requires at least one scan scope mount or remote target")
        for m in self.mounts:
            if not m.container_path.startswith("/") or not m.host_path.startswith("/"):
                raise DeploymentError(f"scope mount paths must be absolute: {m}")
            # Paths land in YAML + a docker volume spec; a newline or ':' could inject directives.
            for p in (m.container_path, m.host_path):
                if any(c in p for c in "\n\r:") or '"' in p:
                    raise DeploymentError(f"unsafe character in scope path: {p!r}")


@dataclass(frozen=True, slots=True)
class AgentBundle:
    """The generated file set, keyed by bundle-relative path → bytes."""

    files: dict[str, bytes] = field(default_factory=dict)


def _yaml_list(items: list[str]) -> str:
    return "\n".join(f"  - {it}" for it in items)


def _yaml_sq(value: str) -> str:
    """A YAML single-quoted scalar (``'`` doubled). Values are pre-validated to exclude ``'``."""
    return "'" + value.replace("'", "''") + "'"


def _yaml_dict(items: dict[str, str]) -> str:
    """A YAML mapping block — single-quoted keys + values (both pre-validated to exclude ``'``)."""
    return "\n".join(f"  {_yaml_sq(k)}: {_yaml_sq(v)}" for k, v in sorted(items.items()))


def _render_remote_targets(targets: tuple[RemoteTargetSpec, ...]) -> str:
    """Render the ``remote_targets:`` block (rclone/SMB/SFTP), or ``  []`` when none.

    rclone targets additionally need the agent image to ship the ``rclone`` binary (ADR-028) —
    the default agent image does not, so a deployment using rclone must point ``image`` at one
    that does. SMB/SFTP need no extra binary (asyncssh/smbprotocol are in the base image).
    """
    if not targets:
        return "  []"
    blocks: list[str] = []
    for t in targets:
        lines = [
            f"  - protocol: {t.protocol}",
            f"    host: {_yaml_sq(t.host)}",
            f"    remote_path: {_yaml_sq(t.remote_path)}",
        ]
        if t.share is not None:
            lines.append(f"    share: {_yaml_sq(t.share)}")
        if t.port is not None:
            lines.append(f"    port: {t.port}")
        if t.username is not None:
            lines.append(f"    username: {_yaml_sq(t.username)}")
        if t.password_ref is not None:
            lines.append(f"    password_ref: {_yaml_sq(t.password_ref)}")
        if t.private_key_ref is not None:
            lines.append(f"    private_key_ref: {_yaml_sq(t.private_key_ref)}")
        lines.append(f"    verify: {str(t.verify).lower()}")
        lines.append(f"    lab_insecure: {str(t.lab_insecure).lower()}")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


def _render_config(spec: BundleSpec) -> str:
    scan_scope = [m.container_path for m in spec.mounts]
    fullbit_scope = [m.container_path for m in spec.mounts if m.fullbit]
    scope_block = _yaml_list(scan_scope) if scan_scope else "  []"
    fullbit_block = _yaml_list(fullbit_scope) if fullbit_scope else "  []"
    # ADR-029 relabel: map each scan root (container mount) → its real host path so the UI shows the
    # real drive (display_name) instead of the synthetic /scan/... mount. Only when they differ.
    labels = {m.container_path: m.host_path for m in spec.mounts if m.host_path != m.container_path}
    labels_block = _yaml_dict(labels) if labels else "  {}"
    return f"""# Fathom agent config for {spec.host_id} — generated by deploy (ADR-026).
# Read-only, throttled; pushes full-bit + metadata to core over CA-pinned mTLS.
host_id: {spec.host_id}
ingest_url: {spec.ingest_url}
client_cert_path: /certs/client.crt
client_key_path:  /certs/client.key
server_ca_path:   /certs/fathom-ca.crt
scan_scope:
{scope_block}
fullbit_scope:
{fullbit_block}
scope_labels:
{labels_block}
remote_targets:
{_render_remote_targets(spec.remote_targets)}
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


def _render_compose(spec: BundleSpec) -> str:
    volumes = [
        "      - ./agent.config.yaml:/config/agent.config.yaml:ro",
        "      - ./certs:/certs:ro",
        "      - fathom-staging:/var/lib/fathom",
    ]
    volumes += [f"      - {m.host_path}:{m.container_path}:ro" for m in spec.mounts]
    volumes_block = "\n".join(volumes)
    return f"""# Fathom scan agent on {spec.host_id} — generated by the deploy subsystem (ADR-026).
# Read-only, cap-dropped (uid 0 + DAC_READ_SEARCH only), mem-capped. Pushes to core via the
# mTLS proxy. Start: docker compose up -d agent
name: fathom-agent-{spec.host_id}
services:
  agent:
    image: {spec.image}
    container_name: fathom-agent-{spec.host_id}
    user: "0:0"
    cap_drop: ["ALL"]
    cap_add: ["DAC_READ_SEARCH"]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/tmp"]
    command: ["python", "-m", "fathom.agent"]
    environment:
      FATHOM_AGENT_CONFIG: /config/agent.config.yaml
      FATHOM_AGENT_STAGING: /var/lib/fathom/staging.sqlite
      FATHOM_AGENT_OPERATOR: fathom-agent-{spec.host_id}
    extra_hosts:
      - "proxy:{spec.proxy_host_ip}"
    volumes:
{volumes_block}
    restart: "no"
    mem_limit: {spec.mem_limit}
    memswap_limit: {spec.mem_limit}
    cpus: {spec.cpus}
volumes:
  fathom-staging:
"""


def build_agent_bundle(spec: BundleSpec, minted: MintedCert) -> AgentBundle:
    """Render the full bundle (compose + config + certs) as ``path -> bytes``."""
    files: dict[str, bytes] = {
        "agent.config.yaml": _render_config(spec).encode("utf-8"),
        "docker-compose.yml": _render_compose(spec).encode("utf-8"),
        "certs/client.crt": minted.cert_pem.encode("utf-8"),
        "certs/client.key": minted.key_pem.encode("utf-8"),
        "certs/fathom-ca.crt": minted.ca_cert_pem.encode("utf-8"),
    }
    return AgentBundle(files=files)
