"""Agent configuration models (ADD 02 §"Configuration model").

Pydantic v2, fail-fast, no silent defaults for required fields (code-quality #10). The
throttle profile is the machine-readable form of the non-impact contract; ``scan_scope``
is an allow-list the agent refuses to scan outside of (and which the server independently
re-enforces — never trust the agent alone, AR-0012). ``write_enabled`` defaults to
``False``: remediation is off until a deliberate, documented deployment step turns it on.
"""

from __future__ import annotations

import posixpath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from fathom.adapters.config import AdapterConfig
from fathom.security.paths import PathSafetyError, validate_config_path

IoClass = Literal["idle", "best-effort", "realtime"]
RemoteProtocol = Literal["smb", "sftp", "rclone"]

Percent = Annotated[float, Field(ge=0.0, le=100.0)]
PositiveInt = Annotated[int, Field(ge=1)]


class PauseRules(BaseModel):
    """Ceilings that move a running scan into the ``Paused`` state (ADD 02 state machine)."""

    model_config = ConfigDict(extra="forbid")

    load1_above: float = Field(gt=0.0, description="1-minute loadavg ceiling")
    iowait_above_percent: Percent = Field(description="per-device I/O-wait ceiling")


class ResumeRules(BaseModel):
    """Conditions under which a paused scan resumes (hysteresis vs :class:`PauseRules`)."""

    model_config = ConfigDict(extra="forbid")

    load1_below: float = Field(gt=0.0, description="resume once 1-min loadavg drops below this")


class HardRules(BaseModel):
    """Non-negotiable safety rules enforced regardless of load (ADD 02, ADD 16)."""

    model_config = ConfigDict(extra="forbid")

    block_fullbit_during_raid_resync: bool = True


class ThrottleProfile(BaseModel):
    """The enforced (not advisory) throttle profile for a scan (ADD 02 §throttle)."""

    model_config = ConfigDict(extra="forbid")

    io_class: IoClass = "idle"
    io_max_mbps: PositiveInt = 80
    cpu_max_percent: Percent = 40.0
    walk_concurrency: PositiveInt = 4
    hash_concurrency: PositiveInt = 2
    pause_when: PauseRules
    resume_when: ResumeRules
    hard_rules: HardRules = Field(default_factory=HardRules)

    @field_validator("resume_when")
    @classmethod
    def _resume_below_pause(cls, value: ResumeRules, info: ValidationInfo) -> ResumeRules:
        pause = info.data.get("pause_when")
        if pause is not None and value.load1_below >= pause.load1_above:
            raise ValueError(
                "resume_when.load1_below must be below pause_when.load1_above (hysteresis)"
            )
        return value


class RemoteBackendConfig(BaseModel):
    """A single remote scan target for an SMB or SFTP backend (config-only, not persisted).

    The storage-backends subsystem walks remote shares metadata-only (full-bit never runs over
    SMB/SFTP — ADD 02 line 63). Secret material is **by reference**, never by value:
    ``password_ref`` and ``private_key_ref`` name secrets the agent resolves at runtime via the
    pluggable secret backend (ADR-010), exactly like the adapter's ``api_key_ref`` — there is no
    field that can carry key material, so a secret can never land in code/config (STRIDE I-2). The
    ``username`` is an identity, not a secret, so it is a plain literal value.

    ``verify`` (host-key / TLS verification) defaults ``True``; the only way to permit an
    unverified transport is the loud, lab-only ``lab_insecure`` flag, validated to be deliberate
    (parity with :class:`~fathom.adapters.config.AdapterConfig`, code-quality #6).
    """

    model_config = ConfigDict(extra="forbid")

    protocol: RemoteProtocol
    host: str = Field(min_length=1)
    # SMB: the share name (``\\host\share`` → ``share``). SFTP: irrelevant (path is the root).
    share: str | None = None
    # The remote root path to walk; an allow-list anchor, not a free target (server re-enforces).
    remote_path: str = Field(min_length=1, default="/")
    port: PositiveInt | None = None
    # Username is an identity (not a secret) — a plain literal value.
    username: str | None = None
    # Secret *references* only (ADR-010). Resolved via the agent's secret_provider at runtime.
    password_ref: str | None = None
    private_key_ref: str | None = None
    # Host-key / TLS verification on by default; only ``lab_insecure`` may turn it off (loudly).
    verify: bool = True
    lab_insecure: bool = False

    @field_validator("host")
    @classmethod
    def _host_no_scheme(cls, value: str) -> str:
        if "://" in value or "/" in value or "\\" in value:
            raise ValueError("host must be a bare hostname/IP, no scheme or path components")
        return value

    @model_validator(mode="after")
    def _validate_protocol_shape_and_security(self) -> RemoteBackendConfig:
        if self.protocol == "smb" and not self.share:
            raise ValueError("smb remote target requires a 'share' name")
        if self.protocol == "rclone" and (self.password_ref or self.private_key_ref):
            # rclone auth lives in the host's rclone.conf (configured out of band) — not here.
            raise ValueError(
                "rclone remote target takes no credential references; configure the remote in "
                "the host's rclone.conf (host = the rclone remote name, remote_path = its subpath)"
            )
        if not self.verify and not self.lab_insecure:
            raise ValueError(
                "verify=False requires lab_insecure=True (host-key/TLS verification is "
                "mandatory outside the lab profile, security_constraints)"
            )
        # Path-containment (ADR-029/AR-0012): remote_path/share are interpolated into
        # ``catalogue_mount``, which the catalogue/ingest/read contract treats as a POSIX-absolute
        # anchor. A ``..`` segment (or a control/backslash char) would let the synthetic mount
        # normalise OUT into a real local namespace (e.g. /sftp/h/../../etc → /etc) and alias a
        # genuine local volume's entries. Reject fail-closed; the deploy bundle and the server-side
        # ingest re-vet refuse the same shape.
        for label, val in (("remote_path", self.remote_path), ("share", self.share)):
            if not val:
                continue
            if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in val):
                raise ValueError(f"{label} must not contain control characters")
            if "\\" in val:
                raise ValueError(f"{label} must not contain a backslash")
            if ".." in val.split("/"):
                raise ValueError(f"{label} must not contain a '..' path-traversal segment")
        return self

    @property
    def mount_key(self) -> str:
        """The human ``scheme://`` identifier (no credentials) — the scan-root id + display label.

        Used as the scan root the runner passes to the backend, the backend ``supports()`` match,
        and (ADR-029) the volume ``display_name`` shown in the UI. It is NOT the stored mountpoint:
        ``scheme://`` is not a POSIX-absolute path, which the catalogue/ingest/read contract
        requires — see :attr:`catalogue_mount`.
        """
        if self.protocol == "smb":
            return f"smb://{self.host}/{self.share}{self.remote_path}"
        if self.protocol == "rclone":
            # host = the rclone remote name (e.g. "gdrive"); remote_path = the subpath within it.
            return f"rclone://{self.host}{self.remote_path}"
        return f"sftp://{self.host}{self.remote_path}"

    @property
    def catalogue_mount(self) -> str:
        """POSIX-absolute synthetic mountpoint stored as ``Volume.mountpoint`` (ADR-029).

        The catalogue, ingest's AR-0012 re-vetting, and every read query require an absolute
        mountpoint that each entry path is string-prefixed by; a ``scheme://`` ``mount_key`` is
        neither. This synthetic path is that anchor — remote backends anchor their entries under
        it — so remote volumes conform to the same contract POSIX volumes already meet WITHOUT any
        change to the vetting/read logic. The pretty ``mount_key`` rides along as ``display_name``.
        """
        if self.protocol == "smb":
            base = f"/smb/{self.host}/{self.share}{self.remote_path}"
        elif self.protocol == "rclone":
            sub = self.remote_path.strip("/")
            base = f"/rclone/{self.host}/{sub}" if sub else f"/rclone/{self.host}"
        else:
            base = f"/sftp/{self.host}{self.remote_path}"
        # Canonicalise (POSIX, never os.path — the agent may run on Windows but the catalogue
        # mount is always POSIX). A safe-but-cosmetically-non-canonical remote_path/share (e.g.
        # '/data//sub' or '/a/./b') would otherwise be transmitted verbatim and then 422'd by the
        # server's canonical-mountpoint re-vet (ingest re-runs the same normpath). `..` can't reach
        # here — it is rejected in _validate_protocol_shape_and_security.
        return posixpath.normpath(base)


# ADR-033: the ONLY fields an operator may override per-host from the core — safe, non-secret,
# non-identity. NOT write_enabled (enabling the write/quarantine path remotely is too sensitive),
# and never host_id / ingest_url / cert paths / secret refs (identity + transport stay local).
_OVERRIDABLE_FIELDS = frozenset(
    {"scan_scope", "fullbit_scope", "exclude_scope", "cross_mounts", "throttle"}
)


class AgentConfig(BaseModel):
    """Top-level agent configuration. Required fields have no silent defaults."""

    model_config = ConfigDict(extra="forbid")

    host_id: str = Field(min_length=1)
    ingest_url: str
    client_cert_path: str
    client_key_path: str
    server_ca_path: str
    # Local scan roots. May be empty for a remote-only agent (it scans only ``remote_targets``);
    # the model validator below requires at least one of scan_scope / remote_targets (ADR-029).
    scan_scope: list[str] = Field(default_factory=list)
    # Optional full-bit allow-list: a subset of ``scan_scope`` the agent will content-hash. A
    # full-bit job whose target is not within this list is refused (defence-in-depth on top of
    # the per-scan impact ack + resync gate; fullbit-dedup files_to_modify). Empty by default →
    # full-bit is opt-in per deployment, never implicit.
    fullbit_scope: list[str] = Field(default_factory=list)
    # Optional exclude list (ADR-034): absolute directory prefixes the walk PRUNES — it never
    # descends into, nor reports, any path at or under an excluded prefix. Subtree semantics (e.g.
    # exclude /var/lib/docker, or C:\Windows, under a wider scan root). Operator-overridable
    # (ADR-033) and re-validated like scan_scope. Empty by default. Glob patterns are out of scope.
    exclude_scope: list[str] = Field(default_factory=list)
    write_enabled: bool = False
    # --- Remediation actor trust (remediation-enable; only used when write_enabled) --------
    # The trusted-key reference the actor's signed-job listener verifies orchestrator jobs
    # against. ``orchestrator_pubkey_ref`` is a *reference* into the agent's secret backend
    # for the orchestrator's Ed25519 public key (or the shared HMAC secret in fallback mode) —
    # never the key itself (ADR-010). ``orchestrator_key_id`` is the non-secret key id the
    # actor pins (rejecting any job signed under a different key id). The actor refuses every
    # job unless these are configured AND write_enabled is True (no execute path otherwise).
    orchestrator_pubkey_ref: str | None = None
    orchestrator_key_id: str = "orchestrator-v1"
    # The signing algorithm the actor pins for the orchestrator key. Default Ed25519 (owner ruling,
    # non-repudiation); "hmac-sha256" ONLY for the documented symmetric fallback. The listener
    # requires the resolved key material to match this exactly — a mismatch fails loud at startup,
    # so a misconfigured key type can never silently produce a broken-but-not-erroring verifier
    # (ADR-025 adversarial-review fix: no algorithm auto-detection / confusion).
    orchestrator_signing_algorithm: str = "ed25519"
    # The quarantine tier the executor moves removed duplicates into (reversible, ADR-011).
    # An absolute path owned by strata-actor; required before any execute can run.
    quarantine_dir: str | None = None
    # Durable local act-audit log for listen mode (ADR-025 adversarial-review fix): the executor
    # also records each act here as an append-only JSONL, so even if a result post is lost (a core
    # restart in the act→result window) there is still a tamper-evident record of what the actor did
    # on this host — preserving audit-before-act durability agent-side, not only via core's splice.
    # Defaults to ``<quarantine_dir>/.act-audit.jsonl`` when unset (resolved at listen startup).
    act_audit_path: str | None = None
    # Descend into nested mounts under a scope root (e.g. ZFS child datasets under a pool
    # like tank, which each have their own device id). Off keeps a scan inside the
    # root's filesystem.
    cross_mounts: bool = False
    # Optional control-plane adapter (ADD 04) + the pool whose resilver state gates full-bit on
    # this host. On a pure-ZFS/TrueNAS host there is no ``/proc/mdstat``, so without an adapter the
    # full-bit resync guard fails closed and blocks full-bit forever (AR-0002 §5). Wiring the
    # TrueNAS adapter (e.g. over the on-box ``unix://`` middleware socket, api_key_ref by-reference)
    # lets the guard read the REAL pool state — pausing on a true resilver, allowing when idle.
    # ``adapter_pool`` is required when ``adapter`` is set (the pool the guard checks).
    adapter: AdapterConfig | None = None
    adapter_pool: str | None = None
    # Optional remote SMB/SFTP scan targets (storage-backends subsystem). Empty by default; a
    # remote target is metadata-only (full-bit never runs over SMB/SFTP — ADD 02 line 63) and
    # still gated by ``scan_scope``/server re-enforcement (AR-0012). Creds are by reference only.
    remote_targets: list[RemoteBackendConfig] = Field(default_factory=list)
    # --- Distributed preview grant-serve trust (ADR-014; only used when set) ----------------------
    # When ``preview_grant_pubkey_ref`` is set the agent runs the preview grant-serve loop: it
    # long-polls core for a signed FileGrant for one of ITS files, verifies it against this PINNED
    # core grant public key (a *reference* into the secret backend, never the key — ADR-010), reads
    # exactly that one file (O_NOFOLLOW + inode-anchored + bounded, via LocalFileFetcher) and serves
    # the bytes back. Read-only: it does NOT require ``write_enabled``/``quarantine_dir`` (the
    # remediation gates). The single-use nonce ledger lives in ``preview_nonce_dir`` (defaults to
    # ``quarantine_dir`` when that is set). Absent the ref, the loop never starts (default-off).
    preview_grant_pubkey_ref: str | None = None
    preview_grant_key_id: str = "preview-v1"
    preview_nonce_dir: str | None = None
    # --- Live directory browse-serve trust (ADR-034 Phase 2; only used when set) ---------------
    # When ``browse_grant_pubkey_ref`` is set the agent runs the read-only browse-serve loop: it
    # long-polls core for a signed BrowseRequest for THIS host, verifies it against this PINNED core
    # browse public key (a *reference* into the secret backend, never the key — ADR-010), lists
    # exactly that one directory (metadata only — names/sizes/counts, NEVER contents) and serves it
    # back. Read-only: it does NOT require ``write_enabled``/``quarantine_dir`` (the remediation
    # gates) — browse trust is not write trust. The single-use nonce ledger lives in
    # ``browse_nonce_dir`` (defaults to ``preview_nonce_dir``/``quarantine_dir``). Absent the ref,
    # the loop never starts (default-off).
    browse_grant_pubkey_ref: str | None = None
    browse_grant_key_id: str = "browse-v1"
    browse_nonce_dir: str | None = None
    throttle: ThrottleProfile

    @field_validator("ingest_url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("ingest_url must be https:// (fail-closed transport, ADD 03)")
        return value

    @field_validator("client_cert_path", "client_key_path", "server_ca_path")
    @classmethod
    def _abs_path(cls, value: str) -> str:
        try:
            return str(validate_config_path(value))
        except PathSafetyError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("quarantine_dir", "act_audit_path", "preview_nonce_dir", "browse_nonce_dir")
    @classmethod
    def _opt_abs_path(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        try:
            return str(validate_config_path(value))
        except PathSafetyError as exc:
            raise ValueError(f"{info.field_name}: {exc}") from exc

    @field_validator("scan_scope", "fullbit_scope", "exclude_scope")
    @classmethod
    def _scope_paths_absolute(cls, value: list[str], info: ValidationInfo) -> list[str]:
        normalised: list[str] = []
        for root in value:
            try:
                normalised.append(str(validate_config_path(root)))
            except PathSafetyError as exc:
                raise ValueError(f"{info.field_name} entry {root!r}: {exc}") from exc
        return normalised

    @model_validator(mode="after")
    def _adapter_pool_required_with_adapter(self) -> AgentConfig:
        """An adapter needs the pool whose resilver state it gates full-bit on (ADD 04)."""
        if self.adapter is not None and not self.adapter_pool:
            raise ValueError("adapter is configured but adapter_pool (the gated pool) is not set")
        return self

    @model_validator(mode="after")
    def _must_scan_something(self) -> AgentConfig:
        """An agent must scan *something* — local roots and/or remote targets (ADR-029).

        ``scan_scope`` may be empty for a remote-only agent (e.g. one that scans only a cloud
        remote), but an agent with neither is a misconfiguration, not a no-op.
        """
        if not self.scan_scope and not self.remote_targets:
            raise ValueError("at least one scan_scope entry or remote_targets entry is required")
        return self

    @model_validator(mode="after")
    def _fullbit_within_scan_scope(self) -> AgentConfig:
        """Every full-bit root must lie within ``scan_scope`` — full-bit can't widen scope."""
        for root in self.fullbit_scope:
            if not self.in_scope(root):
                raise ValueError(
                    f"fullbit_scope entry {root!r} is not within scan_scope "
                    "(full-bit may only narrow, never widen, the scanned scope)"
                )
        return self

    def in_scope(self, target: str) -> bool:
        """Return whether ``target`` lies within the configured ``scan_scope`` allow-list.

        The agent refuses any job whose target is not within scope; the server enforces
        the same check independently (AR-0012).
        """
        try:
            candidate = validate_config_path(target)
        except PathSafetyError:
            return False
        for root in self.scan_scope:
            root_path = validate_config_path(root)
            if candidate == root_path or root_path in candidate.parents:
                return True
        return False

    def in_fullbit_scope(self, target: str) -> bool:
        """Return whether ``target`` is within the full-bit allow-list (``fullbit_scope``).

        Full-bit content reads are gated by this on top of ``scan_scope``: a target outside the
        full-bit allow-list is refused even if it is within the metadata scan scope.
        """
        if not self.fullbit_scope:
            return False
        try:
            candidate = validate_config_path(target)
        except PathSafetyError:
            return False
        for root in self.fullbit_scope:
            root_path = validate_config_path(root)
            if candidate == root_path or root_path in candidate.parents:
                return True
        return False

    def is_excluded(self, target: str) -> bool:
        """Return whether ``target`` lies at or under an ``exclude_scope`` prefix (ADR-034).

        The walk prunes such paths — it neither reports them nor descends into them. An unsafe
        target (path-validation failure) is treated as excluded (fail-closed: don't scan it).
        """
        if not self.exclude_scope:
            return False
        try:
            candidate = validate_config_path(target)
        except PathSafetyError:
            return True
        for ex in self.exclude_scope:
            ex_path = validate_config_path(ex)
            if candidate == ex_path or ex_path in candidate.parents:
                return True
        return False

    def reportable(self) -> dict[str, object]:
        """The EFFECTIVE config to report to the core for the Agents UI (ADR-033 #9).

        Only the observable, operator-relevant fields — no secret refs, no cert/quarantine paths,
        no identity/transport. This is what the core stores on ``host.reported_config`` and shows.
        """
        return {
            "scan_scope": list(self.scan_scope),
            "fullbit_scope": list(self.fullbit_scope),
            "exclude_scope": list(self.exclude_scope),
            "cross_mounts": self.cross_mounts,
            "write_enabled": self.write_enabled,
            "throttle": self.throttle.model_dump(mode="json"),
        }

    def with_override(self, override: dict[str, object]) -> AgentConfig:
        """Return a NEW config with the operator override merged over ONLY ``_OVERRIDABLE_FIELDS``
        and the whole result **re-validated** by this model (ADR-033 #10).

        Identity / transport / secret fields are never taken from ``override``. Raises
        ``pydantic.ValidationError`` if the merged config is invalid (e.g. fullbit ⊄ scan, bad
        throttle, unsafe path) — the agent run-start caller catches it and keeps its LOCAL config
        (fail-safe). An empty / all-unknown override is a no-op (returns ``self``).
        """
        safe = {k: v for k, v in override.items() if k in _OVERRIDABLE_FIELDS}
        if not safe:
            return self
        merged = self.model_dump(mode="python")
        merged.update(safe)
        return AgentConfig.model_validate(merged)
