"""API wire schemas (Pydantic v2) — validated at every boundary (standards/18 §4).

These are the over-the-wire contracts for the agent→core push. They are intentionally
distinct from the ORM rows: the server never trusts an agent-supplied identity or path
without re-validating it (AR-0012).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class HostFrame(BaseModel):
    """Agent self-description; the authoritative identity is the mTLS fingerprint."""

    name: str = Field(min_length=1, max_length=255)
    os: str | None = Field(default=None, max_length=255)
    agent_version: str | None = Field(default=None, max_length=64)


class VolumeFrame(BaseModel):
    """The volume a batch belongs to (ADD 04 topology)."""

    mountpoint: str = Field(min_length=1, max_length=4096)
    fs_type: str = Field(max_length=64)
    device: str = Field(max_length=255)
    transport: str = Field(max_length=32)
    raid_role: str | None = Field(default=None, max_length=255)
    pool: str | None = Field(default=None, max_length=255)
    dataset: str | None = Field(default=None, max_length=255)
    total: int = Field(ge=0)
    used: int = Field(ge=0)
    free: int = Field(ge=0)
    # Human label for a synthetic-mountpoint (remote) volume (ADR-029); None for local volumes.
    display_name: str | None = Field(default=None, max_length=4096)


# A BLAKE3 hexdigest is 64 lowercase hex chars (32-byte default). Validated at the boundary
# so a malformed hash can never reach the dedup grouping (risks: hash column length/format).
_BLAKE3_HEX = "^[0-9a-f]{64}$"
# A provider-attested hash (ADR-028) varies by algorithm (md5=32 hex, sha1=40, sha256=64,
# quickxorhash/dropbox are base64-ish). Bounded, charset-restricted; the algo is a short token.
_PROVIDER_HASH = r"^[A-Za-z0-9+/=_-]{1,128}$"
_PROVIDER_ALGO = r"^[a-z0-9._-]{1,32}$"


class EntryFrame(BaseModel):
    """One filesystem entry in a push batch (mirrors backends.FsEntry on the wire).

    ``partial_hash`` / ``full_hash`` are carried only on a ``mode='fullbit'`` batch; a metadata
    batch leaves them ``None`` and ingest then leaves the catalogue columns untouched
    (fullbit-dedup data_model_changes). Both are validated as 64-char BLAKE3 hex.
    """

    path: str = Field(min_length=1, max_length=4096)
    name: str = Field(max_length=1024)
    is_dir: bool
    is_symlink: bool
    size_logical: int = Field(ge=0)
    size_on_disk: int = Field(ge=0)
    mtime: float
    ctime: float
    uid: int
    gid: int
    inode: int
    # Device id (``st_dev``) — part of the entry identity so ZFS child datasets that reuse low
    # inode numbers don't collide on the upsert key. Defaults to 0 (single-fs / remote backends).
    dev: int = 0
    flags: dict[str, bool] = Field(default_factory=dict)
    partial_hash: str | None = Field(default=None, pattern=_BLAKE3_HEX)
    full_hash: str | None = Field(default=None, pattern=_BLAKE3_HEX)
    # Provider-attested hash + its algorithm (ADR-028 phase 2). A DISTINCT trust class from the
    # BLAKE3 full_hash: it rides a metadata batch (the agent never read the bytes — the cloud
    # provider computed it), is stored in its own catalogue columns, and is report-only (never
    # drives remediation). Both-or-neither: a hash without its algorithm can't be safely grouped.
    provider_hash: str | None = Field(default=None, pattern=_PROVIDER_HASH)
    provider_hash_algo: str | None = Field(default=None, pattern=_PROVIDER_ALGO)

    @model_validator(mode="after")
    def _provider_hash_pairing(self) -> EntryFrame:
        if (self.provider_hash is None) != (self.provider_hash_algo is None):
            raise ValueError("provider_hash and provider_hash_algo must be set together")
        return self


class IngestBatch(BaseModel):
    """A single resumable, idempotent push from an agent (ADD 02 §7.2).

    ``removed_inodes`` carries the **explicit** deletions the incremental change feed detected
    (incremental owner ruling: an explicit present/removed_at marker, NOT snapshot-staleness
    inference). The server marks those ``(host_id, volume_id, inode)`` rows ``present=False`` and
    emits a ``DELETE`` change_log row — it never deletes the catalogue row. Re-appearing inodes
    resurrect on the next upsert. A metadata batch may carry removals; a fullbit batch never does
    (full-bit re-hashes existing files, it does not detect deletions). The list is bounded by the
    same per-batch limit as ``entries`` so a malformed batch cannot blow up the reconcile step.
    """

    host: HostFrame
    volume: VolumeFrame
    mode: str = Field(pattern="^(metadata|fullbit)$")
    snapshot_id: int | None = None  # None → open a new snapshot
    entries: list[EntryFrame] = Field(default_factory=list)
    removed_inodes: list[int] = Field(default_factory=list)


class IngestResult(BaseModel):
    """Server acknowledgement of an accepted batch.

    ``entries_removed`` is how many of ``removed_inodes`` matched a live catalogue row and were
    flipped to ``present=False`` (incremental reconciliation). ``changes_logged`` is the number
    of ``change_log`` rows the reconciliation emitted (0 when the volume's feed is disabled).
    """

    snapshot_id: int
    host_id: int
    volume_id: int
    entries_received: int
    entries_rejected: int
    entries_removed: int = 0
    changes_logged: int = 0


class FinalizeResult(BaseModel):
    """Server acknowledgement of a post-drain rollup finalize (ADD 09 §8).

    The agent posts this once after its drain so the server recomputes ``subtree_rollup`` (and a
    ``size_history`` point) for the calling host's volumes touched since the last finalize.
    ``volume_ids`` are exactly the volumes recomputed (empty when nothing changed since last
    time); ``rollup_rows`` is the total rollup rows written across them. ``dup_groups`` is the
    number of report-only duplicate groups rebuilt in the same call after a full-bit ingest (``0``
    on a metadata-only deployment, where no full hashes exist — fullbit-dedup, ADD 02 §7.1). The
    host is the authenticated mTLS identity, never the body (AR-0012).
    """

    host_id: int
    volume_ids: list[int]
    rollup_rows: int
    dup_groups: int = 0


# --- read surface -----------------------------------------------------------------------


class VolumeOut(BaseModel):
    """A volume with usage and topology for the volumes view (bar/pie)."""

    model_config = {"from_attributes": True}

    id: int
    host_id: int
    mountpoint: str
    fs_type: str
    device: str
    transport: str
    raid_role: str | None
    total: int
    used: int
    free: int
    # Human label for a synthetic-mountpoint (remote) volume (ADR-029); the UI shows this in
    # preference to the (synthetic) mountpoint. None for local volumes.
    display_name: str | None = None


class TreeChildOut(BaseModel):
    """A child node with aggregated subtree sizes + per-entry metadata for drill-down."""

    entry_id: int
    path: str
    name: str
    is_dir: bool
    is_symlink: bool
    size_logical: int
    size_on_disk: int
    subtree_size_logical: int
    subtree_size_on_disk: int
    file_count: int
    mtime: float
    uid: int
    gid: int
    inode: int
    flags: dict[str, bool]
    content_hash: str | None


class SearchResultOut(BaseModel):
    """One estate-search hit (GET /api/v1/search): enough to render + jump to it in the explorer."""

    path: str
    name: str
    is_dir: bool
    size_logical: int
    size_on_disk: int
    host_id: int
    volume_id: int


class HistoryPointOut(BaseModel):
    """One time-series sample of a subtree's size."""

    model_config = {"from_attributes": True}

    ts: datetime
    total_size_logical: int
    total_size_on_disk: int
    file_count: int


class ChangeOut(BaseModel):
    """One churn row — a created / modified / removed path in a window (ADD 09 §4).

    Read-only, scope-filtered: the churn read for a path/window returns these straight from the
    ``change_log`` (incremental subsystem). ``size_delta`` is signed (negative on shrink/removal).
    """

    model_config = {"from_attributes": True}

    path: str
    change_type: str
    size_delta: int
    ts: datetime


# --- chart surface (ui-viewer; frontend ADD §4/§10) -------------------------------------


class TreemapNodeOut(BaseModel):
    """One sized node for the ECharts treemap/sunburst (one drill level, capped node set)."""

    model_config = {"from_attributes": True}

    path: str
    name: str
    is_dir: bool
    subtree_size_logical: int
    subtree_size_on_disk: int
    file_count: int


class TopNItemOut(BaseModel):
    """One 'biggest offender' row for the bar chart / top-N list."""

    model_config = {"from_attributes": True}

    path: str
    name: str
    is_dir: bool
    size_logical: int
    size_on_disk: int
    file_count: int


class GrowthPointOut(BaseModel):
    """One downsampled point on the growth-over-time series."""

    model_config = {"from_attributes": True}

    ts: datetime
    total_size_logical: int
    total_size_on_disk: int
    file_count: int


class GrowthSeriesOut(BaseModel):
    """A server-downsampled growth series for one subtree (frontend ADD §10)."""

    model_config = {"from_attributes": True}

    volume_id: int
    path: str
    points: list[GrowthPointOut]


# --- duplicates surface (fullbit-dedup; ADD 09 §4, frontend ADD §4) ---------------------


class DuplicateMemberOut(BaseModel):
    """One member of a duplicate group — a single byte-identical copy (read-only).

    ``is_mount_alias`` flags a member that lives on a NETWORK mount (NFS/SMB/sshfs): it is a remote
    *view* of bytes physically stored on another host, not a separate reclaimable copy, so the UI
    highlights it as a cross-mount false positive and it does not count toward reclaimable space.
    """

    model_config = {"from_attributes": True}

    entry_id: int
    host_id: int
    volume_id: int
    path: str
    is_mount_alias: bool = False


class DuplicateGroupOut(BaseModel):
    """A confirmed duplicate group with its non-binding suggested keeper (read-only).

    ``reclaimable_bytes`` counts only **native** copies (``size * (native_copies - 1)``) — a
    network-mount member is a cross-mount alias and frees nothing, so it is excluded.
    ``suggested_keeper_*`` is the non-binding suggestion the UI shows with its reason (ADR-011).
    Report only — no selection or write is implied (security_constraints: report-only boundary).
    """

    model_config = {"from_attributes": True}

    id: int
    full_hash: str
    size: int
    member_count: int
    reclaimable_bytes: int
    suggested_keeper_entry_id: int | None
    suggested_keeper_reason: str | None


class DuplicateGroupDetailOut(DuplicateGroupOut):
    """A duplicate group plus its (scope-filtered) members for the detail view."""

    members: list[DuplicateMemberOut]


class DuplicatesSummaryOut(BaseModel):
    """Estate (or single-volume) dedup headline: how many groups and how much is reclaimable."""

    group_count: int
    total_reclaimable_bytes: int


class DuplicatesPage(BaseModel):
    """A keyset-paginated page of duplicate groups (mandatory at 50M rows; API §2)."""

    items: list[DuplicateGroupOut]
    next_cursor: str | None = None


class ProviderDuplicateMemberOut(BaseModel):
    """One member of a provider-hash duplicate group (read-only)."""

    entry_id: int
    host_id: int
    volume_id: int
    path: str


class ProviderDuplicateGroupOut(BaseModel):
    """A set of objects the *provider* reports as identical, by hash algorithm (ADR-028 phase 2).

    Distinct from :class:`DuplicateGroupOut` (content-verified BLAKE3): these come from a cloud
    provider's own hash (rclone ``lsjson --hash``) at zero egress, and are **report-only** — there
    is no suggested keeper and no remediation path (provider hashes never drive a delete).
    """

    algo: str
    provider_hash: str
    size: int
    member_count: int
    reclaimable_bytes: int
    members: list[ProviderDuplicateMemberOut]


class ProviderDuplicatesOut(BaseModel):
    """Provider-hash (cross-cloud) duplicate groups, capped at the requested limit.

    ``truncated`` is True when more groups exist than ``limit`` returned — the UI shows a "narrow
    the scope / raise the limit" hint rather than implying it listed everything.
    """

    items: list[ProviderDuplicateGroupOut]
    truncated: bool = False


# --- preview surface (preview-worker; ADR-014) -------------------------------------------


class PreviewArtifactOut(BaseModel):
    """One DERIVED preview artifact for the browser (ADR-014). Never raw bytes/SVG/HTML.

    ``data_b64`` is the base64 of the *derived* artifact (a re-encoded raster, an extracted text
    snippet, or a structured highlight) — already transformed by the sandbox. ``media_type`` is
    the artifact's safe type, not the source file's. The wire model carries no raw original bytes
    (security_constraints: preview is derived-only).
    """

    kind: str
    media_type: str
    data_b64: str
    meta: dict[str, str | int | bool]


class PreviewResultOut(BaseModel):
    """A rendered preview's derived artifacts + type badge + cache-hit metadata (read-only).

    ``type`` is the detected (magic-byte) type badge the UI shows; ``cache_hit`` distinguishes a
    cached artifact from a fresh render; ``sandbox_job_id`` correlates with the access audit row
    (file-mgmt §4.2). No raw bytes are present (ADR-014).
    """

    entry_id: int
    type: str
    cache_hit: bool
    sandbox_job_id: str
    artifacts: list[PreviewArtifactOut]


# --- scan creation surface (full-bit opt-in; fullbit-dedup endpoints) --------------------


class FullBitScanRequest(BaseModel):
    """An operator's request to create a full-bit scan with a persisted impact ack.

    Report-only: this records the operator's intent + acknowledgement (persisted on the snapshot
    for audit, ADD 02 non-impact contract). It performs no content read and triggers no write —
    the agent runs the gated full-bit pass on its own host (security_constraints).
    """

    volume_id: int = Field(ge=1)
    # The operator's acknowledgement that a full-bit scan is heavy and reads file contents; the
    # message must name the backing device class (e.g. "USB RAID5") per the non-impact contract.
    impact_ack: str = Field(min_length=1, max_length=1024)
    # Optional sub-tree scope within the volume; absent → the whole volume.
    scope_path: str | None = Field(default=None, max_length=4096)


class ScanCreatedOut(BaseModel):
    """Acknowledgement that a full-bit scan request was recorded (no write performed)."""

    snapshot_id: int
    volume_id: int
    mode: str


class SnapshotOut(BaseModel):
    """One immutable scan-run row for the Scans tab (GET /api/v1/scans).

    Read-only history of metadata/full-bit scan runs on a volume. ``warning_ack`` carries the
    operator's persisted impact acknowledgement for a full-bit run (ADD 02 non-impact contract).
    """

    id: int
    host_id: int
    volume_id: int
    mode: str
    started_at: datetime | None
    finished_at: datetime | None
    entry_count: int | None
    total_size_on_disk: int | None
    warning_ack: dict[str, object] | None


class HostOut(BaseModel):
    """One registered host + its agent liveness for the Agents/fleet tab (GET /api/v1/agents).

    ``volume_count`` is the number of catalogued volumes on the host; ``last_seen`` is the most
    recent mTLS contact (null until the agent first pushes). Read-only fleet topology (ADD 04).
    """

    id: int
    name: str
    os: str | None
    agent_version: str | None
    last_seen: datetime | None
    volume_count: int
    # Last scan-run outcome (observability) — null until the host reports a run. Lets the Agents
    # tab show whether the most recent scan actually succeeded, not just that the agent is alive.
    last_run_outcome: str | None = None  # ok | partial | failed
    last_run_finished_at: datetime | None = None
    last_run_entries_seen: int | None = None
    last_run_scopes_failed: int | None = None
    # ADR-033: the effective config the agent last reported (scan/fullbit scope, cross_mounts,
    # write_enabled, throttle) — null until a config-reporting agent runs; and the operator's
    # pending override (null = none). Shown in the Agents UI (#9); set via the override endpoint.
    reported_config: dict[str, object] | None = None
    desired_config: dict[str, object] | None = None


class AgentRunScopeFrame(BaseModel):
    """One scanned root's outcome within an agent run report (mirrors runner.ScopeOutcome)."""

    root: str = Field(min_length=1, max_length=4096)
    entries_seen: int = Field(ge=0)
    rows_changed: int = Field(ge=0)
    error: str | None = Field(default=None, max_length=1024)
    fullbit_hashed: int = Field(default=0, ge=0)
    fullbit_error: str | None = Field(default=None, max_length=1024)


class AgentRunReport(BaseModel):
    """End-of-run report an agent POSTs to ``/api/v1/agents/runs`` (mTLS-authenticated).

    The host is the verified cert fingerprint, never the body (AR-0012). The server re-derives the
    aggregate outcome (ok/partial/failed) and totals from ``scopes`` — it never trusts an
    agent-asserted aggregate — so a misreporting agent can only describe its own scopes, not forge
    a fleet-wide health verdict.
    """

    started_at: datetime
    finished_at: datetime
    pushed: int = Field(default=0, ge=0)
    finalized: int | None = Field(default=None, ge=0)
    agent_version: str | None = Field(default=None, max_length=64)
    scopes: list[AgentRunScopeFrame] = Field(default_factory=list, max_length=4096)
    # ADR-033: the EFFECTIVE config this run used (AgentConfig.reportable()). Stored on the host +
    # the run row for the Agents UI (#9). Optional — pre-ADR-033 agents omit it.
    reported_config: dict[str, object] | None = Field(default=None)


class AgentRunResult(BaseModel):
    """Acknowledgement of a recorded agent run (the server-derived outcome)."""

    run_id: int
    host_id: int
    outcome: str


class AgentConfigOverrideIn(BaseModel):
    """Operator-set per-host config override (ADR-033 #10) — ONLY the safe, overridable fields.

    ``extra="forbid"`` makes the API reject any non-overridable key (host_id, ingest_url, cert
    paths, secret refs, write_enabled), so the override boundary is enforced here AND re-enforced by
    the owning agent, which re-validates the full merged config against its own model and applies it
    fail-safe. ``throttle`` is opaque here (the agent re-validates it against its ThrottleProfile).
    """

    model_config = ConfigDict(extra="forbid")

    scan_scope: list[str] | None = Field(default=None, max_length=256)
    fullbit_scope: list[str] | None = Field(default=None, max_length=256)
    # ADR-034: absolute directory prefixes to prune from the walk (subtree excludes).
    exclude_scope: list[str] | None = Field(default=None, max_length=256)
    cross_mounts: bool | None = None
    throttle: dict[str, object] | None = None


class AuditRecordOut(BaseModel):
    """One hash-chained audit row for the Audit tab (GET /api/v1/audit).

    ``id`` is the append sequence; ``prev_hash``/``row_hash`` expose the tamper-evident chain so
    the UI can show (and a verifier can re-walk) the linkage (ADD 03 §8).
    """

    id: int
    ts: str
    actor: str
    action: str
    target: str
    result: str
    prev_hash: str | None
    row_hash: str


class AuditPage(BaseModel):
    """A keyset page of audit rows (newest first) plus the cursor for the next page.

    ``next_cursor`` is the ``id`` of the last row in this page (as a string), or null when the
    final page has been reached — passed back as ``?cursor=`` to fetch older rows.
    """

    items: list[AuditRecordOut]
    next_cursor: str | None


# --- content-aware Organize (ADR-021; read-only suggestion surface) ----------------------


class OrganizeSuggestRequest(BaseModel):
    """Ask for a proposed reorganisation of the files under one folder (read-only)."""

    volume_id: int = Field(ge=1)
    path: str = Field(min_length=1, max_length=4096)
    max_files: int = Field(default=60, ge=1, le=200)


class OrganizeItemOut(BaseModel):
    """One file's proposed disposition after server-side validation/clamping.

    ``status`` is ``move`` (relocate/rename to ``proposed_relpath``), ``keep`` (already placed
    well), or ``rejected`` (the model's target escaped the root, was a bad name, or collided —
    never moved). ``proposed_relpath`` is relative to the requested folder.
    """

    entry_id: int
    current_path: str
    current_name: str
    proposed_relpath: str
    proposed_name: str
    reason: str
    status: str


class OrganizeProposalOut(BaseModel):
    """A reviewable Organize suggestion for one folder (the model proposes; the server clamps)."""

    root: str
    volume_id: int
    model: str
    considered: int
    rejected: int
    items: list[OrganizeItemOut]


# --- Organize apply: build a reversible MOVE plan from an approved subset (ADR-023) -------


class OrganizeMoveIn(BaseModel):
    """One operator-approved relocation: a catalogue entry + its in-root target (re-clamped)."""

    entry_id: int = Field(ge=1)
    dest_rel: str = Field(min_length=1, max_length=4096)  # relative to the folder; server-clamped


class OrganizePlanRequest(BaseModel):
    """Build a reversible MOVE plan from a reviewed proposal's approved subset (ADR-023).

    The client sends only ``entry_id`` + the approved ``dest_rel`` per move; the server pulls the
    drift anchor (inode/size/hash) and source path from the catalogue and re-clamps every target to
    ``path`` (AR-0012 — the operator chose the destinations, the server owns the rest).
    """

    volume_id: int = Field(ge=1)
    path: str = Field(min_length=1, max_length=4096)  # the folder root the moves stay within
    moves: list[OrganizeMoveIn] = Field(min_length=1, max_length=200)
    idempotency_key: str | None = Field(default=None, max_length=128)


class OrganizePlanItemOut(BaseModel):
    entry_id: int
    path: str  # current absolute source path
    dest_rel: str  # destination relative to move_root


class OrganizePlanOut(BaseModel):
    """A built, persisted MOVE plan — feed ``plan_id`` to the remediation dry-run/execute spine."""

    plan_id: str
    move_root: str
    host_id: str
    blast_count: int
    reclaimable_bytes: int  # bytes relocated (reversible; not reclaimed) — sized for the UI
    status: str
    items: list[OrganizePlanItemOut]


class ServerConfigOut(BaseModel):
    """The non-secret server feature flags shown (read-only) on the Settings page.

    Curated by hand (never a blanket dump of Settings) so a secret can never leak: only feature
    toggles, the inference model/URL, and numeric limits are listed here.
    """

    organize_enabled: bool
    inference_provider: str
    inference_ollama_url: str
    organize_model: str
    inference_allow_egress: bool
    inference_timeout_seconds: float
    remediation_enabled: bool
    remediation_blast_cap: int
    preview_enabled: bool
    change_log_retention_days: int


class ReconcileRequest(BaseModel):
    """Compare a definitive ``(volume, path)`` against a comparison one (ADR-024; read-only)."""

    definitive_volume_id: int = Field(ge=1)
    definitive_path: str = Field(min_length=1, max_length=4096)
    comparison_volume_id: int = Field(ge=1)
    comparison_path: str = Field(min_length=1, max_length=4096)


class ReconcileItemOut(BaseModel):
    relpath: str
    classification: str  # identical|content_same_meta_diff|diverged|size_match_unhashed|missing_*
    definitive_size: int | None
    comparison_size: int | None
    definitive_hash: str | None
    comparison_hash: str | None


class ReconcileOut(BaseModel):
    """A read-only cross-host comparison: per-class counts + a bounded sample of flagged items."""

    definitive_volume_id: int
    definitive_root: str
    comparison_volume_id: int
    comparison_root: str
    counts: dict[str, int]
    considered: int
    items: list[ReconcileItemOut]
    truncated: bool


class OrganizeActivityOut(BaseModel):
    """Recent churn in a folder (ADR-021 Phase 3 watch trigger) — a hint to re-organise.

    Read-only summary off the incremental change feed (``change_log``): how many files were
    created/modified/deleted under ``path`` within the window. ``suggests_reorganise`` is True when
    new or changed files appeared — the UI surfaces it as a "re-organise?" nudge; nothing is ever
    auto-applied (a human still approves every plan).
    """

    volume_id: int
    path: str
    since_hours: int
    created: int
    modified: int
    deleted: int
    capped: bool  # True when the change count hit the scan limit (so counts are a lower bound)
    suggests_reorganise: bool
