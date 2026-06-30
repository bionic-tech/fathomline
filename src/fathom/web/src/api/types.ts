// Wire types mirroring the FastAPI response_models (src/fathom/api/schemas.py). In CI these
// are regenerated from /openapi.json via `npm run gen:api` (openapi-typescript) and this file
// re-exports the generated shapes so the rest of the app imports one stable surface; the
// hand-written shapes here are the compile-time contract until generation runs (API ADD §2).

export interface VolumeOut {
  id: number;
  host_id: number;
  mountpoint: string;
  fs_type: string;
  device: string;
  transport: string;
  raid_role: string | null;
  total: number;
  used: number;
  free: number;
  // Human label for a synthetic-mountpoint (remote/cloud) volume (ADR-029); the UI shows this in
  // preference to the synthetic mountpoint. Navigation/drill paths still use `mountpoint`.
  display_name?: string | null;
}

/** The label to SHOW for a volume (pretty remote name when present); not for path navigation. */
export function volumeLabel(v: { mountpoint: string; display_name?: string | null }): string {
  return v.display_name ?? v.mountpoint;
}

export interface TreeChildOut {
  entry_id: number;
  path: string;
  name: string;
  is_dir: boolean;
  is_symlink: boolean;
  size_logical: number;
  size_on_disk: number;
  subtree_size_logical: number;
  subtree_size_on_disk: number;
  file_count: number;
  mtime: number;
  uid: number;
  gid: number;
  inode: number;
  flags: Record<string, boolean>;
  content_hash: string | null;
}

// --- sandboxed preview (GET /api/v1/preview/{entry_id}, ADR-014) ------------------------

export interface PreviewArtifactOut {
  kind: "thumbnail" | "page_raster" | "text_snippet" | "code_render";
  media_type: string;
  data_b64: string;
  meta: Record<string, string | number | boolean>;
}

export interface PreviewResultOut {
  entry_id: number;
  type: string;
  cache_hit: boolean;
  sandbox_job_id: string;
  artifacts: PreviewArtifactOut[];
}

// --- estate search (GET /api/v1/search) -------------------------------------------------

export interface SearchResultOut {
  path: string;
  name: string;
  is_dir: boolean;
  size_logical: number;
  size_on_disk: number;
  host_id: number;
  volume_id: number;
}

// --- content-aware Organize (ADR-021; read-only suggestion) -----------------------------

export interface OrganizeItemOut {
  entry_id: number;
  current_path: string;
  current_name: string;
  proposed_relpath: string;
  proposed_name: string;
  reason: string;
  status: string; // "move" | "keep" | "rejected"
}

export interface OrganizeProposalOut {
  root: string;
  volume_id: number;
  model: string;
  considered: number;
  rejected: number;
  items: OrganizeItemOut[];
}

// --- Organize apply: build a reversible MOVE plan from an approved subset (ADR-023) -------

export interface OrganizeMoveIn {
  entry_id: number;
  dest_rel: string; // relative to the folder; server re-clamps to the root
}

export interface OrganizePlanRequest {
  volume_id: number;
  path: string;
  moves: OrganizeMoveIn[];
  idempotency_key?: string | null;
}

export interface OrganizePlanItemOut {
  entry_id: number;
  path: string;
  dest_rel: string;
}

export interface OrganizePlanOut {
  plan_id: string;
  move_root: string;
  host_id: string;
  blast_count: number;
  reclaimable_bytes: number;
  status: string;
  items: OrganizePlanItemOut[];
}

// --- server config (read-only feature flags shown on the Settings page) -------------------

export interface ServerConfigOut {
  organize_enabled: boolean;
  inference_provider: string;
  inference_model: string;
  inference_ollama_url: string;
  organize_model: string | null;
  inference_allow_egress: boolean;
  inference_timeout_seconds: number;
  remediation_enabled: boolean;
  remediation_blast_cap: number;
  preview_enabled: boolean;
  change_log_retention_days: number;
  concierge_enabled: boolean;
  concierge_model: string | null;
  concierge_embeddings_enabled: boolean;
  scan_coordinator_enabled: boolean;
  notifications_enabled: boolean;
  onboarding_completed: boolean;
}

// --- Notification Center (ADR-031) + outbound channels (ADR-039) ---------------------------

export interface NotificationOut {
  id: number;
  category: string; // recommendation | problem | activity | security
  severity: string; // info | warning | critical
  title: string;
  body: string;
  source: string;
  host_id?: number | null;
  volume_id?: number | null;
  created_at: string;
  read: boolean;
}

export interface NotificationListOut {
  items: NotificationOut[];
  unread_count: number;
}

export interface UnreadCountOut {
  unread_count: number;
}

export interface NotifyChannelResult {
  channel: string;
  ok: boolean;
  detail: string;
}

export interface NotifyTestResult {
  results: NotifyChannelResult[];
}

// --- Suitability / onboarding (ADR-037) ---------------------------------------------------

export interface HostFactsOut {
  cpu_cores?: number | null;
  cpu_model?: string | null;
  ram_bytes?: number | null;
  gpu_name?: string | null;
  gpu_vram_bytes?: number | null;
  arch?: string | null;
}

export type SuitabilityRating = "green" | "amber" | "red";

export interface OptionAssessmentOut {
  key: string;
  label: string;
  rating: SuitabilityRating;
  reason: string;
}

export interface HostSuitabilityOut {
  host_id: number;
  name: string;
  facts_known: boolean;
  facts?: HostFactsOut | null;
  options: OptionAssessmentOut[];
  recommendation: string;
  recommended_chat_provider: string;
  recommended_chat_model: string | null;
  recommended_embedder: string;
  recommended_embedding_dim: number | null;
}

export interface SuitabilityListOut {
  hosts: HostSuitabilityOut[];
  egress_allowed: boolean;
}

// AI concierge (ADR-035): a natural-language question over the catalogue + its grounded answer.
export interface ConciergeTurn {
  role: "user" | "assistant";
  content: string;
}

export interface ConciergeAskRequest {
  question: string;
  volume_id?: number | null;
  host_id?: number | null;
  /** The page/view the user asked from — a soft context hint (ADR-035). */
  page?: string | null;
  /** Recent conversation turns (client-held memory) so follow-ups resolve. */
  history?: ConciergeTurn[];
}

export interface ConciergeCitationOut {
  label: string;
  path?: string | null;
  entry_id?: number | null;
  host_id?: number | null;
  volume_id?: number | null;
}

export interface ConciergeActionOut {
  label: string;
  route: string;
  volume_id?: number | null;
}

export interface ConciergeAnswerOut {
  answer: string;
  tool: string;
  considered: number;
  citations: ConciergeCitationOut[];
  actions?: ConciergeActionOut[];
}

// --- cross-host reconciliation (ADR-024; read-only divergence detection) ------------------

export interface ReconcileRequest {
  definitive_volume_id: number;
  definitive_path: string;
  comparison_volume_id: number;
  comparison_path: string;
}

export interface ReconcileItemOut {
  relpath: string;
  classification: string;
  definitive_size: number | null;
  comparison_size: number | null;
  definitive_hash: string | null;
  comparison_hash: string | null;
}

export interface ReconcileOut {
  definitive_volume_id: number;
  definitive_root: string;
  comparison_volume_id: number;
  comparison_root: string;
  counts: Record<string, number>;
  considered: number;
  items: ReconcileItemOut[];
  truncated: boolean;
}

export interface OrganizeActivityOut {
  volume_id: number;
  path: string;
  since_hours: number;
  created: number;
  modified: number;
  deleted: number;
  capped: boolean;
  suggests_reorganise: boolean;
}

// --- churn feed (incremental change_log; GET /api/v1/changes) ----------------------------

export interface ChangeOut {
  path: string;
  change_type: string; // create | modify | delete (backend incremental.CHANGE_TYPES)
  size_delta: number; // signed: negative on shrink/removal
  ts: string;
}

export interface TreemapNodeOut {
  path: string;
  name: string;
  is_dir: boolean;
  subtree_size_logical: number;
  subtree_size_on_disk: number;
  file_count: number;
}

export interface TopNItemOut {
  path: string;
  name: string;
  is_dir: boolean;
  size_logical: number;
  size_on_disk: number;
  file_count: number;
}

export interface GrowthPointOut {
  ts: string;
  total_size_logical: number;
  total_size_on_disk: number;
  file_count: number;
}

export interface GrowthSeriesOut {
  volume_id: number;
  path: string;
  points: GrowthPointOut[];
}

export interface Grant {
  role: string;
  scope_kind: "global" | "host" | "volume";
  host_id: number | null;
  volume_id: number | null;
}

export interface MeResponse {
  subject: string;
  source: string;
  display_name: string | null;
  groups: string[];
  grants: Grant[];
  mfa_fresh: boolean;
  mfa_enrolled?: boolean; // a confirmed TOTP enrollment exists
}

export interface EnrollResponse {
  provisioning_uri: string; // otpauth:// URI (carries the TOTP secret)
}

export type SizeBasis = "on_disk" | "logical";
export type TopNKind = "dir" | "file" | "any";

// --- duplicates surface (fullbit-dedup; src/fathom/api/routers/duplicates.py) -----------

export interface DuplicateMemberOut {
  entry_id: number;
  host_id: number;
  volume_id: number;
  path: string;
  // True when this copy lives on a network mount (NFS/SMB/sshfs): a remote view of bytes stored on
  // another host, not a reclaimable copy. The UI flags it as a cross-mount false positive.
  is_mount_alias: boolean;
}

export interface DuplicateGroupOut {
  id: number;
  full_hash: string;
  size: number;
  member_count: number;
  reclaimable_bytes: number;
  suggested_keeper_entry_id: number | null;
  suggested_keeper_reason: string | null;
}

export interface DuplicateGroupDetailOut extends DuplicateGroupOut {
  members: DuplicateMemberOut[];
}

export interface DuplicatesSummaryOut {
  group_count: number;
  total_reclaimable_bytes: number;
}

export interface DuplicatesPage {
  items: DuplicateGroupOut[];
  next_cursor: string | null;
}

// Provider-hash (cross-cloud) duplicates — ADR-028 phase 2: the cloud provider's own hash, zero
// egress, report-only (no keeper, no remediation). Distinct from the BLAKE3 DupGroup above.
export interface ProviderDuplicateMemberOut {
  entry_id: number;
  host_id: number;
  volume_id: number;
  path: string;
}

export interface ProviderDuplicateGroupOut {
  algo: string;
  provider_hash: string;
  size: number;
  member_count: number;
  reclaimable_bytes: number;
  members: ProviderDuplicateMemberOut[];
}

export interface ProviderDuplicatesOut {
  items: ProviderDuplicateGroupOut[];
  truncated: boolean;
}

// --- remediation write surface (ADR-011; gated: BUILD/EXECUTE/QUARANTINE + step-up MFA) --

export type PlanAction = "quarantine" | "hard_delete" | "hardlink" | "move";

export interface BuildPlanRequest {
  group_id: number;
  keep_entry_id: number;
  action?: PlanAction;
  idempotency_key?: string | null;
}

export interface PlanItemOut {
  entry_id: number;
  path: string;
  action: string;
}

export interface PlanOut {
  plan_id: string;
  keeper_path: string;
  host_id: string;
  blast_count: number;
  reclaimable_bytes: number;
  status: string;
  items: PlanItemOut[];
}

export interface DriftItemOut {
  entry_id: string;
  reason: string;
}

export interface DryRunOut {
  plan_id: string;
  ok: boolean;
  drifted: DriftItemOut[];
}

export interface ExecResultOut {
  entry_id: string;
  action: string;
  status: string;
}

export interface ExecuteOut {
  plan_id: string;
  results: ExecResultOut[];
}

// --- scans / snapshot history (snapshot rows; ADD 02/ADD 09 §4) -------------------------
// The snapshot history read surface (GET /api/v1/scans) lists immutable scan runs per volume.
// Creation is POST /api/v1/scans/fullbit (src/fathom/api/routers/scans.py).

export interface SnapshotOut {
  id: number;
  host_id: number;
  volume_id: number;
  mode: string;
  started_at: string | null;
  finished_at: string | null;
  entry_count: number | null;
  total_size_on_disk: number | null;
  warning_ack: Record<string, unknown> | null;
}

export interface ScanCreatedOut {
  snapshot_id: number;
  volume_id: number;
  mode: string;
}

// --- agents / fleet (host rows + agent last_seen; ADD 04 topology, frontend ADD §4) -----

export interface HostOut {
  id: number;
  name: string;
  os: string | null;
  agent_version: string | null;
  last_seen: string | null;
  volume_count: number | null;
  // Last scan-run outcome (observability) — null until the host reports a run.
  last_run_outcome: "ok" | "partial" | "failed" | null;
  last_run_finished_at: string | null;
  last_run_entries_seen: number | null;
  last_run_scopes_failed: number | null;
  // ADR-033: the effective config the agent last reported (#9), and the operator's pending override
  // (#10). Opaque dicts (scan_scope, fullbit_scope, cross_mounts, write_enabled, throttle); null
  // until reported / when no override.
  reported_config: Record<string, unknown> | null;
  desired_config: Record<string, unknown> | null;
}

// ADR-033 #10: the per-host override an operator PUTs — only the safe overridable fields (the API
// rejects anything else; write_enabled is intentionally not overridable).
export interface AgentConfigOverride {
  scan_scope?: string[];
  fullbit_scope?: string[];
  exclude_scope?: string[];
  cross_mounts?: boolean;
  throttle?: Record<string, unknown>;
}

// --- on-demand scan dispatch (POST /api/v1/agents/{host_id}/scan; signed-job channel) ----------
// The two scan depths: a fast metadata pass, or a heavy full-bit (content-fingerprint) pass.
export type ScanMode = "metadata" | "fullbit";

// 202 response when the dispatch channel is armed; the endpoint 503s until it's enabled on the core.
export interface ScanDispatchOut {
  job_id: string;
}

// --- live directory browse (ADR-034 Phase 2): pick scan roots/excludes by listing real dirs ----

export interface BrowseEntry {
  name: string;
  path: string;
  is_dir: boolean;
  is_symlink: boolean;
  size: number;
  mtime: number;
  subtree_size: number | null;
  subtree_file_count: number | null;
  subtree_truncated: boolean;
}

export interface BrowseResult {
  request_id: string;
  path: string;
  entries: BrowseEntry[];
  truncated: boolean;
  error: string | null;
}

export interface BrowseVolume {
  mountpoint: string;
  fs_type: string;
  total: number;
  used: number;
  free: number;
}

// --- audit log (hash-chained, append-only; READ_AUDIT-gated; ADD 03 §8, 09-data §54) ----

export interface AuditRecordOut {
  id: number;
  ts: string;
  actor: string;
  action: string;
  target: string;
  result: string;
  prev_hash: string | null;
  row_hash: string;
}

export interface AuditPage {
  items: AuditRecordOut[];
  next_cursor: string | null;
}

// --- admin users / role assignments (src/fathom/api/routers/admin_users.py) -------------

export interface AdminUserOut {
  id: number;
  subject: string;
  source: string;
  display_name: string | null;
  is_active: boolean;
}

export interface AssignmentOut {
  id: number;
  user_id: number;
  role: string;
  scope_kind: "global" | "host" | "volume";
  host_id: number | null;
  volume_id: number | null;
}

export interface CreateAssignmentRequest {
  role: string;
  scope_kind: "global" | "host" | "volume";
  host_id?: number | null;
  volume_id?: number | null;
}

export interface CreateUserRequest {
  username: string;
  display_name?: string | null;
  password: string;
}

// --- agent deployment (ADR-026): push SSH-deploy + pull enrollment -----------------------

export interface SshCredentialIn {
  username: string;
  private_key?: string | null;
  passphrase?: string | null;
  certificate?: string | null;
  password?: string | null;
  sudo_password?: string | null;
}

export interface ScopeMountIn {
  container_path: string;
  host_path: string;
  fullbit: boolean;
}

// A remote scan target generated into the agent bundle (ADR-029). Credentials are SECRET
// REFERENCES (names the agent resolves at runtime), never inline; rclone takes none (rclone.conf).
export interface RemoteTargetIn {
  protocol: "rclone" | "smb" | "sftp";
  host: string;
  remote_path?: string;
  share?: string | null;
  port?: number | null;
  username?: string | null;
  password_ref?: string | null;
  private_key_ref?: string | null;
  verify?: boolean;
  lab_insecure?: boolean;
}

export interface PreflightRequest {
  target: string;
  port?: number;
  credential: SshCredentialIn;
  proxy_host_ip?: string;
  expected_host_key?: string | null;
}

export interface PreflightOut {
  target: string;
  ok: boolean;
  reachable: boolean;
  docker_present: boolean;
  proxy_reachable: boolean;
  host_key_fingerprint: string;
  notes: string[];
}

export interface DeployHostIn {
  target: string;
  port?: number;
  host_id: string;
  credential: SshCredentialIn;
  mounts?: ScopeMountIn[];
  remote_targets?: RemoteTargetIn[];
  proxy_host_ip?: string;
  expected_host_key?: string | null;
  remote_dir?: string;
}

export interface DeployRequest {
  hosts: DeployHostIn[];
}

export interface HostStatusOut {
  host_id: string;
  target: string;
  phase: string;
  detail: string;
  fingerprint: string | null;
  host_key: string | null;
}

export interface DeployRunOut {
  run_id: string;
  created_by: string;
  complete: boolean;
  hosts: HostStatusOut[];
}

export interface EnrollRequest {
  host_id: string;
  platform?: "linux" | "windows";
  mounts?: ScopeMountIn[];
  remote_targets?: RemoteTargetIn[];
  // Native Windows agent (ADR-027): real Windows paths to scan, and the subset to content-hash
  // (full-bit W2 — local-only, never hydrates cloud placeholders). Metadata-only when omitted.
  windows_scan_paths?: string[];
  windows_fullbit_paths?: string[];
  proxy_host_ip?: string;
  core_base_url?: string;
}

export interface EnrollOut {
  host_id: string;
  token: string;
  command: string;
  expires_at: string;
}

// --- runtime settings store (ADR-038) ----------------------------------------------------

export interface SettingOut {
  key: string;
  category: string;
  type: string; // bool | int | float | str | list
  editable: boolean;
  is_secret: boolean;
  restart_required: boolean;
  help: string;
  overridden: boolean;
  is_set: boolean;
  value: unknown; // null for a secret; the effective value otherwise
  label: string; // human label; the key is shown secondary
  options: string[] | null; // closed value set → strict dropdown
  suggestions?: string[] | null; // open value set → free-text combobox (datalist hints)
  relevant: boolean; // currently applies given other settings' values
  relevant_hint: string | null; // why it's inapplicable (shown when relevant is false)
  advanced?: boolean; // tuck behind an "Advanced" disclosure in the UI
}

export interface SettingsListOut {
  settings: SettingOut[];
  named_secrets: string[];
  version: number;
}

export interface SetSecretRequest {
  ref: string;
  value: string;
}

export interface RevealSecretOut {
  key: string;
  value: string;
}

export interface SettingMutationResult {
  key: string;
  overridden: boolean;
  restart_required: boolean;
  version: number;
}
