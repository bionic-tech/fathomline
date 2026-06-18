// TanStack Query hooks over the typed client (frontend ADD §5/§7). Each hook owns one keyed,
// background-refetched server cache. Charts are fed from these — the same data also drives the
// data-table alternatives so the numbers are reachable without the chart (frontend ADD §9).

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { apiDelete, apiGet, apiPost, apiPut, toQuery } from "./client";
import type {
  AdminUserOut,
  AssignmentOut,
  AuditPage,
  CreateAssignmentRequest,
  BuildPlanRequest,
  ChangeOut,
  DeployRequest,
  DeployRunOut,
  DryRunOut,
  EnrollRequest,
  EnrollOut,
  PreflightRequest,
  PreflightOut,
  DuplicateGroupDetailOut,
  DuplicatesPage,
  DuplicatesSummaryOut,
  ProviderDuplicatesOut,
  ExecuteOut,
  AgentConfigOverride,
  BrowseResult,
  BrowseVolume,
  GrowthSeriesOut,
  PlanOut,
  HostOut,
  MeResponse,
  OrganizeActivityOut,
  ReconcileOut,
  ReconcileRequest,
  OrganizePlanOut,
  OrganizePlanRequest,
  OrganizeProposalOut,
  ScanCreatedOut,
  SearchResultOut,
  SizeBasis,
  SnapshotOut,
  TopNItemOut,
  TopNKind,
  ServerConfigOut,
  TreemapNodeOut,
  TreeChildOut,
  VolumeOut,
} from "./types";

/** The non-secret server feature flags (read-only) for the Settings page. */
export function useServerConfig(): UseQueryResult<ServerConfigOut> {
  return useQuery({
    queryKey: ["server-config"],
    queryFn: () => apiGet<ServerConfigOut>("/config"),
    staleTime: 5 * 60 * 1000,
  });
}

export function useWhoAmI(): UseQueryResult<MeResponse> {
  return useQuery({
    queryKey: ["whoami"],
    queryFn: () => apiGet<MeResponse>("/auth/me"),
    retry: false,
    staleTime: 60_000,
  });
}

export function useVolumes(): UseQueryResult<VolumeOut[]> {
  return useQuery({
    queryKey: ["volumes"],
    queryFn: () => apiGet<VolumeOut[]>("/volumes"),
  });
}

export function useTree(volumeId: number | null, path: string | null): UseQueryResult<TreeChildOut[]> {
  return useQuery({
    queryKey: ["tree", volumeId, path],
    queryFn: () => apiGet<TreeChildOut[]>(`/tree${toQuery({ volume_id: volumeId, path })}`),
    enabled: volumeId !== null && path !== null,
  });
}

export function useTreemap(
  volumeId: number | null,
  path: string | null,
  limit = 100,
): UseQueryResult<TreemapNodeOut[]> {
  return useQuery({
    queryKey: ["treemap", volumeId, path, limit],
    queryFn: () =>
      apiGet<TreemapNodeOut[]>(`/treemap${toQuery({ volume_id: volumeId, path, limit })}`),
    enabled: volumeId !== null && path !== null,
  });
}

export function useTopN(
  volumeId: number | null,
  path: string | null,
  n = 20,
  by: SizeBasis = "on_disk",
  kind: TopNKind = "any",
): UseQueryResult<TopNItemOut[]> {
  return useQuery({
    queryKey: ["top-n", volumeId, path, n, by, kind],
    queryFn: () =>
      apiGet<TopNItemOut[]>(`/top-n${toQuery({ volume_id: volumeId, path, n, by, kind })}`),
    enabled: volumeId !== null && path !== null,
  });
}

export function useHistorySeries(
  volumeId: number | null,
  path: string | null,
  buckets = 200,
): UseQueryResult<GrowthSeriesOut> {
  return useQuery({
    queryKey: ["history-series", volumeId, path, buckets],
    queryFn: () =>
      apiGet<GrowthSeriesOut>(`/history/series${toQuery({ volume_id: volumeId, path, buckets })}`),
    enabled: volumeId !== null && path !== null,
  });
}

/** Estate search: live entries whose name contains `q`, biggest first (optional single volume). */
export function useSearch(
  q: string,
  volumeId: number | null,
  enabled = true,
): UseQueryResult<SearchResultOut[]> {
  return useQuery({
    queryKey: ["search", q, volumeId],
    queryFn: () => apiGet<SearchResultOut[]>(`/search${toQuery({ q, volume_id: volumeId })}`),
    enabled: enabled && q.trim().length >= 2,
  });
}

/** The 'what changed' churn feed (created/modified/removed) for a volume + optional subtree/window. */
export function useChanges(
  volumeId: number | null,
  path: string | null,
  since: string | null,
  limit = 200,
): UseQueryResult<ChangeOut[]> {
  return useQuery({
    queryKey: ["changes", volumeId, path, since, limit],
    queryFn: () =>
      apiGet<ChangeOut[]>(`/changes${toQuery({ volume_id: volumeId, path, since, limit })}`),
    enabled: volumeId !== null,
  });
}

// --- duplicates (VIEW_DEDUP; src/fathom/api/routers/duplicates.py) -----------------------

/** A keyset-paginated page of duplicate groups. `enabled` lets the page gate on capability. */
export function useDuplicates(
  volumeId: number | null,
  cursor: string | null,
  enabled = true,
): UseQueryResult<DuplicatesPage> {
  return useQuery({
    queryKey: ["duplicates", volumeId, cursor],
    queryFn: () =>
      apiGet<DuplicatesPage>(`/duplicates${toQuery({ volume_id: volumeId, cursor })}`),
    enabled,
  });
}

/** Cross-cloud provider-hash duplicate groups (zero-egress, report-only; ADR-028 phase 2). */
export function useProviderDuplicates(
  volumeId: number | null,
  enabled = true,
): UseQueryResult<ProviderDuplicatesOut> {
  return useQuery({
    queryKey: ["provider-duplicates", volumeId],
    queryFn: () =>
      apiGet<ProviderDuplicatesOut>(`/duplicates/provider${toQuery({ volume_id: volumeId })}`),
    enabled,
  });
}

/** The dedup headline (group count + total reclaimable) for the dashboard KPI. */
export function useDuplicatesSummary(
  volumeId: number | null,
  enabled = true,
): UseQueryResult<DuplicatesSummaryOut> {
  return useQuery({
    queryKey: ["duplicates-summary", volumeId],
    queryFn: () =>
      apiGet<DuplicatesSummaryOut>(`/duplicates/summary${toQuery({ volume_id: volumeId })}`),
    enabled,
  });
}

/** One duplicate group with its in-scope members (loaded when a group is expanded). */
export function useDuplicateGroup(groupId: number | null): UseQueryResult<DuplicateGroupDetailOut> {
  return useQuery({
    queryKey: ["duplicate-group", groupId],
    queryFn: () => apiGet<DuplicateGroupDetailOut>(`/duplicates/${groupId}`),
    enabled: groupId !== null,
  });
}

// --- remediation write surface (ADR-011; gated mutations + step-up MFA) ------------------

/** Build a quarantine/delete plan from a confirmed dup group + the chosen keeper (BUILD_REMEDIATION). */
export function useBuildPlan(): UseMutationResult<PlanOut, Error, BuildPlanRequest> {
  return useMutation({
    mutationFn: async (body: BuildPlanRequest) =>
      (await apiPost<PlanOut>("/remediation/plans", body)) as PlanOut,
  });
}

/** Dry-run a built plan: re-verify every item, returning the drift report (no mutation). */
export function useDryRunPlan(): UseMutationResult<DryRunOut, Error, string> {
  return useMutation({
    mutationFn: async (planId: string) =>
      (await apiPost<DryRunOut>(`/remediation/plans/${planId}/dry-run`)) as DryRunOut,
  });
}

/** Execute the non-drifted subset (EXECUTE_REMEDIATION + FRESH step-up MFA; default-OFF gate). */
export function useExecutePlan(): UseMutationResult<
  ExecuteOut,
  Error,
  { planId: string; confirmBlast: boolean; confirmHost: string }
> {
  return useMutation({
    mutationFn: async (vars: { planId: string; confirmBlast: boolean; confirmHost: string }) =>
      (await apiPost<ExecuteOut>(`/remediation/plans/${vars.planId}/execute`, {
        confirm_blast: vars.confirmBlast,
        confirm_host: vars.confirmHost,
      })) as ExecuteOut,
  });
}

/**
 * Recent churn in the selected folder (ADR-021 Phase 3 watch trigger) — a read-only "re-organise?"
 * nudge off the change feed. Nothing is auto-applied; the operator still drives suggest→apply.
 */
export function useOrganizeActivity(
  volumeId: number | null,
  path: string | null,
): UseQueryResult<OrganizeActivityOut> {
  return useQuery({
    queryKey: ["organize-activity", volumeId, path],
    queryFn: () =>
      apiGet<OrganizeActivityOut>(`/organize/activity${toQuery({ volume_id: volumeId, path })}`),
    enabled: volumeId !== null && path !== null,
    // A stale-OK hint, not live data — don't hammer the feed on every focus.
    staleTime: 60_000,
  });
}

/** Ask for a content-aware reorganisation of a folder (read-only suggestion; ADR-021). */
export function useOrganizeSuggest(): UseMutationResult<
  OrganizeProposalOut,
  Error,
  { volumeId: number; path: string; maxFiles?: number }
> {
  return useMutation({
    mutationFn: async (vars: { volumeId: number; path: string; maxFiles?: number }) =>
      (await apiPost<OrganizeProposalOut>("/organize/suggest", {
        volume_id: vars.volumeId,
        path: vars.path,
        // Default kept modest so a small local model responds promptly; the server caps at 200.
        max_files: vars.maxFiles ?? 20,
      })) as OrganizeProposalOut,
  });
}

/**
 * Build a reversible MOVE plan from an approved subset of a proposal (ADR-023; BUILD_REMEDIATION,
 * default-OFF behind organize+remediation). The returned plan_id then drives the SAME remediation
 * dry-run/execute hooks above — apply reuses the gated spine, no second destructive surface.
 */
export function useOrganizePlan(): UseMutationResult<OrganizePlanOut, Error, OrganizePlanRequest> {
  return useMutation({
    mutationFn: async (body: OrganizePlanRequest) =>
      (await apiPost<OrganizePlanOut>("/organize/plan", body)) as OrganizePlanOut,
  });
}

/** Cross-host reconciliation (ADR-024): classify a comparison tree against a definitive one. */
export function useReconcile(): UseMutationResult<ReconcileOut, Error, ReconcileRequest> {
  return useMutation({
    mutationFn: async (body: ReconcileRequest) =>
      (await apiPost<ReconcileOut>("/reconcile", body)) as ReconcileOut,
  });
}

/** Verify a TOTP code to stamp step-up MFA freshness on the session (unlocks execute). */
export function useMfaVerify(): UseMutationResult<void, Error, string> {
  return useMutation({
    mutationFn: async (code: string) => {
      await apiPost<void>("/auth/mfa/verify", { code });
    },
  });
}

// --- scans / snapshot history (VIEW_METADATA to read; TRIGGER_FULLBIT_SCAN to create) ----

/** Snapshot/scan history for a volume (immutable scan runs; ADD 02). */
export function useScans(volumeId: number | null, enabled = true): UseQueryResult<SnapshotOut[]> {
  return useQuery({
    queryKey: ["scans", volumeId],
    queryFn: () => apiGet<SnapshotOut[]>(`/scans${toQuery({ volume_id: volumeId })}`),
    enabled,
  });
}

export interface FullBitScanVars {
  volume_id: number;
  impact_ack: string;
  scope_path?: string | null;
}

/** Request a full-bit scan (records an impact ack on a snapshot; report-only, no write). */
export function useCreateFullBitScan(): UseMutationResult<
  ScanCreatedOut | void,
  unknown,
  FullBitScanVars
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: FullBitScanVars) => apiPost<ScanCreatedOut>("/scans/fullbit", vars),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: ["scans", vars.volume_id] });
    },
  });
}

// --- agents / fleet (MANAGE_AGENTS to manage; read for fleet health) ---------------------

/** Hosts/agents in the fleet with last-seen heartbeat (ADD 04 topology). */
export function useAgents(enabled = true): UseQueryResult<HostOut[]> {
  return useQuery({
    queryKey: ["agents"],
    queryFn: () => apiGet<HostOut[]>("/agents"),
    enabled,
  });
}

/** Set (or clear, with {}) a host's agent config override (ADR-033 #10; MANAGE_AGENTS). The agent
 * applies it on its next run, fail-safe. Invalidates the agents list so the new override shows. */
export function useSetAgentConfig(): UseMutationResult<
  void,
  unknown,
  { hostId: number; override: AgentConfigOverride }
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ hostId, override }) =>
      apiPut<void>(`/agents/${hostId}/config`, override) as Promise<void>,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["agents"] });
    },
  });
}

// --- audit (READ_AUDIT; hash-chained append-only log) ------------------------------------

/** A page of the hash-chained audit log (auditor/admin only). */
export function useAudit(cursor: string | null, enabled = true): UseQueryResult<AuditPage> {
  return useQuery({
    queryKey: ["audit", cursor],
    queryFn: () => apiGet<AuditPage>(`/audit${toQuery({ cursor })}`),
    enabled,
  });
}

// --- admin users / role assignments (MANAGE_USERS; admin_users.py) -----------------------

export function useAdminUsers(enabled = true): UseQueryResult<AdminUserOut[]> {
  return useQuery({
    queryKey: ["admin-users"],
    queryFn: () => apiGet<AdminUserOut[]>("/users"),
    enabled,
  });
}

export function useUserAssignments(
  userId: number | null,
  enabled = true,
): UseQueryResult<AssignmentOut[]> {
  return useQuery({
    queryKey: ["user-assignments", userId],
    queryFn: () => apiGet<AssignmentOut[]>(`/users/${userId}/assignments`),
    enabled: enabled && userId !== null,
  });
}

export interface CreateAssignmentVars {
  userId: number;
  body: CreateAssignmentRequest;
}

/** Grant a (role, scope) assignment to a user (admin; audited server-side). */
export function useCreateAssignment(): UseMutationResult<
  AssignmentOut | void,
  unknown,
  CreateAssignmentVars
> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, body }: CreateAssignmentVars) =>
      apiPost<AssignmentOut>(`/users/${userId}/assignments`, body),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: ["user-assignments", vars.userId] });
    },
  });
}

export interface DeleteAssignmentVars {
  userId: number;
  assignmentId: number;
}

/** Revoke a (role, scope) assignment from a user (admin; audited server-side). */
export function useDeleteAssignment(): UseMutationResult<void, unknown, DeleteAssignmentVars> {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, assignmentId }: DeleteAssignmentVars) =>
      apiDelete(`/users/${userId}/assignments/${assignmentId}`),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: ["user-assignments", vars.userId] });
    },
  });
}

// --- agent deployment (ADR-026): DEPLOY_AGENT + step-up MFA; default-OFF (503 until armed) ----

/** Preflight one target over SSH (reachable? docker? proxy?) — no change made (DEPLOY_AGENT). */
export function usePreflight(): UseMutationResult<PreflightOut, Error, PreflightRequest> {
  return useMutation({
    mutationFn: async (body: PreflightRequest) =>
      (await apiPost<PreflightOut>("/deployment/preflight", body)) as PreflightOut,
  });
}

/** Start a batch push-deploy (DEPLOY_AGENT + FRESH step-up MFA); returns the run to poll. */
export function useDeployAgents(): UseMutationResult<DeployRunOut, Error, DeployRequest> {
  return useMutation({
    mutationFn: async (body: DeployRequest) =>
      (await apiPost<DeployRunOut>("/deployment/deploy", body)) as DeployRunOut,
  });
}

/** Poll a deploy run's per-host status until it completes. */
export function useDeployRun(runId: string | null): UseQueryResult<DeployRunOut> {
  return useQuery({
    queryKey: ["deploy-run", runId],
    queryFn: () => apiGet<DeployRunOut>(`/deployment/runs/${runId}`),
    enabled: runId !== null,
    // Refetch while the run is in flight; stop once every host is terminal OR the poll errors
    // (e.g. a 404 if the run was evicted) so the UI never loops forever (round 1, P3).
    refetchInterval: (query) =>
      query.state.data?.complete || query.state.status === "error" ? false : 1500,
  });
}

/** Issue a one-time pull-enrollment token + bootstrap command (DEPLOY_AGENT + FRESH step-up MFA). */
export function useEnrollToken(): UseMutationResult<EnrollOut, Error, EnrollRequest> {
  return useMutation({
    mutationFn: async (body: EnrollRequest) =>
      (await apiPost<EnrollOut>("/deployment/enroll", body)) as EnrollOut,
  });
}

// --- live directory browse (ADR-034 Phase 2): MANAGE_AGENTS/DEPLOY_AGENT + per-request step-up ---

/** List one directory on an ENROLLED host live (MANAGE_AGENTS + FRESH step-up MFA; 503 if off). */
export function useBrowseHost(): UseMutationResult<
  BrowseResult,
  Error,
  { hostId: number; path: string; withSizes?: boolean }
> {
  return useMutation({
    mutationFn: async ({ hostId, path }) =>
      (await apiPost<BrowseResult>(`/agents/${hostId}/browse`, { path })) as BrowseResult,
  });
}

/** List one directory on a NOT-yet-enrolled target over SSH (DEPLOY_AGENT + FRESH step-up MFA). */
export function useDeployBrowse(): UseMutationResult<
  BrowseResult,
  Error,
  PreflightRequest & { path: string; with_sizes?: boolean }
> {
  return useMutation({
    mutationFn: async (body) =>
      (await apiPost<BrowseResult>("/deployment/browse", body)) as BrowseResult,
  });
}

/** Probe a not-yet-enrolled target's mounted volumes via df (DEPLOY_AGENT + FRESH step-up MFA). */
export function useProbeVolumes(): UseMutationResult<BrowseVolume[], Error, PreflightRequest> {
  return useMutation({
    mutationFn: async (body: PreflightRequest) =>
      (await apiPost<BrowseVolume[]>("/deployment/probe-volumes", body)) as BrowseVolume[],
  });
}
