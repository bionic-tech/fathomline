// Client-side RBAC mirror of the server permission matrix (src/fathom/auth/principal.py,
// ADD 13 §3). This is a *UX* layer only — it hides/disables surfaces the principal lacks so the
// UI never offers a control the server would 403. The server remains authoritative: deny-by-
// default scope/capability enforcement runs on every request regardless of what the SPA renders
// (frontend ADD §2; ADD 13 §3/§4). Keep the capability set + role→caps map in lockstep with the
// Python matrix so the two never drift.

import type { Grant, MeResponse } from "../api/types";

export type Capability =
  | "view_metadata"
  | "preview"
  | "view_dedup"
  | "trigger_metadata_scan"
  | "trigger_fullbit_scan"
  | "build_remediation"
  | "execute_remediation"
  | "quarantine_manage"
  | "read_audit"
  | "read_config"
  | "manage_users"
  | "manage_agents"
  | "deploy_agent";

export type Role = "viewer" | "operator" | "remediator" | "auditor" | "admin";

// Role → capabilities, inheritance already resolved (viewer < operator < remediator), with the
// parallel read-only auditor and the all-powerful admin — exactly the resolved sets in
// principal.py's _ROLE_CAPS.
const VIEWER: Capability[] = ["view_metadata", "preview", "view_dedup"];
const OPERATOR: Capability[] = [...VIEWER, "trigger_metadata_scan", "trigger_fullbit_scan"];
const REMEDIATOR: Capability[] = [
  ...OPERATOR,
  "build_remediation",
  "execute_remediation",
  "quarantine_manage",
];
const AUDITOR: Capability[] = [...VIEWER, "read_audit", "read_config"];
const ALL: Capability[] = [
  "view_metadata",
  "preview",
  "view_dedup",
  "trigger_metadata_scan",
  "trigger_fullbit_scan",
  "build_remediation",
  "execute_remediation",
  "quarantine_manage",
  "read_audit",
  "read_config",
  "manage_users",
  "manage_agents",
  "deploy_agent",
];

const ROLE_CAPS: Record<Role, Capability[]> = {
  viewer: VIEWER,
  operator: OPERATOR,
  remediator: REMEDIATOR,
  auditor: AUDITOR,
  admin: ALL,
};

function roleHas(role: string, cap: Capability): boolean {
  const caps = ROLE_CAPS[role as Role];
  return caps !== undefined && caps.includes(cap);
}

/** The set of capabilities a principal holds across all its grants (any-scope union). */
export function capabilitiesOf(grants: readonly Grant[] | undefined): Set<Capability> {
  const out = new Set<Capability>();
  for (const g of grants ?? []) {
    for (const cap of ROLE_CAPS[g.role as Role] ?? []) out.add(cap);
  }
  return out;
}

/**
 * Whether the principal holds `cap` in *some* scope. The server still enforces the precise
 * (capability, scope) check per request — this only governs whether the UI offers the control.
 */
export function principalHas(me: MeResponse | undefined, cap: Capability): boolean {
  if (!me) return false;
  return me.grants.some((g) => roleHas(g.role, cap));
}
