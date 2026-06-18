// RBAC mirror unit tests — keep the client capability map in lockstep with principal.py's
// resolved role→caps matrix (ADD 13 §3). These are pure-function checks (no network).

import { describe, expect, it } from "vitest";

import type { Grant, MeResponse } from "../api/types";
import { capabilitiesOf, principalHas } from "./rbac";

function grant(role: string): Grant {
  return { role, scope_kind: "global", host_id: null, volume_id: null };
}

function me(grants: Grant[]): MeResponse {
  return {
    subject: "u",
    source: "local",
    display_name: null,
    groups: [],
    grants,
    mfa_fresh: true,
  };
}

describe("rbac capability mirror", () => {
  it("viewer holds the read capabilities but not audit/manage", () => {
    const caps = capabilitiesOf([grant("viewer")]);
    expect(caps.has("view_metadata")).toBe(true);
    expect(caps.has("view_dedup")).toBe(true);
    expect(caps.has("read_audit")).toBe(false);
    expect(caps.has("manage_users")).toBe(false);
  });

  it("operator inherits viewer and gains the scan triggers", () => {
    const caps = capabilitiesOf([grant("operator")]);
    expect(caps.has("view_dedup")).toBe(true);
    expect(caps.has("trigger_fullbit_scan")).toBe(true);
    expect(caps.has("read_audit")).toBe(false);
  });

  it("auditor is read-only with audit + config, parallel to admin", () => {
    const caps = capabilitiesOf([grant("auditor")]);
    expect(caps.has("read_audit")).toBe(true);
    expect(caps.has("read_config")).toBe(true);
    expect(caps.has("trigger_fullbit_scan")).toBe(false);
    expect(caps.has("manage_users")).toBe(false);
  });

  it("admin holds every capability", () => {
    const caps = capabilitiesOf([grant("admin")]);
    expect(caps.has("read_audit")).toBe(true);
    expect(caps.has("manage_users")).toBe(true);
    expect(caps.has("manage_agents")).toBe(true);
  });

  it("principalHas unions across multiple grants and is false without a principal", () => {
    expect(principalHas(me([grant("viewer"), grant("auditor")]), "read_audit")).toBe(true);
    expect(principalHas(me([grant("viewer")]), "manage_users")).toBe(false);
    expect(principalHas(undefined, "view_metadata")).toBe(false);
    expect(principalHas(me([grant("unknown_role")]), "view_metadata")).toBe(false);
  });
});
