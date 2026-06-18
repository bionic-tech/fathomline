// Feature-page render tests. We mock the typed api client so no real fetch happens, then assert
// the RBAC gating + data rendering for the data-driven surfaces (Audit hidden without
// READ_AUDIT; Duplicates renders groups + reclaimable; Settings shows the principal).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet } = vi.hoisted(() => ({ apiGet: vi.fn() }));

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return { ...actual, apiGet };
});

const { Audit } = await import("./audit/Audit");
const { Duplicates } = await import("./duplicates/Duplicates");
const { Settings } = await import("./settings/Settings");

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function meWith(grants: Array<{ role: string }>) {
  return {
    subject: "u",
    source: "local",
    display_name: "U",
    groups: [],
    grants: grants.map((g) => ({ ...g, scope_kind: "global", host_id: null, volume_id: null })),
    mfa_fresh: true,
  };
}

afterEach(() => vi.clearAllMocks());

describe("Audit page RBAC", () => {
  it("refuses to render the log for a non-auditor principal", async () => {
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") return Promise.resolve(meWith([{ role: "viewer" }]));
      return Promise.resolve({ items: [], next_cursor: null });
    });
    wrap(<Audit />);
    expect(
      await screen.findByText(/restricted to auditors and admins/i),
    ).toBeInTheDocument();
  });

  it("renders audit rows for an admin principal", async () => {
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") return Promise.resolve(meWith([{ role: "admin" }]));
      if (path.startsWith("/audit"))
        return Promise.resolve({
          items: [
            {
              id: 1,
              ts: "2026-06-01T00:00:00Z",
              actor: "admin",
              action: "auth.login",
              target: "local",
              result: "granted",
              prev_hash: null,
              row_hash: "abc123def456789",
            },
          ],
          next_cursor: null,
        });
      return Promise.resolve({});
    });
    wrap(<Audit />);
    expect(await screen.findByText("auth.login")).toBeInTheDocument();
  });
});

describe("Duplicates page", () => {
  it("renders dup groups with reclaimable size for a viewer", async () => {
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") return Promise.resolve(meWith([{ role: "viewer" }]));
      if (path === "/volumes") return Promise.resolve([]);
      // Cross-cloud (provider-hash) section — distinct endpoint, matched before /duplicates.
      if (path.startsWith("/duplicates/provider"))
        return Promise.resolve({ items: [], truncated: false });
      if (path.startsWith("/duplicates"))
        return Promise.resolve({
          items: [
            {
              id: 7,
              full_hash: "ffffffffffffffffffff",
              size: 1024,
              member_count: 3,
              reclaimable_bytes: 2048,
              suggested_keeper_entry_id: null,
              suggested_keeper_reason: null,
            },
          ],
          next_cursor: null,
        });
      return Promise.resolve({});
    });
    wrap(<Duplicates />);
    // The reclaimable total appears in the header summary.
    expect(await screen.findByText(/Reclaimable on this page/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/ffffffffffff/)).toBeInTheDocument());
  });
});

describe("Settings page", () => {
  it("shows the principal and hides user-management for a non-admin", async () => {
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") return Promise.resolve(meWith([{ role: "viewer" }]));
      if (path === "/volumes") return Promise.resolve([]);
      return Promise.resolve([]);
    });
    wrap(<Settings />);
    expect(await screen.findByText("Your account")).toBeInTheDocument();
    expect(screen.queryByText(/Users & roles/i)).not.toBeInTheDocument();
  });
});
