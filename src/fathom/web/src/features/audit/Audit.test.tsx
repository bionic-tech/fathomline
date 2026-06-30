// Audit tabs (ADR-043): Log (table + pager) by default, with a dedicated Integrity tab that
// explains + reports the hash-chain continuity check. Restricted to auditors/admins.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Audit } = await import("./Audit");

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function meWith(role: string) {
  return {
    subject: "u",
    source: "local",
    display_name: "U",
    groups: [],
    grants: [{ role, scope_kind: "global", host_id: null, volume_id: null }],
    mfa_fresh: true,
  };
}

const auditPage = {
  items: [
    {
      id: 1,
      ts: "2026-06-20T10:00:00+00:00",
      actor: "admin",
      action: "settings.set",
      target: "concierge_enabled",
      result: "ok",
      row_hash: "aaaa111122223333",
      prev_hash: "0000000000000000",
    },
  ],
  next_cursor: null,
};

afterEach(() => vi.clearAllMocks());

describe("Audit page", () => {
  it("refuses to render for a principal without read_audit", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("viewer")) : Promise.resolve(auditPage),
    );
    wrap(<Audit />);
    expect(await screen.findByText(/restricted to auditors and admins/i)).toBeInTheDocument();
  });

  it("shows the Log table and an Integrity tab reporting an intact chain", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("auditor")) : Promise.resolve(auditPage),
    );
    wrap(<Audit />);

    // Default Log tab shows the record.
    expect(await screen.findByText("settings.set")).toBeInTheDocument();
    // Integrity tab reports the chain check.
    fireEvent.click(screen.getByRole("tab", { name: /integrity/i }));
    expect(await screen.findByText(/chain intact across all 1 row/i)).toBeInTheDocument();
  });
});
