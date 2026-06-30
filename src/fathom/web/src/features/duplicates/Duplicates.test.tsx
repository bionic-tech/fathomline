// Duplicates tabs (ADR-043): the cross-cloud (provider-hash) section becomes a second tab ONLY when
// there's something to show — estates without rclone remotes keep the flat single table, no empty
// tab. The content table is always the default view.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Duplicates } = await import("./Duplicates");

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

const dupPage = {
  items: [
    { id: 1, full_hash: "abcdef0123456789", size: 1000, member_count: 2, reclaimable_bytes: 1000 },
  ],
  next_cursor: null,
};

const providerGroup = {
  algo: "md5",
  provider_hash: "ffeeddccbbaa9988",
  size: 2000,
  member_count: 2,
  reclaimable_bytes: 2000,
  members: [],
};

afterEach(() => vi.clearAllMocks());

describe("Duplicates page", () => {
  it("keeps a flat content table when there are no cross-cloud duplicates", async () => {
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") return Promise.resolve(meWith("viewer"));
      if (path.startsWith("/duplicates/provider")) return Promise.resolve({ items: [], truncated: false });
      if (path.startsWith("/duplicates")) return Promise.resolve(dupPage);
      return Promise.resolve([]); // /volumes etc.
    });

    wrap(<Duplicates />);

    expect(await screen.findByText(/abcdef012345/)).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /cross-cloud/i })).toBeNull();
  });

  it("adds a Cross-cloud tab when provider duplicates exist", async () => {
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") return Promise.resolve(meWith("viewer"));
      if (path.startsWith("/duplicates/provider"))
        return Promise.resolve({ items: [providerGroup], truncated: false });
      if (path.startsWith("/duplicates")) return Promise.resolve(dupPage);
      return Promise.resolve([]);
    });

    wrap(<Duplicates />);

    expect(await screen.findByRole("tab", { name: /content duplicates/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /cross-cloud/i })).toBeInTheDocument();
    // The content table stays the default (active) view.
    expect(screen.getByText(/abcdef012345/)).toBeInTheDocument();
  });
});
