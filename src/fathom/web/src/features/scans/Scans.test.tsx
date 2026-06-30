// Scans (snapshot history) page render states — no test existed (GAPS: untested page). Mocks
// apiGet for /auth/me (capability gate), /volumes, and /scans; drives the select-a-volume prompt,
// the history table, the empty/error states, and the capability split: only an operator
// (trigger_fullbit_scan) gets the "Deep scan" request tab; a viewer sees the table alone.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Scans } = await import("./Scans");
const { useUiStore } = await import("../../state/uiStore");

const VOLUME = {
  id: 1,
  host_id: 1,
  mountpoint: "/mnt/pool",
  display_name: null,
  fs_type: "zfs",
  used: 1,
  total: 2,
  free: 1,
};

const SNAPSHOT = {
  id: 7,
  mode: "metadata",
  started_at: "2026-06-20T00:00:00Z",
  finished_at: "2026-06-20T00:05:00Z",
  entry_count: 1234,
  total_size_on_disk: 1000,
};

function _me(role: string): Record<string, unknown> {
  return {
    subject: "u",
    source: "local",
    display_name: "u",
    groups: [],
    grants: [{ role, scope_kind: "global", host_id: null, volume_id: null }],
    mfa_fresh: false,
    mfa_enrolled: false,
  };
}

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Scans page", () => {
  it("prompts to select a volume when none is selected", async () => {
    apiGet.mockImplementation((url: string) =>
      url.startsWith("/auth/me") ? Promise.resolve(_me("viewer")) : Promise.resolve([]),
    );
    wrap(<Scans />);
    expect(
      await screen.findByText(/select a volume from the top bar to see its scan history/i),
    ).toBeInTheDocument();
  });

  it("renders the snapshot history table for a viewer (no Deep scan tab)", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/auth/me")) return Promise.resolve(_me("viewer"));
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/scans")) return Promise.resolve([SNAPSHOT]);
      return Promise.resolve([]);
    });
    wrap(<Scans />);
    expect(await screen.findByText("Metadata (fast)")).toBeInTheDocument();
    // A viewer lacks trigger_fullbit_scan → the deep-scan request tab is never offered.
    expect(screen.queryByRole("tab", { name: /deep scan/i })).not.toBeInTheDocument();
  });

  it("offers the Deep scan request tab to an operator", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/auth/me")) return Promise.resolve(_me("operator"));
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/scans")) return Promise.resolve([SNAPSHOT]);
      return Promise.resolve([]);
    });
    wrap(<Scans />);
    expect(await screen.findByRole("tab", { name: /deep scan/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /history/i })).toBeInTheDocument();
  });

  it("shows the empty state when the volume has no scans", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) =>
      url.startsWith("/auth/me") ? Promise.resolve(_me("viewer")) : Promise.resolve([]),
    );
    wrap(<Scans />);
    expect(await screen.findByText(/no scans recorded for this volume yet/i)).toBeInTheDocument();
  });

  it("renders an error when the scans query fails", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/auth/me")) return Promise.resolve(_me("viewer"));
      if (url.startsWith("/scans")) return Promise.reject(new Error("boom"));
      return Promise.resolve([]);
    });
    wrap(<Scans />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
