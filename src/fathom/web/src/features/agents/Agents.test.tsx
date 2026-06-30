// Agents (fleet health) page — the P5 host-grouped redesign + P3 "Scan now". Mocks apiGet for
// /auth/me (capability gate), /agents, and /volumes; apiPost for the scan-dispatch endpoint. Drives
// empty/error, host cards, the outcome status badges (ok/partial/failed/never), volume grouping,
// the Advanced (agent config) disclosure, and the Scan now control (root+mode body, 503 copy,
// capability gate).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Agents } = await import("./Agents");
const { ApiError } = await import("../../api/client");

const HOST = {
  id: 1,
  name: "nas-1",
  os: "TrueNAS",
  agent_version: "0.2.0",
  volume_count: 1,
  last_seen: null,
  last_run_outcome: null,
  last_run_finished_at: null,
  last_run_entries_seen: null,
  last_run_scopes_failed: null,
  reported_config: null,
  desired_config: null,
};

const HOST_B = {
  id: 2,
  name: "node-1",
  os: "Debian",
  agent_version: "0.2.0",
  volume_count: 1,
  last_seen: null,
  last_run_outcome: "ok",
  last_run_finished_at: "2026-06-20T00:00:00Z",
  last_run_entries_seen: 5,
  last_run_scopes_failed: 0,
  reported_config: null,
  desired_config: null,
};

const VOLUME = {
  id: 10,
  host_id: 1,
  mountpoint: "/scan/tank",
  display_name: null,
  fs_type: "zfs",
  device: "tank",
  transport: "local",
  raid_role: null,
  total: 2_000_000,
  used: 1_000_000,
  free: 1_000_000,
};

const VOLUME_B = {
  id: 20,
  host_id: 2,
  mountpoint: "/scan/data",
  display_name: null,
  fs_type: "ext4",
  device: "sda",
  transport: "local",
  raid_role: null,
  total: 100,
  used: 50,
  free: 50,
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

function mockApi(role: string, hosts: unknown[], volumes: unknown[] = []): void {
  apiGet.mockImplementation((url: string) => {
    if (url.startsWith("/auth/me")) return Promise.resolve(_me(role));
    if (url.startsWith("/agents")) return Promise.resolve(hosts);
    if (url.startsWith("/volumes")) return Promise.resolve(volumes);
    return Promise.resolve([]);
  });
}

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function cardFor(name: string): HTMLElement {
  return screen.getByRole("heading", { name }).closest("article") as HTMLElement;
}

afterEach(() => vi.clearAllMocks());

describe("Agents page", () => {
  it("shows the empty state when no agents have registered", async () => {
    mockApi("admin", []);
    wrap(<Agents />);
    expect(
      await screen.findByText(/no agents have registered with this core yet/i),
    ).toBeInTheDocument();
  });

  it("renders a host card with its status badge and OS", async () => {
    mockApi("admin", [HOST], [VOLUME]);
    wrap(<Agents />);
    expect(await screen.findByRole("heading", { name: "nas-1" })).toBeInTheDocument();
    // last_run_outcome is null → the host has never reported a run.
    expect(within(cardFor("nas-1")).getByText("never scanned")).toBeInTheDocument();
    expect(screen.getByText(/TrueNAS · agent/)).toBeInTheDocument();
  });

  it("renders an error when the agents query fails", async () => {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/auth/me")) return Promise.resolve(_me("admin"));
      if (url.startsWith("/agents")) return Promise.reject(new Error("boom"));
      return Promise.resolve([]);
    });
    wrap(<Agents />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  it("tells a viewer that enrol/revoke is not available to their role", async () => {
    mockApi("viewer", []);
    wrap(<Agents />);
    expect(await screen.findByText(/not available to your role/i)).toBeInTheDocument();
  });

  it("omits the not-available copy for an admin (manage_agents)", async () => {
    mockApi("admin", []);
    wrap(<Agents />);
    // The header renders before whoami resolves (canManage defaults false), so the viewer-only
    // copy shows transiently; once /auth/me resolves as admin it must disappear.
    await waitFor(() =>
      expect(screen.queryByText(/not available to your role/i)).not.toBeInTheDocument(),
    );
  });

  it("groups each host's volumes under its own card as friendly host:path rows", async () => {
    mockApi("admin", [HOST, HOST_B], [VOLUME, VOLUME_B]);
    wrap(<Agents />);
    expect(await screen.findByRole("heading", { name: "nas-1" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "node-1" })).toBeInTheDocument();

    const cardA = cardFor("nas-1");
    expect(within(cardA).getByText(/nas-1: tank/)).toBeInTheDocument();
    expect(within(cardA).queryByText(/node-1: data/)).not.toBeInTheDocument();

    const cardB = cardFor("node-1");
    expect(within(cardB).getByText(/node-1: data/)).toBeInTheDocument();
  });

  it("maps each last-run outcome to a clear status badge (ok/partial/failed/never)", async () => {
    mockApi(
      "admin",
      [
        { ...HOST, id: 1, name: "h-never", last_run_outcome: null },
        { ...HOST, id: 2, name: "h-ok", last_run_outcome: "ok", last_run_finished_at: "2026-06-20T00:00:00Z" },
        { ...HOST, id: 3, name: "h-fail", last_run_outcome: "failed", last_run_finished_at: "2026-06-20T00:00:00Z" },
        {
          ...HOST,
          id: 4,
          name: "h-part",
          last_run_outcome: "partial",
          last_run_scopes_failed: 2,
          last_run_finished_at: "2026-06-20T00:00:00Z",
        },
      ],
      [],
    );
    wrap(<Agents />);
    await screen.findByRole("heading", { name: "h-never" });
    expect(within(cardFor("h-never")).getByText("never scanned")).toBeInTheDocument();
    expect(within(cardFor("h-ok")).getByText("ok")).toBeInTheDocument();
    expect(within(cardFor("h-fail")).getByText("failed")).toBeInTheDocument();
    expect(within(cardFor("h-part")).getByText("partial (2)")).toBeInTheDocument();
  });

  it("folds the advanced agent config behind a disclosure (hidden by default)", async () => {
    mockApi("admin", [HOST], [VOLUME]);
    wrap(<Agents />);
    await screen.findByRole("heading", { name: "nas-1" });
    expect(screen.queryByText(/effective config/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /advanced/i }));
    expect(await screen.findByText(/effective config/i)).toBeInTheDocument();
  });

  it("dispatches a Scan now to /agents/{id}/scan with the chosen root + mode", async () => {
    apiPost.mockResolvedValue({ job_id: "job-1" });
    mockApi("admin", [HOST], [VOLUME]);
    wrap(<Agents />);
    await screen.findByRole("heading", { name: "nas-1" });

    const volRow = screen.getByText(/nas-1: tank/).closest("li") as HTMLElement;
    fireEvent.change(within(volRow).getByRole("combobox", { name: /scan mode/i }), {
      target: { value: "fullbit" },
    });
    fireEvent.click(within(volRow).getByRole("button", { name: /scan now/i }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/agents/1/scan", {
        root: "/scan/tank",
        mode: "fullbit",
      }),
    );
    expect(await within(volRow).findByText(/scan queued/i)).toBeInTheDocument();
  });

  it("shows the not-enabled-yet hint when scan dispatch 503s", async () => {
    apiPost.mockRejectedValue(new ApiError(503, { detail: "dispatch off" }));
    mockApi("admin", [HOST], [VOLUME]);
    wrap(<Agents />);
    await screen.findByRole("heading", { name: "nas-1" });

    const volRow = screen.getByText(/nas-1: tank/).closest("li") as HTMLElement;
    fireEvent.click(within(volRow).getByRole("button", { name: /scan now/i }));

    expect(
      await screen.findByText(/scan dispatch isn't enabled on this server yet/i),
    ).toBeInTheDocument();
  });

  it("hides the Scan now control from a viewer (no trigger_metadata_scan)", async () => {
    mockApi("viewer", [HOST], [VOLUME]);
    wrap(<Agents />);
    await screen.findByRole("heading", { name: "nas-1" });
    expect(screen.queryByRole("button", { name: /scan now/i })).not.toBeInTheDocument();
  });

  it("shows Scan now to an operator (trigger_metadata_scan) even without manage_agents", async () => {
    // Scan Now is gated on TRIGGER_METADATA_SCAN, not MANAGE_AGENTS — an operator who can trigger
    // scans gets the button (matching the backend) while config overrides stay admin-only.
    mockApi("operator", [HOST], [VOLUME]);
    wrap(<Agents />);
    await screen.findByRole("heading", { name: "nas-1" });
    expect(screen.getAllByRole("button", { name: /scan now/i }).length).toBeGreaterThan(0);
    // …but the admin-only "not available to your role" copy is gone (they aren't an admin) and the
    // override save affordance is absent: open Advanced and confirm no save-override control.
    fireEvent.click(screen.getAllByRole("button", { name: /advanced/i })[0]);
    expect(screen.queryByRole("button", { name: /save override|apply override/i })).not.toBeInTheDocument();
  });
});
