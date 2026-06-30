// Estate-inventory modal (UC-charts-7). NOTE: the modal is an internal subcomponent of the
// Dashboard — it is not a standalone export and has no `open` prop (there is no charts/
// InventoryModal.tsx). It is therefore driven here through the Dashboard's "Volumes ▸" KPI button,
// the only way it opens. ChartAdapter is mocked so the dashboard's charts don't pull in
// ECharts/canvas (which jsdom lacks); the modal itself is plain DOM.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("./ChartAdapter", () => ({
  ChartAdapter: ({ ariaLabel }: { ariaLabel: string }) => <div data-testid="chart">{ariaLabel}</div>,
}));

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Dashboard } = await import("../features/dashboard/Dashboard");
const { useUiStore } = await import("../state/uiStore");

// Three volumes across two hosts → the modal should group them under nas-1 (two) and node-1 (one).
const VOLUMES = [
  { id: 1, host_id: 1, mountpoint: "/mnt/tank", display_name: null, fs_type: "zfs", used: 100, total: 200, free: 100 },
  { id: 2, host_id: 1, mountpoint: "/mnt/nc", display_name: "nextcloud-data", fs_type: "ext4", used: 50, total: 100, free: 50 },
  { id: 3, host_id: 2, mountpoint: "/mnt/backup", display_name: null, fs_type: "btrfs", used: 10, total: 20, free: 10 },
];
const AGENTS = [
  { id: 1, name: "nas-1" },
  { id: 2, name: "node-1" },
];

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function mockEstate(): void {
  apiGet.mockImplementation((url: string) => {
    if (url.startsWith("/volumes")) return Promise.resolve(VOLUMES);
    if (url.startsWith("/agents")) return Promise.resolve(AGENTS);
    if (url.startsWith("/duplicates/summary")) {
      return Promise.resolve({ group_count: 0, total_reclaimable_bytes: 0 });
    }
    return Promise.resolve([]);
  });
}

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Estate inventory modal (UC-charts-7)", () => {
  it("opens from the Volumes KPI and groups volumes by host", async () => {
    mockEstate();
    wrap(<Dashboard />);

    fireEvent.click(await screen.findByTitle("Show hosts and their volumes"));

    const dialog = await screen.findByRole("dialog", { name: /estate inventory/i });
    expect(dialog).toHaveTextContent(/2 host\(s\), 3 volume\(s\)/i);
    // Grouped per host (heading carries the host name).
    expect(screen.getByText(/nas-1/)).toBeInTheDocument();
    expect(screen.getByText(/node-1/)).toBeInTheDocument();
    // Volume rows: display_name wins over mountpoint when present.
    expect(screen.getByText("/mnt/tank")).toBeInTheDocument();
    expect(screen.getByText("nextcloud-data")).toBeInTheDocument();
    expect(screen.getByText("/mnt/backup")).toBeInTheDocument();
  });

  it("closes via the Close button", async () => {
    mockEstate();
    wrap(<Dashboard />);

    fireEvent.click(await screen.findByTitle("Show hosts and their volumes"));
    await screen.findByRole("dialog", { name: /estate inventory/i });

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: /estate inventory/i })).not.toBeInTheDocument(),
    );
  });
});
