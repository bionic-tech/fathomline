// Sunburst wrapper (mirrors Treemap.test.tsx): feeds the sunburst option + a11y table to the
// adapter and wires onDrill to the adapter's node-click. ChartAdapter is mocked (no ECharts/canvas
// in jsdom); the mock invokes onSelect so the drill wiring is exercised.
//
// UC-charts-3 also covers the Treemap⇄Sunburst toggle, which lives in the Dashboard composition
// panel (not in the Sunburst wrapper). It is exercised here by rendering the Dashboard with the
// same mocked adapter, where treemap vs sunburst is told apart by the adapter's aria label.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import type { TreemapNodeOut } from "../api/types";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("./ChartAdapter", () => ({
  ChartAdapter: ({ ariaLabel, onSelect }: { ariaLabel: string; onSelect?: (p: string) => void }) => (
    <button data-testid="chart" type="button" onClick={() => onSelect?.("/p/movies")}>
      {ariaLabel}
    </button>
  ),
}));

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Sunburst } = await import("./Sunburst");
const { Dashboard } = await import("../features/dashboard/Dashboard");
const { useUiStore } = await import("../state/uiStore");

const NODES: TreemapNodeOut[] = [
  { path: "/p/movies", name: "movies", is_dir: true, subtree_size_logical: 300, subtree_size_on_disk: 300, file_count: 2 },
];

const VOLUME = {
  id: 1,
  host_id: 1,
  mountpoint: "/mnt/pool",
  display_name: null,
  fs_type: "zfs",
  used: 100,
  total: 200,
  free: 100,
};

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Sunburst", () => {
  it("renders the sunburst adapter with its accessible label", () => {
    render(<Sunburst nodes={NODES} />);
    expect(screen.getByTestId("chart")).toHaveTextContent(/estate sunburst by on-disk size/i);
  });

  it("forwards node clicks to onDrill", () => {
    const onDrill = vi.fn();
    render(<Sunburst nodes={NODES} onDrill={onDrill} />);
    fireEvent.click(screen.getByTestId("chart"));
    expect(onDrill).toHaveBeenCalledWith("/p/movies");
  });
});

describe("Composition view toggle (UC-charts-3)", () => {
  it("flips aria-pressed and swaps treemap⇄sunburst without refetching the node set", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/treemap")) return Promise.resolve(NODES);
      if (url.startsWith("/history/series")) return Promise.resolve({ points: [] });
      if (url.startsWith("/duplicates/summary")) {
        return Promise.resolve({ group_count: 0, total_reclaimable_bytes: 0 });
      }
      return Promise.resolve([]);
    });

    wrap(<Dashboard />);
    fireEvent.click(await screen.findByRole("tab", { name: /composition/i }));

    // Default view is treemap: its toggle is pressed and the treemap adapter is shown.
    const treemapBtn = await screen.findByRole("button", { name: "Treemap" });
    const sunburstBtn = screen.getByRole("button", { name: "Sunburst" });
    expect(treemapBtn).toHaveAttribute("aria-pressed", "true");
    expect(sunburstBtn).toHaveAttribute("aria-pressed", "false");
    expect(await screen.findByText(/estate treemap by on-disk size/i)).toBeInTheDocument();

    const treemapFetches = (): number =>
      apiGet.mock.calls.map((c) => c[0] as string).filter((u) => u.startsWith("/treemap")).length;
    const before = treemapFetches();

    fireEvent.click(sunburstBtn);

    // The view swaps to the sunburst and aria-pressed flips across the pair.
    expect(await screen.findByText(/estate sunburst by on-disk size/i)).toBeInTheDocument();
    expect(screen.queryByText(/estate treemap by on-disk size/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sunburst" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Treemap" })).toHaveAttribute("aria-pressed", "false");
    // Pure view state: the same node set is reused, so no extra /treemap request fires.
    expect(treemapFetches()).toBe(before);
  });
});
