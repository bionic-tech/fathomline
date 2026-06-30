// Dashboard error-state regression (EC-charts-18/19): a FAILED chart query must render an
// error + retry, never the "no data — run a scan" empty state (which would tell the operator to
// run a scan that already ran). Each chart panel branches on isError BEFORE the empty branch.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

// Stub the single ECharts adapter so the composition charts render as a clickable button (no
// canvas/ECharts in jsdom). The button forwards onSelect with a node path so the drill wiring is
// observable; the button text is the adapter's aria label so treemap vs sunburst is distinguishable.
vi.mock("../../charts/ChartAdapter", () => ({
  ChartAdapter: ({ ariaLabel, onSelect }: { ariaLabel: string; onSelect?: (p: string) => void }) => (
    <button data-testid="chart" type="button" onClick={() => onSelect?.("/mnt/pool/movies")}>
      {ariaLabel}
    </button>
  ),
}));

const { Dashboard } = await import("./Dashboard");
const { useUiStore } = await import("../../state/uiStore");

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

const NODE = {
  path: "/mnt/pool/movies",
  name: "movies",
  is_dir: true,
  subtree_size_logical: 300,
  subtree_size_on_disk: 300,
  file_count: 2,
};

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => {
  vi.clearAllMocks();
  // Reset the shared zustand selection so one test's selected volume doesn't leak into the next.
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Dashboard chart error states", () => {
  it("shows an error + retry on the capacity tab when /volumes fails (not a stuck spinner)", async () => {
    apiGet.mockRejectedValue(new Error("network down"));

    wrap(<Dashboard />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/couldn't load volumes/i);
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
    // The bug being guarded: it must NOT sit on the "Loading volumes…" placeholder forever.
    expect(screen.queryByText(/loading volumes/i)).not.toBeInTheDocument();
  });

  it("shows an error + retry on the composition tab when the treemap query fails", async () => {
    // A volume is selected, so the treemap query is enabled and can fail.
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/treemap")) return Promise.reject(new Error("treemap 504"));
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/history/series")) return Promise.resolve({ points: [] });
      if (url.startsWith("/duplicates/summary")) {
        return Promise.resolve({ group_count: 0, total_reclaimable_bytes: 0 });
      }
      return Promise.resolve([]);
    });

    wrap(<Dashboard />);
    fireEvent.click(await screen.findByRole("tab", { name: /composition/i }));

    expect(await screen.findByText(/couldn't load composition data/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
    // The divergence: a query ERROR must not be reported as the empty "run a scan" state.
    expect(screen.queryByText(/no composition data/i)).not.toBeInTheDocument();
  });

  it("still shows the empty 'run a scan' state when the treemap succeeds with no nodes", async () => {
    // Regression guard: the empty branch must survive once isError is checked first.
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/history/series")) return Promise.resolve({ points: [] });
      if (url.startsWith("/duplicates/summary")) {
        return Promise.resolve({ group_count: 0, total_reclaimable_bytes: 0 });
      }
      return Promise.resolve([]); // treemap returns [] → empty, not error
    });

    wrap(<Dashboard />);
    fireEvent.click(await screen.findByRole("tab", { name: /composition/i }));

    expect(await screen.findByText(/no composition data/i)).toBeInTheDocument();
    expect(screen.queryByText(/couldn't load composition data/i)).not.toBeInTheDocument();
  });

  it("shows 'not enough history' (not 'select a volume') once a volume is selected", async () => {
    // EC-charts-19: with a volume selected, an empty growth series means "insufficient history",
    // not "pick a volume" — the growth panel now branches on selection like composition does.
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/history/series")) return Promise.resolve({ points: [] });
      if (url.startsWith("/duplicates/summary")) {
        return Promise.resolve({ group_count: 0, total_reclaimable_bytes: 0 });
      }
      return Promise.resolve([]);
    });

    wrap(<Dashboard />);
    fireEvent.click(await screen.findByRole("tab", { name: /growth/i }));

    expect(await screen.findByText(/not enough history yet/i)).toBeInTheDocument();
    expect(
      screen.queryByText(/select a volume to view growth over time/i),
    ).not.toBeInTheDocument();
  });
});

describe("Dashboard composition drill", () => {
  function mockComposition(): void {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/treemap")) return Promise.resolve([NODE]);
      if (url.startsWith("/history/series")) return Promise.resolve({ points: [] });
      if (url.startsWith("/duplicates/summary")) {
        return Promise.resolve({ group_count: 0, total_reclaimable_bytes: 0 });
      }
      return Promise.resolve([]);
    });
  }

  it("drills into a clicked composition node via selectPath (UC-charts-2)", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    mockComposition();

    wrap(<Dashboard />);
    fireEvent.click(await screen.findByRole("tab", { name: /composition/i }));
    // Clicking the (stubbed) treemap fires onSelect → drill → selectPath.
    fireEvent.click(await screen.findByText(/estate treemap by on-disk size/i));
    await waitFor(() => expect(useUiStore.getState().selectedPath).toBe("/mnt/pool/movies"));
  });

  it("re-roots to the volume mount when the root breadcrumb is clicked (UC-charts-4)", async () => {
    // Drilled in: the mount crumb is a button; clicking it resets the drill to the volume root.
    useUiStore.setState({
      selectedHostId: 1,
      selectedVolumeId: 1,
      selectedPath: "/mnt/pool/movies",
    });
    mockComposition();

    wrap(<Dashboard />);
    fireEvent.click(await screen.findByRole("tab", { name: /composition/i }));
    fireEvent.click(await screen.findByRole("button", { name: "/mnt/pool" }));
    await waitFor(() => expect(useUiStore.getState().selectedPath).toBe("/mnt/pool"));
  });
});
