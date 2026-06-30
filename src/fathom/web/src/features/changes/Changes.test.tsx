// Changes (churn feed) page render states — no test existed (GAPS: untested page). Mocks apiGet
// and drives the four states: select-a-volume prompt, populated rows, empty window, query error.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Changes } = await import("./Changes");
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

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

// The /changes request URLs apiGet saw, in order (carries the since= window anchor).
const changesCalls = (): string[] =>
  apiGet.mock.calls.map((c) => c[0] as string).filter((u) => u.startsWith("/changes"));

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Changes page", () => {
  it("prompts to select a volume when none is selected", async () => {
    apiGet.mockResolvedValue([]);
    wrap(<Changes />);
    expect(await screen.findByText(/select a volume from the top bar/i)).toBeInTheDocument();
  });

  it("renders the churn rows and maps the backend verb to a friendly badge (EC-changes-20)", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/changes")) {
        return Promise.resolve([
          // The backend emits the verb "create" (not "created") — the badge must still style it.
          {
            path: "/mnt/pool/new.mkv",
            change_type: "create",
            size_delta: 100,
            ts: "2026-06-20T00:00:00Z",
          },
        ]);
      }
      return Promise.resolve([]);
    });
    wrap(<Changes />);
    expect(await screen.findByText("/mnt/pool/new.mkv")).toBeInTheDocument();
    // "create" → friendly label "created" with the online badge class (not the default fallback).
    const badge = screen.getByText("created");
    expect(badge).toHaveClass("fathom-badge-online");
  });

  it("re-fetches with a new `since` when the window dropdown changes (UC-changes-3)", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/changes")) return Promise.resolve([]);
      return Promise.resolve([]);
    });
    wrap(<Changes />);
    // The default window (7 days) anchors a `since` timestamp on every request.
    await waitFor(() => expect(changesCalls().length).toBeGreaterThan(0));
    expect(changesCalls().every((u) => u.includes("since="))).toBe(true);

    // Switching to "All" (index 3) clears the bound → toQuery drops the null `since` param.
    fireEvent.change(screen.getByLabelText(/window/i), { target: { value: "3" } });
    await waitFor(() => expect(changesCalls().some((u) => !u.includes("since="))).toBe(true));
  });

  it("shows a truncation hint when the row count hits the cap (EC-changes-8)", async () => {
    // EC-changes-8: when the feed fills the requested limit (500) the window almost certainly
    // overflowed it, so the page now renders a "results may be truncated" hint. (Previously this
    // asserted no hint — the unimplemented divergence — which has been flipped.)
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    const rows = Array.from({ length: 500 }, (_, i) => ({
      path: `/mnt/pool/f${i}.bin`,
      change_type: "create",
      size_delta: 1,
      ts: "2026-06-20T00:00:00Z",
    }));
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/changes")) return Promise.resolve(rows);
      return Promise.resolve([]);
    });
    wrap(<Changes />);
    await screen.findByText("/mnt/pool/f0.bin");
    expect(screen.getByText(/results may be truncated/i)).toBeInTheDocument();
  });

  it("shows no truncation hint when the row count is under the cap", async () => {
    // The hint is gated on hitting the exact limit; a partial window renders plainly.
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    const rows = Array.from({ length: 3 }, (_, i) => ({
      path: `/mnt/pool/f${i}.bin`,
      change_type: "create",
      size_delta: 1,
      ts: "2026-06-20T00:00:00Z",
    }));
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/changes")) return Promise.resolve(rows);
      return Promise.resolve([]);
    });
    wrap(<Changes />);
    await screen.findByText("/mnt/pool/f0.bin");
    expect(screen.queryByText(/truncat/i)).not.toBeInTheDocument();
  });

  it("shows the empty state when the window has no changes", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockResolvedValue([]); // /volumes and /changes both empty
    wrap(<Changes />);
    expect(await screen.findByText(/no recorded changes in this window/i)).toBeInTheDocument();
  });

  it("renders an error (not the empty state) when the changes query fails", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/changes")) return Promise.reject(new Error("boom"));
      return Promise.resolve([]);
    });
    wrap(<Changes />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText(/no recorded changes in this window/i)).not.toBeInTheDocument();
  });
});
