// Largest ("what's eating my space?") page render states — no test existed (GAPS: untested page).
// Mocks apiGet; the page uses useNavigate so it is wrapped in a MemoryRouter. Drives the
// select-a-volume prompt, the ranked table (dir → drill button, file → span), empty, and error.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Largest } = await import("./Largest");
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

function _item(over: Record<string, unknown>) {
  return {
    path: "/mnt/pool/x",
    name: "x",
    is_dir: false,
    size_on_disk: 100,
    size_logical: 100,
    file_count: 0,
    ...over,
  };
}

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

// The /top-n request URLs apiGet was called with, in order (carries the by=/kind= query params).
const topNCalls = (): string[] =>
  apiGet.mock.calls.map((c) => c[0] as string).filter((u) => u.startsWith("/top-n"));

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Largest page", () => {
  it("prompts to select a volume when none is selected", async () => {
    apiGet.mockResolvedValue([]);
    wrap(<Largest />);
    expect(await screen.findByText(/select a volume from the top bar/i)).toBeInTheDocument();
  });

  it("ranks items: a directory drills, a file does not", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/top-n")) {
        return Promise.resolve([
          _item({ path: "/mnt/pool/movies", name: "movies", is_dir: true, file_count: 3 }),
          _item({ path: "/mnt/pool/a.mkv", name: "a.mkv", is_dir: false }),
        ]);
      }
      return Promise.resolve([]);
    });
    wrap(<Largest />);
    // The directory is a drill-in button ("movies/"); the file is plain text.
    expect(await screen.findByRole("button", { name: "movies/" })).toBeInTheDocument();
    expect(screen.getByText("a.mkv")).toBeInTheDocument();
  });

  it("re-ranks with by=logical when the Size select changes (UC-largest-1/2)", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/top-n")) return Promise.resolve([_item({})]);
      return Promise.resolve([]);
    });
    wrap(<Largest />);
    // The initial ranking is by on-disk size (the default basis).
    await screen.findByRole("table");
    expect(topNCalls().some((u) => u.includes("by=on_disk"))).toBe(true);

    fireEvent.change(screen.getByLabelText(/size/i), { target: { value: "logical" } });
    // Flipping the basis re-keys the query → a fresh request with by=logical.
    await waitFor(() => expect(topNCalls().some((u) => u.includes("by=logical"))).toBe(true));
  });

  it("re-ranks with kind=dir then kind=file when the Kind select changes (UC-largest-3/4)", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      if (url.startsWith("/top-n")) return Promise.resolve([_item({})]);
      return Promise.resolve([]);
    });
    wrap(<Largest />);
    await screen.findByRole("table");
    // Defaults to kind=any.
    expect(topNCalls().every((u) => u.includes("kind=any"))).toBe(true);

    fireEvent.change(screen.getByLabelText(/kind/i), { target: { value: "dir" } });
    await waitFor(() => expect(topNCalls().some((u) => u.includes("kind=dir"))).toBe(true));

    fireEvent.change(screen.getByLabelText(/kind/i), { target: { value: "file" } });
    await waitFor(() => expect(topNCalls().some((u) => u.includes("kind=file"))).toBe(true));
  });

  it("shows the empty state when nothing is ranked", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockResolvedValue([]); // /volumes and /top-n both empty
    wrap(<Largest />);
    expect(await screen.findByText(/no ranked items/i)).toBeInTheDocument();
  });

  it("renders an error (not the empty state) when the top-n query fails", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/top-n")) return Promise.reject(new Error("boom"));
      return Promise.resolve([]);
    });
    wrap(<Largest />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText(/no ranked items/i)).not.toBeInTheDocument();
  });
});
