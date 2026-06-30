// Explorer three-pane file manager (frontend ADD §4): no-volume prompt, the listing table, a
// directory drill (updates the shared path), and client-side column sorting. Scopes assertions to
// the "Directory listing" region so the tree pane's duplicate names don't make matches ambiguous.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet } = vi.hoisted(() => ({ apiGet: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet };
});

const { Explorer } = await import("./Explorer");
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
const CHILDREN = [
  {
    path: "/mnt/pool/movies",
    name: "movies",
    is_dir: true,
    is_symlink: false,
    subtree_size_logical: 300,
    subtree_size_on_disk: 300,
    file_count: 2,
    mtime: 1000,
  },
  {
    path: "/mnt/pool/a.txt",
    name: "a.txt",
    is_dir: false,
    is_symlink: false,
    subtree_size_logical: 50,
    subtree_size_on_disk: 50,
    file_count: 0,
    mtime: 2000,
  },
];

function dataRouter(url: string): Promise<unknown> {
  if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
  if (url.startsWith("/tree")) return Promise.resolve(CHILDREN);
  return Promise.resolve([]);
}

function wrap(node: JSX.Element): ReturnType<typeof render> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function listing(): HTMLElement {
  return screen.getByRole("region", { name: /directory listing/i });
}

function listingNames(): string[] {
  return within(listing())
    .getAllByRole("button")
    .map((b) => b.textContent ?? "")
    .filter((t) => /movies|a\.txt/.test(t));
}

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Explorer", () => {
  it("prompts to pick a volume when none is selected", () => {
    apiGet.mockImplementation(dataRouter);
    wrap(<Explorer />);
    expect(screen.getByText(/select a volume from the top bar to browse it/i)).toBeInTheDocument();
  });

  it("renders the directory listing rows for the selected volume", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation(dataRouter);
    wrap(<Explorer />);

    // The region exists immediately (empty table) — await the rows that the /tree query fills in.
    expect(await within(listing()).findByText("movies/")).toBeInTheDocument();
    expect(within(listing()).getByText("a.txt")).toBeInTheDocument();
  });

  it("drills into a directory when its name is clicked (updates the shared path)", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation(dataRouter);
    wrap(<Explorer />);

    fireEvent.click(await within(listing()).findByText("movies/"));
    expect(useUiStore.getState().selectedPath).toBe("/mnt/pool/movies");
  });

  it("sorts by name when the Name column header is clicked", async () => {
    useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool" });
    apiGet.mockImplementation(dataRouter);
    wrap(<Explorer />);

    // Default sort is on-disk descending → movies (300) before a.txt (50).
    await within(await screen.findByRole("region", { name: /directory listing/i })).findByText(
      "movies/",
    );
    expect(listingNames()).toEqual(["movies/", "a.txt"]);

    // Click Name → ascending by name → a.txt before movies.
    fireEvent.click(within(listing()).getByRole("button", { name: /^name/i }));
    expect(listingNames()).toEqual(["a.txt", "movies/"]);
  });
});
