// Search (estate find-a-file) page render states — no test existed (GAPS: catalogue-explorer
// "no Explorer/Search/pane tests"). Submitting the form sets the term immediately (bypassing the
// 300ms keystroke debounce), so we can drive: the <2-char prompt, results, empty, and error.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const navigate = vi.fn();
vi.mock("react-router-dom", async (orig) => ({
  ...(await orig<typeof import("react-router-dom")>()),
  useNavigate: () => navigate,
}));

const { Search } = await import("./Search");
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
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function _result(over: Record<string, unknown>) {
  return {
    path: "/mnt/pool/movie.mkv",
    name: "movie.mkv",
    is_dir: false,
    size_on_disk: 100,
    host_id: 1,
    volume_id: 1,
    ...over,
  };
}

/** Type a term and submit the search form (immediate, no debounce wait). */
function searchFor(term: string): void {
  fireEvent.change(screen.getByRole("searchbox"), { target: { value: term } });
  fireEvent.submit(screen.getByRole("search"));
}

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({
    selectedHostId: null,
    selectedVolumeId: null,
    selectedPath: null,
    view: "dashboard",
  });
});

describe("Search page", () => {
  it("prompts for at least two characters before searching", async () => {
    apiGet.mockResolvedValue([]);
    wrap(<Search />);
    expect(await screen.findByText(/type at least two characters/i)).toBeInTheDocument();
  });

  it("renders matching results as jump-to-Explorer buttons", async () => {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/search")) return Promise.resolve([_result({})]);
      return Promise.resolve([]); // /agents, /volumes for useNames
    });
    wrap(<Search />);
    searchFor("mkv");
    expect(await screen.findByRole("button", { name: /movie\.mkv/ })).toBeInTheDocument();
  });

  it("shows the empty state when nothing matches", async () => {
    apiGet.mockResolvedValue([]); // /search returns []
    wrap(<Search />);
    searchFor("zzz");
    expect(await screen.findByText(/no live entries match/i)).toBeInTheDocument();
  });

  it("renders an error when the search query fails", async () => {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/search")) return Promise.reject(new Error("boom"));
      return Promise.resolve([]);
    });
    wrap(<Search />);
    searchFor("err");
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  it("jumps a clicked result into the Explorer (UC-explorer-5/6)", async () => {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/search")) return Promise.resolve([_result({})]);
      if (url.startsWith("/volumes")) return Promise.resolve([VOLUME]);
      return Promise.resolve([]); // /agents for useNames
    });
    wrap(<Search />);
    searchFor("mkv");

    // Wait for the volumes query to resolve (the location cell switches "vol 1" → label) so the
    // jump can resolve the result's volume.
    await screen.findByText("mnt/pool");
    fireEvent.click(screen.getByRole("button", { name: /movie\.mkv/ }));

    // selectVolume scopes the host/volume (and seeds the mountpoint), then selectPath narrows to
    // the file's parent dir; the view flips to Explorer and the router navigates to /explore.
    expect(navigate).toHaveBeenCalledWith("/explore");
    const s = useUiStore.getState();
    expect(s.view).toBe("explorer");
    expect(s.selectedHostId).toBe(1);
    expect(s.selectedVolumeId).toBe(1);
    expect(s.selectedPath).toBe("/mnt/pool");
  });
});
