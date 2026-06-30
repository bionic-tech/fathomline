// TreePane: the lazy drill-down tree. Without a path it shows a "select a volume" status; with a
// path + loaded children it renders the DrillTree treeitems.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TreeChildOut } from "../../api/types";

const { apiGet } = vi.hoisted(() => ({ apiGet: vi.fn() }));
vi.mock("../../api/client", async (orig) => ({
  ...(await orig<typeof import("../../api/client")>()), // keep toQuery
  apiGet,
}));

const { TreePane } = await import("./TreePane");

function child(over: Partial<TreeChildOut>): TreeChildOut {
  return {
    entry_id: 1, path: "/p/x", name: "x", is_dir: true, is_symlink: false,
    size_logical: 0, size_on_disk: 0, subtree_size_logical: 0, subtree_size_on_disk: 10,
    file_count: 0, mtime: 0, uid: 0, gid: 0, inode: 1, flags: {}, content_hash: null, ...over,
  };
}

function wrap(node: JSX.Element): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => vi.clearAllMocks());

describe("TreePane", () => {
  it("shows a select-a-volume status when there is no path", () => {
    apiGet.mockResolvedValue([]);
    wrap(<TreePane volumeId={1} path={null} selectedPath={null} onOpen={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent(/select a volume to browse/i);
  });

  it("renders the drill tree once children load for a path", async () => {
    apiGet.mockResolvedValue([child({ path: "/p/movies", name: "movies", is_dir: true })]);
    wrap(<TreePane volumeId={1} path="/p" selectedPath={null} onOpen={vi.fn()} />);
    expect(await screen.findByRole("tree")).toBeInTheDocument();
    expect(screen.getByText("movies")).toBeInTheDocument();
  });

  it("renders an in-pane error banner (not the neutral status) when the children query fails", async () => {
    // EC-explorer-19: a failed drill query now surfaces the app's standard inline error alert
    // inside the pane instead of falling back to the neutral "select a volume" status. (Previously
    // this asserted the neutral status with no alert — that silent-degradation behaviour is flipped.)
    apiGet.mockRejectedValue(new Error("boom"));
    wrap(<TreePane volumeId={1} path="/p" selectedPath={null} onOpen={vi.fn()} />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/couldn't load the directory tree/i);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(screen.queryByRole("tree")).not.toBeInTheDocument();
  });
});
