// ListingPane: the sortable directory table. Covers the same-column sort-direction toggle and the
// DOM-bounding pager note (only the first PAGE=500 rows render for a huge directory).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TreeChildOut } from "../../api/types";

const { apiGet } = vi.hoisted(() => ({ apiGet: vi.fn() }));
vi.mock("../../api/client", async (orig) => ({
  ...(await orig<typeof import("../../api/client")>()), // keep toQuery / ApiError
  apiGet,
}));

const { ListingPane } = await import("./ListingPane");

function child(i: number, sizeOnDisk: number): TreeChildOut {
  return {
    entry_id: i,
    path: `/p/f${i}`,
    name: `f${i}`,
    is_dir: false,
    is_symlink: false,
    size_logical: sizeOnDisk,
    size_on_disk: sizeOnDisk,
    subtree_size_logical: sizeOnDisk,
    subtree_size_on_disk: sizeOnDisk,
    file_count: 0,
    mtime: i,
    uid: 0,
    gid: 0,
    inode: i,
    flags: {},
    content_hash: null,
  };
}

function wrap(children: TreeChildOut[]): void {
  apiGet.mockResolvedValue(children);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <ListingPane volumeId={1} path="/p" onSelect={vi.fn()} onOpen={vi.fn()} />
    </QueryClientProvider>,
  );
}

function dataRowNames(): string[] {
  const region = within(screen.getByRole("region", { name: /directory listing/i }));
  return region
    .getAllByRole("button")
    .map((b) => b.textContent ?? "")
    .filter((t) => /^f\d+$/.test(t));
}

afterEach(() => vi.clearAllMocks());

describe("ListingPane", () => {
  it("toggles sort direction when the same column header is clicked twice", async () => {
    // Default sort is on-disk descending → f-large (300) first.
    wrap([child(1, 100), child(2, 300), child(3, 200)]);
    await screen.findByText("f2"); // 300 → first
    expect(dataRowNames()).toEqual(["f2", "f3", "f1"]);

    // Click the On-disk header → flips to ascending (smallest first).
    fireEvent.click(screen.getByRole("button", { name: /on-disk/i }));
    expect(dataRowNames()).toEqual(["f1", "f3", "f2"]);
  });

  it("resets to the column's default direction when the sort key changes", async () => {
    // EC-explorer-25: switching columns does not carry the previous toggle — each key starts at
    // its own default (names/types ascending, sizes descending).
    wrap([child(1, 100), child(2, 300), child(3, 200)]);
    await screen.findByText("f2");

    // Toggle On-disk to ascending (smallest first).
    fireEvent.click(screen.getByRole("button", { name: /on-disk/i }));
    expect(dataRowNames()).toEqual(["f1", "f3", "f2"]);

    // Switching to another size column starts fresh at that column's default (descending), rather
    // than inheriting the ascending toggle from On-disk.
    fireEvent.click(screen.getByRole("button", { name: /logical/i }));
    expect(dataRowNames()).toEqual(["f2", "f3", "f1"]);
  });

  it("reflects the sorted column and direction through aria-sort", async () => {
    // EC-explorer-25: aria-sort tracks the active column; the others report "none".
    wrap([child(1, 100), child(2, 300), child(3, 200)]);
    await screen.findByText("f2");

    // Default sort: On-disk descending.
    expect(screen.getByRole("columnheader", { name: /on-disk/i })).toHaveAttribute(
      "aria-sort",
      "descending",
    );
    expect(screen.getByRole("columnheader", { name: /name/i })).toHaveAttribute("aria-sort", "none");

    // Clicking Name makes it the sorted column (ascending by default); On-disk resets to none.
    fireEvent.click(screen.getByRole("button", { name: /name/i }));
    expect(screen.getByRole("columnheader", { name: /name/i })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
    expect(screen.getByRole("columnheader", { name: /on-disk/i })).toHaveAttribute(
      "aria-sort",
      "none",
    );
  });

  it("renders at most PAGE rows and notes the truncation for a huge directory", async () => {
    const many = Array.from({ length: 501 }, (_, i) => child(i + 1, i + 1));
    wrap(many);
    // The note interpolates the counts as separate text nodes, so match the whole <p>.
    const note = await screen.findByText(
      (_, el) => el?.tagName === "P" && (el.textContent ?? "").includes("largest of 501 entries"),
    );
    expect(note).toBeInTheDocument();
    expect(dataRowNames()).toHaveLength(500); // DOM is bounded
  });

  it("renders all rows with no truncation note exactly at the PAGE boundary", async () => {
    // EC-explorer-23: the hint only appears when entries exceed PAGE — 500 is not truncated.
    const exactly = Array.from({ length: 500 }, (_, i) => child(i + 1, i + 1));
    wrap(exactly);
    await screen.findByText("f1"); // the smallest row still renders (all 500 are shown)
    expect(dataRowNames()).toHaveLength(500);
    expect(screen.queryByText(/largest of/i)).not.toBeInTheDocument();
  });

  it("renders an in-pane error banner (not an empty table) when the listing query fails", async () => {
    // EC-explorer-19: a rejected listing query now surfaces the app's standard inline error alert
    // inside the pane instead of degrading to a silent empty table. (Previously this asserted no
    // alert — the silent-degradation behaviour — which has been flipped.)
    apiGet.mockRejectedValue(new Error("boom"));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <ListingPane volumeId={1} path="/p" onSelect={vi.fn()} onOpen={vi.fn()} />
      </QueryClientProvider>,
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/couldn't load this directory/i);
    // The pane itself stays mounted, but no sort table (and so no data rows) renders behind the error.
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: /directory listing/i })).toBeInTheDocument();
  });
});
