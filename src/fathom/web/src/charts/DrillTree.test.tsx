// DrillTree: the lazy drill-down tree pane — a treeitem per child, directories navigable, files
// disabled, the focused path marked aria-selected.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DrillTree } from "./DrillTree";
import { formatBytes } from "../lib/format";
import type { TreeChildOut } from "../api/types";

function child(over: Partial<TreeChildOut>): TreeChildOut {
  return {
    entry_id: 1,
    path: "/p/x",
    name: "x",
    is_dir: false,
    is_symlink: false,
    size_logical: 0,
    size_on_disk: 0,
    subtree_size_logical: 0,
    subtree_size_on_disk: 0,
    file_count: 0,
    mtime: 0,
    uid: 0,
    gid: 0,
    inode: 1,
    flags: {},
    content_hash: null,
    ...over,
  };
}

const CHILDREN = [
  child({ path: "/p/movies", name: "movies", is_dir: true, subtree_size_on_disk: 1024 }),
  child({ path: "/p/a.txt", name: "a.txt", is_dir: false, subtree_size_on_disk: 50 }),
];

describe("DrillTree", () => {
  it("renders a treeitem per child with name + formatted size", () => {
    render(<DrillTree path="/p" children={CHILDREN} onOpen={vi.fn()} selectedPath={null} />);
    expect(screen.getAllByRole("treeitem")).toHaveLength(2);
    expect(screen.getByText("movies")).toBeInTheDocument();
    expect(screen.getByText(formatBytes(1024))).toBeInTheDocument();
  });

  it("opens a directory on click but disables a file row", () => {
    const onOpen = vi.fn();
    render(<DrillTree path="/p" children={CHILDREN} onOpen={onOpen} selectedPath={null} />);
    const dirBtn = screen.getByRole("button", { name: /movies/ });
    const fileBtn = screen.getByRole("button", { name: /a\.txt/ });
    expect(fileBtn).toBeDisabled();
    fireEvent.click(dirBtn);
    expect(onOpen).toHaveBeenCalledWith(CHILDREN[0]);
  });

  it("marks the selected path as aria-selected", () => {
    render(<DrillTree path="/p" children={CHILDREN} onOpen={vi.fn()} selectedPath="/p/movies" />);
    const items = screen.getAllByRole("treeitem");
    const selected = items.find((li) => li.getAttribute("aria-selected") === "true");
    expect(selected).toHaveTextContent("movies");
  });
});
