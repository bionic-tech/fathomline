// Vitest + Testing Library: the DataTable alternative is a proper, labelled table reachable
// by assistive tech even when the chart is the visual default (frontend ADD §9, WCAG 2.1 AA).

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DataTable } from "./DataTable";
import { toDataTableTreemap } from "./chartOptions";

const table = toDataTableTreemap([
  { path: "/mnt/pool/movies", name: "movies", is_dir: true, subtree_size_logical: 300, subtree_size_on_disk: 300, file_count: 2 },
]);

describe("DataTable", () => {
  it("exposes a labelled table to assistive tech", () => {
    render(<DataTable table={table} />);
    const grid = screen.getByRole("table", { name: table.caption });
    expect(grid).toBeInTheDocument();
  });

  it("renders a header row and one data row", () => {
    render(<DataTable table={table} visible />);
    expect(screen.getAllByRole("columnheader")).toHaveLength(table.headers.length);
    expect(screen.getByText("movies")).toBeInTheDocument();
  });
});
