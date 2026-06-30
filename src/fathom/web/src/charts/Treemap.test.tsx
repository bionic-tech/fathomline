// Treemap wrapper: feeds the treemap option + a11y table to the adapter and wires onDrill to the
// adapter's node-click. ChartAdapter is mocked (no ECharts/canvas in jsdom); the mock invokes
// onSelect so the drill wiring is exercised.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { TreemapNodeOut } from "../api/types";

vi.mock("./ChartAdapter", () => ({
  ChartAdapter: ({ ariaLabel, onSelect }: { ariaLabel: string; onSelect?: (p: string) => void }) => (
    <button data-testid="chart" type="button" onClick={() => onSelect?.("/p/movies")}>
      {ariaLabel}
    </button>
  ),
}));

const { Treemap } = await import("./Treemap");

const NODES: TreemapNodeOut[] = [
  { path: "/p/movies", name: "movies", is_dir: true, subtree_size_logical: 300, subtree_size_on_disk: 300, file_count: 2 },
];

describe("Treemap", () => {
  it("renders the treemap adapter with its accessible label", () => {
    render(<Treemap nodes={NODES} />);
    expect(screen.getByTestId("chart")).toHaveTextContent(/estate treemap by on-disk size/i);
  });

  it("forwards node clicks to onDrill", () => {
    const onDrill = vi.fn();
    render(<Treemap nodes={NODES} onDrill={onDrill} />);
    fireEvent.click(screen.getByTestId("chart"));
    expect(onDrill).toHaveBeenCalledWith("/p/movies");
  });
});
