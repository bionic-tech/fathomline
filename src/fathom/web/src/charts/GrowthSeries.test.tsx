// GrowthSeries wrapper: empty series → a plain "insufficient history" status (no chart); a
// populated series → the ECharts adapter, named for the path. ChartAdapter is mocked so the test
// doesn't need a canvas/ECharts in jsdom.

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("./ChartAdapter", () => ({
  ChartAdapter: ({ ariaLabel }: { ariaLabel: string }) => (
    <div data-testid="chart">{ariaLabel}</div>
  ),
}));

const { GrowthSeries } = await import("./GrowthSeries");

describe("GrowthSeries", () => {
  it("shows an insufficient-history status for an empty series", () => {
    render(<GrowthSeries series={{ volume_id: 1, path: "/p", points: [] }} />);
    expect(screen.getByRole("status")).toHaveTextContent(/insufficient history/i);
    expect(screen.queryByTestId("chart")).not.toBeInTheDocument();
  });

  it("renders the growth chart named for the path when there are points", () => {
    render(
      <GrowthSeries
        series={{
          volume_id: 1,
          path: "/mnt/pool",
          points: [
            { ts: "2026-06-01T00:00:00Z", total_size_logical: 10, total_size_on_disk: 12, file_count: 3 },
          ],
        }}
      />,
    );
    expect(screen.getByTestId("chart")).toHaveTextContent("/mnt/pool");
  });
});
