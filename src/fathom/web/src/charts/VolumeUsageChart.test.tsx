// VolumeUsageChart wrapper: picks the bar option by default and the single-volume pie for the pie
// variant, falling back to the bar when there is no volume to pie. ChartAdapter is mocked.

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { VolumeOut } from "../api/types";

vi.mock("./ChartAdapter", () => ({
  ChartAdapter: ({ ariaLabel }: { ariaLabel: string }) => (
    <div data-testid="chart">{ariaLabel}</div>
  ),
}));

const { VolumeUsageChart } = await import("./VolumeUsageChart");

const VOL: VolumeOut = {
  id: 1,
  host_id: 1,
  mountpoint: "/mnt/pool",
  fs_type: "zfs",
  device: "t",
  transport: "sata",
  raid_role: null,
  total: 200,
  used: 50,
  free: 150,
};

describe("VolumeUsageChart", () => {
  it("renders the grouped bar by default", () => {
    render(<VolumeUsageChart volumes={[VOL]} />);
    expect(screen.getByTestId("chart")).toHaveTextContent(/grouped by host/i);
  });

  it("renders a single-volume pie for the pie variant", () => {
    render(<VolumeUsageChart volumes={[VOL]} variant="pie" />);
    expect(screen.getByTestId("chart")).toHaveTextContent("/mnt/pool");
  });

  it("falls back to the bar when the pie variant has no volume", () => {
    render(<VolumeUsageChart volumes={[]} variant="pie" />);
    expect(screen.getByTestId("chart")).toHaveTextContent(/grouped by host/i);
  });
});
