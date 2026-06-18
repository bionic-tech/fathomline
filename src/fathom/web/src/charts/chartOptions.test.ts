// Vitest: ChartAdapter builders produce valid ECharts options, and EVERY chart has a matching
// DataTable alternative with the same row count (frontend ADD §9 — a11y parity).

import { describe, expect, it } from "vitest";

import type {
  GrowthSeriesOut,
  TopNItemOut,
  TreemapNodeOut,
  VolumeOut,
} from "../api/types";
import {
  buildGrowthLineOption,
  buildSunburstOption,
  buildTopNBarOption,
  buildTreemapOption,
  buildVolumeBarOption,
  buildVolumePieOption,
  toDataTableGrowth,
  toDataTableTopN,
  toDataTableTreemap,
  toDataTableVolumes,
} from "./chartOptions";

const treemapNodes: TreemapNodeOut[] = [
  { path: "/mnt/pool/movies", name: "movies", is_dir: true, subtree_size_logical: 300, subtree_size_on_disk: 300, file_count: 2 },
  { path: "/mnt/pool/docs", name: "docs", is_dir: true, subtree_size_logical: 50, subtree_size_on_disk: 50, file_count: 1 },
];

const volumes: VolumeOut[] = [
  { id: 1, host_id: 1, mountpoint: "/mnt/pool", fs_type: "zfs", device: "tank", transport: "sata", raid_role: null, total: 1000, used: 400, free: 600 },
];

const topN: TopNItemOut[] = [
  { path: "/mnt/pool/movies", name: "movies", is_dir: true, size_logical: 300, size_on_disk: 300, file_count: 2 },
  { path: "/mnt/pool/docs", name: "docs", is_dir: true, size_logical: 50, size_on_disk: 50, file_count: 1 },
];

const growth: GrowthSeriesOut = {
  volume_id: 1,
  path: "/mnt/pool",
  points: [
    { ts: "2026-01-01T00:00:00Z", total_size_logical: 100, total_size_on_disk: 100, file_count: 1 },
    { ts: "2026-02-01T00:00:00Z", total_size_logical: 350, total_size_on_disk: 350, file_count: 3 },
  ],
};

function seriesType(option: Record<string, unknown>): string {
  const series = option.series as Array<{ type: string }>;
  return series[0].type;
}

describe("ChartAdapter option builders", () => {
  it("builds a treemap series", () => {
    expect(seriesType(buildTreemapOption(treemapNodes))).toBe("treemap");
  });
  it("builds a sunburst series", () => {
    expect(seriesType(buildSunburstOption(treemapNodes))).toBe("sunburst");
  });
  it("builds a volume bar (used+free stacked)", () => {
    const option = buildVolumeBarOption(volumes);
    const series = option.series as Array<{ type: string }>;
    expect(series).toHaveLength(2);
    expect(series.every((s) => s.type === "bar")).toBe(true);
  });
  it("builds a volume pie", () => {
    expect(seriesType(buildVolumePieOption(volumes[0]))).toBe("pie");
  });
  it("builds a top-N bar", () => {
    expect(seriesType(buildTopNBarOption(topN))).toBe("bar");
  });
  it("builds a growth line", () => {
    expect(seriesType(buildGrowthLineOption(growth))).toBe("line");
  });
});

describe("data-table alternatives (a11y parity, frontend ADD §9)", () => {
  it("treemap table has one row per node", () => {
    const table = toDataTableTreemap(treemapNodes);
    expect(table.rows).toHaveLength(treemapNodes.length);
    expect(table.headers).toContain("On-disk size");
  });
  it("volumes table has one row per volume", () => {
    expect(toDataTableVolumes(volumes).rows).toHaveLength(volumes.length);
  });
  it("top-N table has one row per item and is numbered", () => {
    const table = toDataTableTopN(topN);
    expect(table.rows).toHaveLength(topN.length);
    expect(table.rows[0][0]).toBe("1");
  });
  it("growth table has one row per point", () => {
    expect(toDataTableGrowth(growth).rows).toHaveLength(growth.points.length);
  });
});
