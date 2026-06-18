// Single ECharts option builder + a11y data-table projection (ADR-005, frontend ADD §8/§9).
//
// Every chart in Fathom is built here so ECharts shares ONE palette/theme, and every builder
// has a parallel `toDataTable*` that projects the same data into a table — charts are never
// the only way to read the numbers (WCAG 2.1 AA, frontend ADD §9). These are pure functions
// (no DOM), so they are unit-testable and carry no inline-script/eval (CSP, frontend ADD §12).

import type {
  GrowthSeriesOut,
  TopNItemOut,
  TreemapNodeOut,
  VolumeOut,
} from "../api/types";
import { basename, formatBytes, formatBytesExact, formatDate } from "../lib/format";

// The shared palette — kept in sync with tailwind.config.ts `fathom` tokens.
export const PALETTE = [
  "#4f9cff",
  "#e0a458",
  "#5fd0a0",
  "#e06c75",
  "#b48ead",
  "#56b6c2",
  "#d19a66",
  "#98c379",
] as const;

/** A generic ECharts option object (kept loose; ECharts validates at render). */
export type EChartsOption = Record<string, unknown>;

// Byte formatters for chart axes + tooltips so the chart itself reads in KB/MB/GB/TB — not a raw
// "1500000000000" — matching the data tables. These are plain functions (no eval/inline-script, so
// CSP-safe, frontend ADD §12). ECharts passes the axis value to an axisLabel/valueFormatter.
const bytesAxisLabel = { formatter: (v: number): string => formatBytes(v) };

/** A value (numeric) axis whose tick labels read as human sizes. */
const bytesValueAxis = { type: "value", axisLabel: bytesAxisLabel } as const;

/** An axis-triggered tooltip whose series values read as human sizes. */
const bytesAxisTooltip = {
  trigger: "axis",
  valueFormatter: (v: number): string => formatBytes(v),
} as const;

/** An item-triggered tooltip (treemap/pie/sunburst) that shows "<name>: <human size>". */
const bytesItemTooltip = {
  trigger: "item",
  formatter: (p: { name?: string; value?: number | number[] }): string => {
    const v = Array.isArray(p.value) ? p.value[0] : p.value;
    return `${p.name ?? ""}: ${formatBytes(Number(v) || 0)}`;
  },
} as const;

/** A rendered data-table alternative for a chart (headers + rows of cells). */
export interface DataTable {
  caption: string;
  headers: string[];
  rows: string[][];
}

// --- treemap ---------------------------------------------------------------------------

export function buildTreemapOption(nodes: TreemapNodeOut[]): EChartsOption {
  return {
    color: PALETTE,
    tooltip: bytesItemTooltip,
    series: [
      {
        type: "treemap",
        roam: false,
        nodeClick: "link",
        data: nodes.map((n) => ({
          name: n.name,
          value: n.subtree_size_on_disk,
          path: n.path,
        })),
        label: { show: true, formatter: "{b}" },
      },
    ],
  };
}

export function toDataTableTreemap(nodes: TreemapNodeOut[]): DataTable {
  return {
    caption: "Subtree sizes (on-disk)",
    headers: ["Name", "Type", "On-disk size", "Exact bytes", "Files"],
    rows: nodes.map((n) => [
      n.name,
      n.is_dir ? "directory" : "file",
      formatBytes(n.subtree_size_on_disk),
      formatBytesExact(n.subtree_size_on_disk),
      String(n.file_count),
    ]),
  };
}

// --- sunburst --------------------------------------------------------------------------

export function buildSunburstOption(nodes: TreemapNodeOut[]): EChartsOption {
  return {
    color: PALETTE,
    tooltip: bytesItemTooltip,
    series: [
      {
        type: "sunburst",
        radius: ["15%", "95%"],
        data: nodes.map((n) => ({ name: n.name, value: n.subtree_size_on_disk })),
        label: { show: true },
      },
    ],
  };
}

// --- volume usage bar/pie --------------------------------------------------------------

export function buildVolumeBarOption(volumes: VolumeOut[]): EChartsOption {
  return {
    color: PALETTE,
    tooltip: bytesAxisTooltip,
    legend: { data: ["Used", "Free"] },
    xAxis: { type: "category", data: volumes.map((v) => basename(v.mountpoint)) },
    yAxis: bytesValueAxis,
    series: [
      { name: "Used", type: "bar", stack: "cap", data: volumes.map((v) => v.used) },
      { name: "Free", type: "bar", stack: "cap", data: volumes.map((v) => v.free) },
    ],
  };
}

export function buildVolumePieOption(volume: VolumeOut): EChartsOption {
  return {
    color: PALETTE,
    tooltip: bytesItemTooltip,
    series: [
      {
        type: "pie",
        radius: "70%",
        data: [
          { name: "Used", value: volume.used },
          { name: "Free", value: volume.free },
        ],
      },
    ],
  };
}

export function toDataTableVolumes(volumes: VolumeOut[]): DataTable {
  return {
    caption: "Volume capacity",
    headers: ["Mount", "Total", "Used", "Free", "Used %"],
    rows: volumes.map((v) => [
      v.mountpoint,
      formatBytes(v.total),
      formatBytes(v.used),
      formatBytes(v.free),
      v.total > 0 ? `${((v.used / v.total) * 100).toFixed(1)}%` : "—",
    ]),
  };
}

// --- top-N bar ("biggest offenders") ---------------------------------------------------

export function buildTopNBarOption(items: TopNItemOut[]): EChartsOption {
  const ordered = [...items].reverse(); // horizontal bar: largest at the top
  return {
    color: PALETTE,
    tooltip: bytesAxisTooltip,
    grid: { left: 160 },
    xAxis: bytesValueAxis,
    yAxis: { type: "category", data: ordered.map((i) => i.name) },
    series: [{ type: "bar", data: ordered.map((i) => i.size_on_disk) }],
  };
}

export function toDataTableTopN(items: TopNItemOut[]): DataTable {
  return {
    caption: "Largest subtrees / files",
    headers: ["#", "Name", "Type", "On-disk", "Logical", "Files"],
    rows: items.map((i, idx) => [
      String(idx + 1),
      i.name,
      i.is_dir ? "directory" : "file",
      formatBytes(i.size_on_disk),
      formatBytes(i.size_logical),
      String(i.file_count),
    ]),
  };
}

// --- growth line -----------------------------------------------------------------------

export function buildGrowthLineOption(series: GrowthSeriesOut): EChartsOption {
  return {
    color: PALETTE,
    tooltip: bytesAxisTooltip,
    xAxis: { type: "time" },
    yAxis: bytesValueAxis,
    series: [
      {
        name: "On-disk",
        type: "line",
        showSymbol: false,
        data: series.points.map((p) => [p.ts, p.total_size_on_disk]),
      },
    ],
  };
}

export function toDataTableGrowth(series: GrowthSeriesOut): DataTable {
  return {
    caption: `Growth over time — ${series.path}`,
    headers: ["When", "On-disk", "Logical", "Files"],
    rows: series.points.map((p) => [
      formatDate(p.ts),
      formatBytes(p.total_size_on_disk),
      formatBytes(p.total_size_logical),
      String(p.file_count),
    ]),
  };
}
