// The single ECharts React adapter (ADR-005, frontend ADD §8/§9).
//
// All chart types go through this one component so they share the palette/theme and so EVERY
// chart is paired with its DataTable alternative (frontend ADD §9). ECharts is imported as the
// tree-shaken core + only the chart/component modules used, keeping the bundle small and the
// strict CSP intact (no eval; frontend ADD §12). The adapter is a thin imperative wrapper: it
// instantiates the ECharts instance on mount, re-applies the option on change, and disposes on
// unmount.

import * as echarts from "echarts/core";
import {
  BarChart,
  LineChart,
  PieChart,
  SunburstChart,
  TreemapChart,
} from "echarts/charts";
import {
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import { DataTable } from "./DataTable";
import type { DataTable as DataTableModel, EChartsOption } from "./chartOptions";

echarts.use([
  TreemapChart,
  SunburstChart,
  BarChart,
  PieChart,
  LineChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  CanvasRenderer,
]);

export interface ChartAdapterProps {
  /** The ECharts option object (built by chartOptions.ts builders). */
  option: EChartsOption;
  /** The matching a11y data-table projection of the same data (frontend ADD §9). */
  table: DataTableModel;
  /** Accessible name for the chart figure. */
  ariaLabel: string;
  height?: number;
  /** Optional click handler (path is carried on treemap node data for drill-down). */
  onSelect?: (path: string) => void;
  /** Show the data table visually (otherwise it stays in the a11y tree only). */
  showTable?: boolean;
}

export function ChartAdapter({
  option,
  table,
  ariaLabel,
  height = 320,
  onSelect,
  showTable = false,
}: ChartAdapterProps): JSX.Element {
  const ref = useRef<HTMLDivElement | null>(null);
  const instanceRef = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (ref.current === null) return undefined;
    const chart = echarts.init(ref.current);
    instanceRef.current = chart;
    if (onSelect) {
      chart.on("click", (params) => {
        // Treemap/sunburst nodes carry the materialised path on their data object.
        const data = (params as { data?: unknown }).data;
        if (data !== null && typeof data === "object" && "path" in data) {
          const path = (data as { path?: unknown }).path;
          if (typeof path === "string") onSelect(path);
        }
      });
    }
    const onResize = (): void => chart.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
      instanceRef.current = null;
    };
    // onSelect is stable per render-tree usage; re-init only on mount/unmount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    instanceRef.current?.setOption(option, true);
  }, [option]);

  return (
    <figure role="figure" aria-label={ariaLabel}>
      <div ref={ref} style={{ width: "100%", height }} role="img" aria-label={ariaLabel} />
      <DataTable table={table} visible={showTable} />
    </figure>
  );
}
