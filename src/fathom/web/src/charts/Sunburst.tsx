// Estate sunburst (ECharts) — same capped node set as the treemap (frontend ADD §4/§10).

import { ChartAdapter } from "./ChartAdapter";
import { buildSunburstOption, toDataTableTreemap } from "./chartOptions";
import type { TreemapNodeOut } from "../api/types";

export interface SunburstProps {
  nodes: TreemapNodeOut[];
  onDrill?: (path: string) => void;
  showTable?: boolean;
}

export function Sunburst({ nodes, onDrill, showTable }: SunburstProps): JSX.Element {
  return (
    <ChartAdapter
      ariaLabel="Estate sunburst by on-disk size"
      option={buildSunburstOption(nodes)}
      table={toDataTableTreemap(nodes)}
      onSelect={onDrill}
      showTable={showTable}
    />
  );
}
