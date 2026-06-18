// Estate treemap (ECharts) with lazy drill-down (frontend ADD §4/§10).

import { ChartAdapter } from "./ChartAdapter";
import { buildTreemapOption, toDataTableTreemap } from "./chartOptions";
import type { TreemapNodeOut } from "../api/types";

export interface TreemapProps {
  nodes: TreemapNodeOut[];
  onDrill?: (path: string) => void;
  showTable?: boolean;
}

export function Treemap({ nodes, onDrill, showTable }: TreemapProps): JSX.Element {
  return (
    <ChartAdapter
      ariaLabel="Estate treemap by on-disk size"
      option={buildTreemapOption(nodes)}
      table={toDataTableTreemap(nodes)}
      onSelect={onDrill}
      showTable={showTable}
    />
  );
}
