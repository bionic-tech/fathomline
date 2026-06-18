// Growth-over-time line (ECharts), fed by the server-downsampled series (frontend ADD §10).

import { ChartAdapter } from "./ChartAdapter";
import { buildGrowthLineOption, toDataTableGrowth } from "./chartOptions";
import type { GrowthSeriesOut } from "../api/types";

export interface GrowthSeriesProps {
  series: GrowthSeriesOut;
  showTable?: boolean;
}

export function GrowthSeries({ series, showTable }: GrowthSeriesProps): JSX.Element {
  if (series.points.length === 0) {
    return <p role="status">Insufficient history to plot growth yet.</p>;
  }
  return (
    <ChartAdapter
      ariaLabel={`Growth over time for ${series.path}`}
      option={buildGrowthLineOption(series)}
      table={toDataTableGrowth(series)}
      showTable={showTable}
    />
  );
}
