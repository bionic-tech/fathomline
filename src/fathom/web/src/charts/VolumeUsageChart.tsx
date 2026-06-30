// Per-volume used/free bar + pie (frontend ADD §4 Dashboard).

import { ChartAdapter } from "./ChartAdapter";
import {
  buildVolumeBarOption,
  buildVolumePieOption,
  toDataTableVolumes,
} from "./chartOptions";
import type { VolumeOut } from "../api/types";

export interface VolumeUsageChartProps {
  volumes: VolumeOut[];
  variant?: "bar" | "pie";
  showTable?: boolean;
  /** Resolve a host id to its name, for the per-host grouping bands/labels (bar variant). */
  hostName?: (id: number) => string;
}

export function VolumeUsageChart({
  volumes,
  variant = "bar",
  showTable,
  hostName,
}: VolumeUsageChartProps): JSX.Element {
  const table = toDataTableVolumes(volumes);
  if (variant === "pie" && volumes.length > 0) {
    return (
      <ChartAdapter
        ariaLabel={`Capacity of ${volumes[0].mountpoint}`}
        option={buildVolumePieOption(volumes[0])}
        table={table}
        showTable={showTable}
      />
    );
  }
  return (
    <ChartAdapter
      ariaLabel="Volume used/free capacity, grouped by host"
      option={buildVolumeBarOption(volumes, { hostName })}
      table={table}
      showTable={showTable}
    />
  );
}
