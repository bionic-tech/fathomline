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
}

export function VolumeUsageChart({
  volumes,
  variant = "bar",
  showTable,
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
      ariaLabel="Volume used/free capacity"
      option={buildVolumeBarOption(volumes)}
      table={table}
      showTable={showTable}
    />
  );
}
