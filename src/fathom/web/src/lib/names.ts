// Resolve numeric host_id / volume_id to human names for display. Cross-host views (Duplicates,
// Search, Reconcile) carry only the IDs; showing "nas-1 · tank" instead of "1 / 1" is the
// difference between knowing where data lives and not. Falls back gracefully if the agents/volumes
// queries are unavailable to the principal (it degrades to "host N" / "vol N", never throws).

import { useAgents, useVolumes } from "../api/queries";

export interface NameResolver {
  hostName: (hostId: number) => string;
  /** Short volume label: the configured display_name, else the mountpoint without the /scan prefix. */
  volumeLabel: (volumeId: number) => string;
}

export function useNames(): NameResolver {
  const agents = useAgents();
  const volumes = useVolumes();
  const hostName = (hostId: number): string =>
    agents.data?.find((h) => h.id === hostId)?.name ?? `host ${hostId}`;
  const volumeLabel = (volumeId: number): string => {
    const v = volumes.data?.find((vol) => vol.id === volumeId);
    if (!v) return `vol ${volumeId}`;
    const short = v.mountpoint.replace(/^\/scan(?=\/)/, "").replace(/^\//, "");
    return v.display_name ?? (short || v.mountpoint);
  };
  return { hostName, volumeLabel };
}
