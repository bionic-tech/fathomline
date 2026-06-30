import type { JSX } from "react";

import { driveBadgeClass, driveType } from "../../lib/driveType";

/** A small colour-coded tag showing a volume's connection/medium (NFS, USB, NVMe, ZFS, …), so the
 * drive type is visible at a glance when picking or reviewing scan scope. Reads only fs_type +
 * transport (both already on VolumeOut); see driveType.ts for the classification. */
export function DriveBadge({
  fs_type,
  transport,
  className = "",
}: {
  fs_type?: string | null;
  transport?: string | null;
  className?: string;
}): JSX.Element {
  const dt = driveType({ fs_type, transport });
  return (
    <span
      className={`fathom-badge ${driveBadgeClass(dt.category)} ${className}`}
      title={dt.title}
      aria-label={`drive type: ${dt.title}`}
    >
      {dt.tag}
    </span>
  );
}
