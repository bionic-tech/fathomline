// driveType.ts — classify a volume's connection/medium from its fs_type + transport into a short
// human tag + a colour category, so the UI can SHOW "is this local, network, USB, cloud…" at a
// glance. Motivated by a real confusion: a scope looked local but the path was a network/stub
// mount and nothing surfaced it. fs_type is the authoritative signal for network filesystems
// (nfs/cifs/sshfs/rclone, which a path alone never reveals); transport (nvme/usb/sata, from the
// backend classifier) refines local block devices. Pure mapping, no I/O — unit-tested.

export type DriveCategory = "local" | "network" | "removable" | "cloud" | "unknown";

export interface DriveType {
  tag: string; // short badge label: "NFS", "USB", "NVMe", "ZFS"…
  category: DriveCategory; // drives the badge colour (network/USB stand out)
  title: string; // tooltip: the full human description
}

/** Classify a volume by its filesystem type + bus transport. fs_type wins for network/cloud. */
export function driveType(v: { fs_type?: string | null; transport?: string | null }): DriveType {
  const fs = (v.fs_type ?? "").toLowerCase().trim();
  const tr = (v.transport ?? "").toLowerCase().trim();

  // --- Network / cloud filesystems: the most important to surface (the path never tells you). ---
  if (fs === "nfs" || fs === "nfs4") return net("NFS", "Network share — NFS");
  if (fs === "cifs" || fs === "smb" || fs === "smb3" || fs === "smbfs")
    return net("SMB", "Network share — SMB/CIFS");
  if (fs.includes("sshfs")) return net("SSH", "Remote over SSH — sshfs/SFTP");
  if (fs.includes("rclone"))
    return { tag: "rclone", category: "cloud", title: "Cloud remote — rclone" };
  if (fs === "9p" || fs.includes("9p"))
    return net("9p", "Virtual passthrough — 9p (VM / WSL2 / Docker-Desktop share)");
  if (fs === "drvfs") return net("drvfs", "Windows drive via WSL — drvfs");

  // --- Local block devices: the backend transport classifier refines the medium. ---
  if (tr === "usb") return { tag: "USB", category: "removable", title: "USB-attached drive" };
  if (tr === "nvme") return { tag: "NVMe", category: "local", title: "NVMe SSD (local)" };
  if (tr === "sata") return { tag: "SATA", category: "local", title: "SATA-attached drive (local)" };

  // --- Otherwise classify by local filesystem type. ---
  if (fs === "zfs") return { tag: "ZFS", category: "local", title: "Local ZFS dataset" };
  if (fs === "btrfs") return { tag: "Btrfs", category: "local", title: "Local Btrfs volume" };
  if (fs === "ext4" || fs === "ext3" || fs === "ext2" || fs === "xfs")
    return { tag: fs.toUpperCase(), category: "local", title: `Local disk — ${fs}` };
  if (fs === "ntfs" || fs === "exfat" || fs === "vfat" || fs === "fat32" || fs === "msdos")
    return {
      tag: fs === "vfat" ? "FAT" : fs.toUpperCase(),
      category: "removable",
      title: `${fs.toUpperCase()} volume — often a USB / external drive`,
    };

  if (fs && fs !== "unknown") return { tag: fs, category: "local", title: `Filesystem: ${fs}` };
  return { tag: "?", category: "unknown", title: "Unknown drive type — not yet classified" };
}

function net(tag: string, title: string): DriveType {
  return { tag, category: "network", title };
}

/** Badge class for a drive category (colour-coded so a network / removable drive is obvious). */
export function driveBadgeClass(category: DriveCategory): string {
  return `fathom-badge-drive-${category}`;
}
