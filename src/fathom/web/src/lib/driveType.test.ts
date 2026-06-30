import { describe, expect, it } from "vitest";

import { driveBadgeClass, driveType } from "./driveType";

describe("driveType", () => {
  it("flags network filesystems by fs_type (the path never reveals them)", () => {
    expect(driveType({ fs_type: "nfs4" })).toMatchObject({ tag: "NFS", category: "network" });
    expect(driveType({ fs_type: "cifs" })).toMatchObject({ tag: "SMB", category: "network" });
    expect(driveType({ fs_type: "fuse.sshfs" })).toMatchObject({ tag: "SSH", category: "network" });
    expect(driveType({ fs_type: "9p" })).toMatchObject({ tag: "9p", category: "network" });
  });

  it("flags rclone remotes as cloud", () => {
    expect(driveType({ fs_type: "fuse.rclone" })).toMatchObject({ tag: "rclone", category: "cloud" });
  });

  it("uses transport to distinguish local media (USB / NVMe / SATA)", () => {
    expect(driveType({ fs_type: "ext4", transport: "usb" })).toMatchObject({
      tag: "USB",
      category: "removable",
    });
    expect(driveType({ fs_type: "ext4", transport: "nvme" })).toMatchObject({
      tag: "NVMe",
      category: "local",
    });
    expect(driveType({ fs_type: "ext4", transport: "sata" })).toMatchObject({
      tag: "SATA",
      category: "local",
    });
  });

  it("falls back to the local filesystem type when transport is unknown", () => {
    expect(driveType({ fs_type: "zfs", transport: "unknown" })).toMatchObject({
      tag: "ZFS",
      category: "local",
    });
    expect(driveType({ fs_type: "xfs", transport: "unknown" })).toMatchObject({
      tag: "XFS",
      category: "local",
    });
    // FAT/NTFS/exFAT lean removable (commonly external) even without a transport hint.
    expect(driveType({ fs_type: "ntfs" })).toMatchObject({ tag: "NTFS", category: "removable" });
  });

  it("network fs_type wins even if a transport is also set", () => {
    expect(driveType({ fs_type: "nfs", transport: "nvme" }).category).toBe("network");
  });

  it("degrades to unknown when nothing is classifiable", () => {
    expect(driveType({ fs_type: "unknown", transport: "unknown" })).toMatchObject({
      category: "unknown",
    });
    expect(driveType({})).toMatchObject({ category: "unknown" });
  });

  it("maps each category to its own badge class", () => {
    expect(driveBadgeClass("network")).toBe("fathom-badge-drive-network");
    expect(driveBadgeClass("removable")).toBe("fathom-badge-drive-removable");
  });
});
