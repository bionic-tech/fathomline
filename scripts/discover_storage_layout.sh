#!/usr/bin/env bash
# discover_storage_layout.sh
# Read-only discovery of disks, RAID, ZFS, and mounts to ground Fathom's scan
# scope (ADD 06 §2, ADD 05). Verifies AR-0007 inputs and any mdadm RAID5 arrays.
#
# SAFE: read-only. No mounts, no array changes, no writes except an optional report file.
#
# Run ON each host:   sudo ./discover_storage_layout.sh | tee fathom-storage-$(hostname).txt
# (sudo gives fuller lsblk/zpool/mdadm detail; runs without it too, with less.)

set -uo pipefail
SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

sec() { printf '\n============================================================\n## %s\n============================================================\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
run() { echo "\$ $*"; "$@" 2>&1 | sed 's/^/    /'; echo; }

sec "Host"
echo "host:   $(hostname)"
echo "date:   $(date -Is)"
echo "kernel: $(uname -r)"
echo "os:     $( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || echo unknown )"

sec "Block devices (lsblk)"
if have lsblk; then
  run lsblk -o NAME,KNAME,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL,TRAN,ROTA
else echo "lsblk not available"; fi

sec "Filesystem usage (df)"
have df && run df -hT -x tmpfs -x devtmpfs

sec "Mounts (non-pseudo)"
run sh -c "mount | grep -vE 'cgroup|proc|sysfs|tmpfs|devpts|securityfs|debugfs|tracefs|mqueue|bpf|fusectl|pstore|configfs|nsfs' | sort"

sec "Linux software RAID (mdadm / /proc/mdstat)"
if [ -r /proc/mdstat ]; then
  echo "--- /proc/mdstat ---"; cat /proc/mdstat | sed 's/^/    /'; echo
  if have mdadm; then
    for md in /dev/md*; do
      [ -b "$md" ] || continue
      echo "--- mdadm --detail $md ---"
      $SUDO mdadm --detail "$md" 2>&1 | sed 's/^/    /'; echo
    done
    # resync/rebuild state gates full-bit scans (ADD 16 / ADD 05)
    if grep -qiE 'recovery|resync|rebuild|check' /proc/mdstat; then
      echo ">> NOTE: an array is resyncing/checking — Fathom must BLOCK full-bit scans now (ADD 16)."
    else
      echo ">> arrays idle (no resync/rebuild in progress)."
    fi
  else echo "mdadm not installed"; fi
else
  echo "no /proc/mdstat (no Linux md RAID on this host)"
fi

sec "ZFS pools (zpool)"
if have zpool; then
  run $SUDO zpool list -o name,size,alloc,free,frag,cap,health,dedup
  run $SUDO zpool status
else echo "zpool not available (not a ZFS host)"; fi

sec "ZFS datasets (zfs list)"
if have zfs; then
  run $SUDO zfs list -o name,used,avail,refer,mountpoint,compression,recordsize,encryption
else echo "zfs not available"; fi

sec "TrueNAS middleware sanity (midclt) — informational"
if have midclt; then
  echo "midclt present — use the middleware API for any persistent change (not raw CLI)."
  run sh -c "midclt call system.info 2>/dev/null | head -c 400; echo"
else
  echo "midclt not found (expected only on TrueNAS SCALE)."
fi

sec "Approx file/inode counts per candidate mount  (cheap, df -i)"
if have df; then
  run df -i -x tmpfs -x devtmpfs
  echo "NOTE: df -i inode counts are a fast proxy for scan-scale (AR-0007). For a true"
  echo "50M-entry estimate, sum inodes across the data datasets/volumes Fathom will index."
fi

sec "DONE"
echo "Share the per-host outputs back; they ground scan scope, the RAID5 resync gate,"
echo "the ZFS dataset layout, and the AR-0007 nightly-scan feasibility estimate."
