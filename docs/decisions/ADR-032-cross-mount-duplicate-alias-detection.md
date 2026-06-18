# ADR-032 — Cross-mount duplicate alias detection (NFS/SMB false positives)

**Status:** Accepted  **Date:** 2026-06-14  **Deciders:** project owner

## Context

Dedup groups byte-identical files by their stored `full_hash` across the whole estate (ADR-011,
fullbit-dedup; only the hash crosses the wire — ADR-002). On a real fleet this surfaces a
**false-positive class**: the *same physical file* is full-hashed twice —

- once **natively** on the host that owns the bytes (e.g. node-1 full-bit-scanning its
  `raid_set_1` ext4 export), and
- once **through a network mount** on another host that mounts that export (e.g. nas-1 scanning
  `/scan/ncdata`, an NFS mount of node-1's export, as an ordinary local POSIX path).

Both rows carry the identical `full_hash`, so they group as a "duplicate" and inflate
`reclaimable_bytes` — but they are **one** physical file seen through two paths. Deleting the
mounted view frees nothing (and could be presented as if it would). This is distinct from a
genuine cross-host duplicate (the same content stored on two *different* physical backings, which
*is* reclaimable). Note remote *backends* (SMB/SFTP/rclone — ADR-029) never full-hash (full-bit is
refused over them), so this only arises from a network filesystem mounted **locally** and scanned
by the POSIX backend.

## Decision

Detect a network-mount member by the catalogue's existing `Volume.fs_type` (the metadata scan
already records it via `/proc/mounts`): a member whose `fs_type` is a network filesystem
(`nfs`/`nfs4`/`cifs`/`smb*`/`sshfs`/`9p`/`ceph`/`glusterfs`/`fuse.rclone` — `is_network_fs`) is a
**cross-mount alias**, not a reclaimable copy. The dedup builder then:

1. flags the member `dup_member.is_mount_alias = true`;
2. computes `reclaimable_bytes` from **native copies only** (`size * (native_copies - 1)`), so an
   alias frees nothing and an all-alias group reclaims zero;
3. ranks the **non-binding keeper among native copies only** — an alias is never the keeper and a
   removal suggestion can never target a real file because of a remote view.

The read API exposes `is_mount_alias` per member and the Duplicates UI highlights it ("mount
alias") and de-emphasises the row, so the false positive is **surfaced, not hidden**.

## Consequences

- **Positive:** the reclaimable headline is honest on a fleet with NFS/SMB exports; operators see
  *why* a cross-host pair is not reclaimable instead of being misled into a no-op deletion.
- **Negative:** detection is by `fs_type` heuristic, not by resolving the exact backing host of a
  mount (which we do not capture). It is intentionally conservative — anything on a network mount
  is treated as a non-reclaimable alias, which can under-count reclaimable space if a network-mount
  volume genuinely held the only copy (an extreme edge); never the reverse (never over-counts).
- **Migration:** `dup_member.is_mount_alias` (default false), rebuilt on every full-bit finalize.

## Cross-references

ADR-002 (only the hash crosses the wire — the property that makes cross-host dedup possible and
is also the blind spot this addresses), ADR-011 (remediation/keeper), ADR-015 (`(host,volume,dev,
inode)` identity), ADR-029 (remote backends, which are metadata-only and so never trigger this).
