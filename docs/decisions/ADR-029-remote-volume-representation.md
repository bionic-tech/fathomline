# ADR-029 — Remote/cloud volume representation (make remote ingest work end-to-end)

**Status:** Accepted (built) · **Date:** 2026-06-11 · **Deciders:** project owner
**Related:** ADR-004 (storage backends), ADR-028 (rclone), ADD 09 (catalogue), AR-0012 (server-side
path re-vetting)

## Context

Two latent bugs were found while wiring the localdev cloud path: **no remote backend (SFTP, SMB, or
rclone) could push to the catalogue end-to-end.** They were only ever unit-tested in isolation with
fake transports, never driven through real ingest.

1. **`scheme://` mountpoints fail the catalogue's path contract.** The catalogue keys ingest and
   every read off `Volume.mountpoint`: it must be POSIX-absolute (ingest's AR-0012 re-vetting runs
   `validate_config_path(mountpoint)`), and every entry path must be string-prefixed by it
   (`_depth_within`, `path LIKE mountpoint%`). A remote `mount_key` like `rclone://gdrive/Backups`
   is neither, so ingest threw and reads returned nothing.

2. **Remote entries collide on the identity key.** The entry identity is
   `(host_id, volume_id, dev, inode)`. Remote entries had `inode=0` (no real inode), so **every**
   file in a remote volume shared `(…, 0, 0)` and clobbered the previous one on upsert — only one
   entry per volume survived (ingest reported "3 received" while one row persisted).

## Decision

Make remote volumes **conform to the existing contract** rather than change the audited
ingest/read logic.

### Representation (Option C — chosen by the owner)

- `Volume.mountpoint` stores a **synthetic POSIX-absolute path** the entries anchor under:
  `RemoteBackendConfig.catalogue_mount` → `/rclone/<host>/<subpath>`, `/sftp/<host><path>`,
  `/smb/<host>/<share><path>`. Ingest's AR-0012 vetting, depth, containment, and the tree drill all
  "just work" — **no change to the vetting or read code** (remote backends now meet the same bar as
  POSIX volumes).
- The pretty `scheme://…` (`mount_key`) rides along as a new nullable **`Volume.display_name`** the
  UI shows (volume picker etc.); navigation/drill still uses the synthetic `mountpoint`. NULL for
  local volumes. Migration `f1b6c2a9d34e`.
- `mount_key` remains the scan-root id the runner passes and the backend `supports()` matches.

### Identity — `synthetic_inode(path)`

Remote/cloud entries get a **stable, path-derived 64-bit synthetic inode** (`backends.remote.
synthetic_inode`, BLAKE2b of the catalogue path, masked to a positive int64). It is stable across
scans (so re-scans upsert, not duplicate) and unique per path (so entries don't collide on
`(host, volume, dev, inode)`). `dev` stays 0. This is the same trick rclone's own VFS uses to
invent inodes.

## Consequences

- **SFTP, SMB and rclone now ingest and browse end-to-end** — covered by per-protocol end-to-end
  ingest tests (`tests/api/test_remote_ingest.py`) plus the synthetic-inode unit test.
- The AR-0012 server-side re-vetting is **unchanged** — its security properties are preserved;
  remote backends simply produce conforming mountpoints/paths. (This is why Option C was preferred
  over a `path_root` field that would have modified the vetting/read path.)
- Collision risk of the synthetic inode is negligible at homelab estate scale (64-bit, ≤ tens of
  millions of files); a collision would clobber two paths' catalogue rows. Accepted for v1 and
  documented; a backend that exposes a real stable object id (some rclone remotes) could use it in
  a later refinement.
- No existing-data migration concern: there were no functioning remote volumes catalogued before
  this (they hit the bug). Local volumes are entirely unaffected (`display_name` NULL, real inodes).
- Provider-hash cross-cloud dedup (ADR-028) is unaffected — it groups on `(algo, hash, size)`,
  independent of inode.
