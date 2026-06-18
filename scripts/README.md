# Operational probe scripts

Two **read-only** scripts that answer environment questions before deploying Fathom to a new
fleet. Neither changes Docker, ZFS, arrays, or system config; the only writes are a
self-cleaning temp fixture (probe 1) and an optional report file you redirect (probe 2).

## 1. `probe_truenas_preview_feasibility.sh`

Answers: can the **preview worker (gVisor/runsc)** and the **metadata root-reader
(`CAP_DAC_READ_SEARCH`)** run inside TrueNAS-managed Docker on this host, or must they relocate
to a standard Linux node?

```bash
# on the TrueNAS host
sudo ./probe_truenas_preview_feasibility.sh | tee fathom-preview-feasibility.txt
```

It prints a **VERDICT**:

- both `PASS` → preview + root-reader can stay on this host.
- otherwise → relocate the failing component to a general-purpose Linux node and re-run the
  probe there to confirm.

Expectation to verify, not assume: `runsc` is usually **not** available under TrueNAS-managed
Docker, which pushes the preview worker to a separate node. The probe confirms reality either
way.

## 2. `discover_storage_layout.sh`

Run on each host you plan to scan:

```bash
sudo ./discover_storage_layout.sh | tee fathom-storage-$(hostname).txt
```

Captures `lsblk`, mounts, `/proc/mdstat` + `mdadm --detail` (and whether a resync is in
progress — which must block full-bit scans), `zpool`/`zfs` layout, and `df -i` inode counts as
a fast proxy for total file-count scale. Use the outputs to (a) decide preview/root-reader
placement, (b) confirm the RAID-resync gate against your real arrays, and (c) sanity-check
scan-schedule feasibility before locking a cadence.

> House rule on TrueNAS systems: the middleware is authoritative — these scripts only *read*;
> any persistent change goes through `midclt`, not the raw CLI.

## Local development

`localdev/` stands up a complete single-machine Fathom (SQLite, seeded with real scans of local
directories) — see [localdev/README.md](localdev/README.md).
