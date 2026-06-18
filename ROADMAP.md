# Fathomline Roadmap

Direction, not promises — items move as reality intervenes. Issues/PRs that align with this
list have the smoothest path in. (Engine internals keep the `fathom` codename throughout.)

## Near term

- **Multi-host deployment guide** — a full, generic walkthrough of the production shape:
  mTLS proxy + CA provisioning + the built-in Deploy wizard (push-SSH and pull-enrolment),
  growing out of [deploy/quickstart/](deploy/quickstart/README.md).
- **Windows coverage, phase 1: read-only agent** — targeting **Windows Server 2016+ and
  Windows 10/11 (x64, NTFS)**; see [ADR-027](docs/decisions/ADR-027-native-windows-agent.md)
  for the full support matrix and phasing. *In progress:* the Windows path-safety rules
  (`fathom/security/winpaths.py` — long-path prefixes, ADS, reserved devices,
  case-insensitive containment) and the **native walker** (`fathom/backends/windows.py` —
  reparse skip-don't-follow, cloud placeholders never hydrated, synthetic ownership, W1
  full-bit refusal; registry-wired on Windows) and the **native enrolment path**
  (`fathom/core/deploy/winbundle.py` — a no-Docker zip bundle with a PowerShell installer that
  registers a daily Scheduled Task; platform-aware `enroll` + PowerShell bootstrap) have landed
  with adversarial tests and a `windows-latest` CI lane. Today, before the agent is packaged,
  Windows machines are scanned agentlessly over SMB. Still to come for W1: frozen-exe
  (`fathomline-agent.exe`) packaging, `SeBackupPrivilege` backup-semantics reads, and end-to-end
  staging/push validation on real Windows. The catalogue identity model already works on NTFS
  (file IDs / volume serials).
- **Screenshots** — README screenshots from the seeded localdev estate. *(The published API
  reference is done: a committed, drift-checked OpenAPI spec at [docs/api/](docs/api/README.md)
  with a Redoc viewer.)*

## Mid term

- **Cloud remotes via rclone** ([ADR-028](docs/decisions/ADR-028-rclone-cloud-backend.md)) —
  *phases 1 + 2a built*: a metadata-only rclone backend puts any rclone remote (Google Drive, S3,
  Dropbox, OneDrive, …) in the estate view with no file downloads, and `lsjson --hash` captures
  the provider's content hash so `provider_dedup.find_provider_hash_duplicates` surfaces
  **cross-cloud duplicates at zero egress** (report-only — never drives remediation, which keys on
  the content-verified BLAKE3 hash). Phase 2b (deferred): cloud-vs-local matching (recompute the
  provider's algorithm on the local side for size-collision candidates) + wiring the grouping to a
  read API route and the Duplicates UI.
- **Reflink / block-clone reclaim** — a new remediation action that deduplicates *without
  deleting anything*: ZFS 2.2+ block cloning and BTRFS/XFS reflinks store the bytes once
  while every path keeps working. Zero-data-loss space reclaim, riding the existing signed +
  audited write path (same gates: default-OFF, step-up MFA, blast caps).
- **Windows coverage, phase 2** — full-content hashing via backup-semantics opens, and
  incremental scans driven by the NTFS **USN change journal** (the Windows-native change feed).
- **Durable nonce store** — replay protection for the signed-job channel that survives agent
  restarts and supports clustered agents (today's in-memory store suits single-agent hosts).
- **Dynamic catalogue partitions** — create per-host/per-volume PostgreSQL partitions at
  ingest time (the migration currently provisions the DEFAULT chain).

## Exploring

- **Windows write path** — remediation on Windows requires re-building the TOCTOU-safe
  executor on Win32 handle semantics and will only ship after its own adversarial security
  review. Read-only Windows comes first, deliberately.
- **Perceptual duplicate matching** — near-duplicate photos/music (the dupeGuru/czkawka
  feature), likely as an opt-in analysis pass; exact-content BLAKE3 remains the only basis
  for any reclaim action.
- **Model-B development** — moving day-to-day development into the public repository once
  the project finds its community.
