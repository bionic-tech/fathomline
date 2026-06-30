# Changelog

All notable changes to **Fathomline** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/). Until the first
tagged release the public API and configuration may still change.

## [Unreleased]

## [0.2.0] - 2026-06-30

### Added

- **Scan Now** — on-demand metadata or full-content scans of a host's volumes, dispatched to the
  owning agent over the signed-job channel (single-use, time-boxed, signature + nonce verified),
  capability-gated and non-destructive; plus a read-only "scan-only" listener mode so a host can
  serve Scan Now without arming the write path.
- **Scan coordinator** — an opt-in core-side lease that serialises heavy scans so concurrent
  nightly runs can't saturate the database.
- **Notification Center** — an in-app bell plus pluggable outbound channels, fed by a proactive
  watch worker: volume-capacity and days-to-full forecasts, and a stale-scan alert that flags a
  host whose scheduled scan has silently stopped completing.
- **AI concierge** — natural-language questions over the catalogue (classify → query → narrate via
  a pluggable local or remote model) and optional semantic path search (pgvector embeddings).
- **Distributed sandboxed previews** — file previews rendered in a gVisor-isolated worker, so the
  core never opens untrusted bytes.
- **Suitability assessment + first-run onboarding** wizard.
- **Native Windows agent — full-content hashing (phase W2)**: reads local files but never hydrates
  cloud placeholders (no OneDrive/recall hangs), and **drive-type tags** in the UI (network / USB /
  NVMe / SATA / cloud) so a mount's connection and medium are visible when choosing scan scope.
- **Provider-aware inference settings** with a cohesive, cross-feature model selection.

### Changed

- Agents screen redesigned around per-host cards; the Deploy wizard derives the in-container agent
  path from the picked host path; volumes carry their connection/medium as a visible tag.

### Security

- MFA TOTP secrets are now encrypted at rest via the runtime settings store (backward-compatible).

## [0.1.0] - 2026-06-18

The initial public release: a multi-host, multi-filesystem disk-estate analyzer. Lightweight
read-only agents scan each host and push file metadata over mutually-authenticated TLS into a
central catalogue; a React UI gives treemaps, estate-wide search, growth trends, duplicate
detection, and a strictly opt-in, audited cleanup path.

### Added

- **Agents & scanning** — read-only per-host agent (container + native Windows build) with
  metadata and full-content scan modes, resumable SQLite staging, idempotent re-runs, and
  self-throttling (I/O class, concurrency budget, load/IO-wait auto-pause).
- **Storage backends** — a `StorageBackend` protocol with a registry; POSIX, ZFS (TrueNAS),
  NTFS/exFAT, native Windows, SFTP, SMB, and rclone backends. Device-topology detection
  (transport bus, RAID role) drives both UI labelling and throttle safety.
- **Remote & cloud targets** — agents can scan cloud remotes (rclone) and SMB/SFTP shares as
  their own volumes; credentials are secret references resolved at runtime, never inline.
- **Central catalogue** — partitioned PostgreSQL store of every host/volume/path with logical
  and on-disk sizes; immutable per-run snapshots for growth and churn over time; bounded-memory
  subtree rollups.
- **Ingest boundary** — mTLS agent authentication by client-cert fingerprint, a proxy-secret
  check so the ingest path can't be reached directly, server-side re-vetting of every
  agent-supplied path, and synchronous post-drain snapshot finalization.
- **Duplicate detection** — content-based dedup (size → partial → full BLAKE3 hash) with
  reclaimable-byte reporting and keeper suggestions; plus zero-egress cross-cloud duplicate
  reporting via provider hashes (report-only — never a driver of remediation).
- **Read API & UI** — a React + TypeScript SPA with treemap/sunburst/bar/pie/tree views,
  estate-wide search, growth series, a churn feed, the duplicates surface, and a fleet/agents
  view with per-host last-run health.
- **Gated remediation (opt-in)** — operator-approved, dry-run-validated plans dispatched as
  signed action jobs to the owning agent; reversible move/rename actions; off by default with
  step-up auth required to execute.
- **Content-aware Organize** — read-only reorganisation suggestions from a pluggable inference
  provider (local or remote), with egress controlled by configuration.
- **Cross-host reconciliation** — divergence detection between two trees on different hosts.
- **Agent deployment subsystem** — push (SSH) and pull (enrolment-token) provisioning of new
  agents, including remote/cloud scan targets, via a Deploy wizard; off by default.
- **Security & governance** — deny-by-default scoped RBAC that fails closed, a hash-chained
  tamper-evident audit log, secrets-by-reference, and a read/write privilege split enforced at
  the OS-user, route, and credential level.
- **Observability** — scan-run reporting and per-host last-run outcome (entries seen, scopes
  failed) surfaced in the API and UI.

### Security

- The remediation (write) path ships disabled and requires explicit enablement plus step-up
  MFA; dry-run validation precedes execution and there is no auto-delete.
- Full-content hashing is refused over remote transports (SMB/SFTP/rclone); content is only
  ever hashed on the host where the data physically lives.

[Unreleased]: https://github.com/bionic-tech/fathomline/compare/v0.2.0...main
[0.2.0]: https://github.com/bionic-tech/fathomline/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bionic-tech/fathomline/releases/tag/v0.1.0
