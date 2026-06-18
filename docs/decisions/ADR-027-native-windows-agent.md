# ADR-027 — Native Windows agent (phased; read-only first)

**Status:** Accepted (roadmap-committed) · **Date:** 2026-06-11 · **Deciders:** project owner
**Related:** ADR-013 (agent packaging), ADR-015 (device id in entry identity), ADR-016
(topologies), ADR-006 (incremental change feeds), ROADMAP "Windows coverage"

## Context

Windows machines are currently covered only agentlessly, as SMB `remote_targets` walked by a
nearby POSIX agent: metadata-only (full-content hashing is refused over remote transports by
design), no incremental feeds, network-bound throughput. Mixed homelab estates routinely
include Windows boxes, so native coverage is a top adoption ask.

An audit of the agent code shows the port is concentrated, not pervasive: the walker
(`os.scandir`/`lstat`), SQLite staging, the mTLS push transport, BLAKE3 hashing and config are
already portable. The genuinely POSIX surface is the `O_NOFOLLOW`/parent-fd discipline
(centred on the remediation executor), the fanotify change feed, the cap-only-root container
privilege model, and POSIX-rooted path validation.

## Decision

Ship a **native Windows agent in phases, read-only first**, with this support matrix:

| Target | Status |
|---|---|
| **Windows Server 2016, 2019, 2022+** (NT 10.0) | supported, x64 |
| **Windows 10** (1607+) and **Windows 11** | supported, x64 |
| Filesystem | **NTFS** primary; FAT/exFAT volumes best-effort (no stable file ids — see ADR-015 fallback) |
| ReFS | **not claimed yet** — ReFS uses 128-bit file ids; our identity column and CPython's `st_ino` are 64-bit. Requires explicit handling before support is stated. |
| Older (Server 2012R2, Win 8.x, 32-bit, ARM64) | out of scope for v1 |

The floor is Server 2016 / Windows 10 1607 (the same NT 10.0 kernel line): it is the oldest
target with reliable long-path behaviour, TLS 1.2 by default, and current CPython support —
and the agent ships as a **frozen executable** (no Python install on the target), running as a
Windows **service**.

### Phase W1 — read-only metadata agent

- **Walk:** `os.scandir` as today; **reparse points are skip-don't-follow** (symlinks,
  junctions, mount points), and **cloud placeholders are never hydrated** — entries carrying
  `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` / `OFFLINE` (OneDrive et al.) are catalogued from
  metadata only.
- **Identity:** unchanged catalogue model — CPython on Windows populates `st_ino` with the
  NTFS file reference number and `st_dev` with the volume serial, mapping directly onto
  `(host_id, volume_id, dev, inode)` (ADR-015).
- **Paths:** `security/paths.py` grows Windows rules — drive-letter/UNC absolutes, `\\?\`
  long-path normalisation, case-insensitive containment checks, reserved device names
  (`CON`, `NUL`, …), and alternate data streams (`file:stream`) treated as part of the name,
  never traversed.
- **Privilege:** the cap-only-root model maps to a service account holding
  **`SeBackupPrivilege`** with `FILE_FLAG_BACKUP_SEMANTICS` opens — the established backup-
  agent pattern for read-everything without ACL edits. `write_enabled: false` semantics are
  identical.
- **Enrolment:** the pull-bootstrap command gets a **PowerShell variant**
  (`windows_powershell_bootstrap`); W1 ships pull enrolment (push-deploy over SSH/WinRM is
  explicitly later). The enrollment request carries `platform: linux|windows`, recorded on the
  grant so redeem renders the matching bundle.
- **CI:** a `windows-latest` lane runs the portable suite plus new Windows path/walk tests;
  POSIX-only tests gain platform markers.

### Bundle shape & install model (resolved during W1 build, 2026-06-11)

- **Native, not Docker.** The Windows bundle (`fathom/core/deploy/winbundle.py`) is a **zip**
  (`agent.config.yaml`, `certs\`, `run-scan.ps1`, `install-agent.ps1`, `README.txt`) — not a
  `docker-compose.yml`. Zip (PowerShell `Expand-Archive`) rather than tar.gz because the floor,
  **Server 2016, has no `tar.exe`**.
- **Scheduled Task, not a service.** The W1 scan agent is a one-shot pass (mirrors the Linux
  cron `run-scan.sh` / compose `restart: "no"`), so the installer registers a **daily Scheduled
  Task** running `run-scan.ps1` as `SYSTEM` at highest privileges. A long-running Windows
  **service** is only needed for the later always-on *listen* daemon (the write path), which W1
  does not ship — so "service wrapper" in the matrix above is, for the W1 scan agent,
  realised as a scheduled task. The frozen `fathomline-agent.exe` is preferred by the launcher
  when present, with a `py -3 -m fathom.agent` fallback (the exe packaging is a follow-up).
- **IP-based ingest, no hosts-file mutation.** The Linux container maps `proxy` via compose
  `extra_hosts`; the native Windows agent instead dials the proxy **by IP** (`windows_ingest_url`
  rewrites only the host of the configured ingest URL). This avoids a system-wide
  `C:\Windows\System32\drivers\etc\hosts` side effect; its one requirement — the proxy server
  cert SAN must include the proxy IP — is already satisfied by the multi-host guide's `server.ext`.
- **Injection discipline.** `host_id`/`proxy_host_ip`/`start_time` are charset-validated before
  reaching any generated `.ps1`; Windows scan paths pass `winpaths` validation and are emitted as
  **single-quoted YAML scalars** (backslashes literal, `'`→`''`) so a path can neither break YAML
  nor inject a directive.

### Adversarial review outcomes (2026-06-11)

An internal adversarial review confirmed 10 findings (a further 8 candidates were refuted).
Addressed in the same session:

- **Install-dir ACL hardening (was HIGH — the load-bearing fix).** `%PROGRAMDATA%` lets standard
  users create subdirectories, so the install dir must not be left at inherited ACLs: a non-admin
  could pre-create `C:\ProgramData\Fathomline` (retaining write access) and later have the SYSTEM
  scheduled task execute an attacker-replaced `run-scan.ps1` — local privilege escalation — or read
  the agent private key at rest. The bootstrap now (a) **refuses** a pre-existing dir not owned by
  SYSTEM/Administrators (squat detection, fail-closed), and (b) takes ownership + strips inherited
  ACEs + grants only SYSTEM/Administrators, both before extraction and after. This is the Windows
  analogue of the Linux path's `chmod 0600` + `tar --no-overwrite-dir`.
- **Cleartext-transport warning (was HIGH).** The bundle fetch carries the agent private key + the
  one-time token over `core_base_url`; the enroll route now logs a loud warning when that URL is
  plain http (T-2). Enforcing https outright is an estate-wide policy change affecting the existing
  (owner-accepted-as-deferred) Linux path and localhost dev, so it stays a documented recommendation
  rather than a unilateral hard-fail.
- **`ingest_url` control-char rejection (LOW)** added for parity with `host_id`; **doc fixes** to the
  token-quote comment and the redeem-route docstring.

### First real-hardware bring-up (2026-06-12)

Running the PyInstaller-frozen W1 exe against a real Windows 11 desktop (vs. CI's
`windows-latest`, which never pushes to a live proxy) surfaced three platform truths that the
Linux-developed code had silently assumed away. All three are fixed and regression-tested:

- **NTFS file IDs are unsigned 64-bit; SQLite integers are signed 64-bit.** `st_ino` carries the
  NTFS file reference number, which routinely exceeds 2⁶³ and overflowed the agent's SQLite
  staging store mid-scan (`OverflowError: Python int too large to convert to SQLite INTEGER`).
  Fixed by reinterpreting `st_ino`/`st_dev` as signed-64 (`_to_signed64`, bijective on
  `[0, 2⁶⁴)`) at the `FsEntry` boundary — the catalogue identity stays stable and round-trips.
- **`os.getloadavg` does not exist on Windows.** The load supervisor guarded the call with
  `try/except OSError`, but Windows raises `AttributeError` (the symbol is absent, not failing),
  crashing the scan the first time `wait_if_paused()` sampled load. Load average has no Windows
  equivalent, so the default provider now degrades to `0.0` there — **load-based auto-pause is a
  no-op on Windows in W1** (as iowait already is by default). A CPU-percent / processor-queue
  proxy to restore throttling is a W2 follow-up.
- **The CA cert must carry `keyUsage=keyCertSign`** (cross-platform, not Windows-specific, but
  only strict stacks expose it). Lenient OpenSSL on Linux accepts a CA without a keyUsage
  extension, so the whole Linux fleet verified fine; Python's `ssl` on Windows (and Go's
  `crypto/tls`) reject the chain outright — `CA cert does not include key usage extension` — so
  the native agent could not verify the proxy. The CA generators (`deploy/nas-1/gen-certs.sh`
  and the documented `openssl` bootstrap) now emit `basicConstraints=critical,CA:TRUE` +
  `keyUsage=critical,keyCertSign,cRLSign`; an existing CA is re-issuable in place from the same
  key (same subject/SKI keeps every signed leaf valid). This generalises the existing
  "Proxy-cert SAN by IP" fail-closed note below: **strict-TLS correctness of the trust material
  is a precondition for any non-OpenSSL agent**, not just Windows.

### Deferred to MSI / frozen-exe packaging (tracked)

- **Run as SYSTEM is interim.** ADR intent is a dedicated low-privilege account holding only
  `SeBackupPrivilege`. The bootstrap runs the W1 task as SYSTEM because creating a service account
  + assigning the LSA privilege is a packaging concern (the MSI installer), not something to do in a
  paste-once bootstrap. In the interim the **install-dir ACL lock above is what bounds the risk**
  (a hijacked-script→SYSTEM escalation requires defeating the SYSTEM/Admins-only DACL first).
- **Proxy-cert SAN by IP.** Because the native agent dials the proxy by IP, the proxy server cert
  SAN must include that IP; TLS verification is fail-closed if it does not (cryptic error). A
  preflight cert-SAN check with a clear message is a packaging-phase nicety.

### Phase W2 — full-content + incremental

Full-bit hashing via backup-semantics opens, and the **NTFS USN change journal** as the
incremental change feed (the Windows-native equivalent of `zfs diff`/fanotify, and more
durable than both — the filesystem maintains it).

### Explicit non-goal until its own review: the write path

Remediation on Windows requires rebuilding the TOCTOU defences (today: `O_NOFOLLOW` +
parent-fd opens) on Win32 handle semantics (`FILE_FLAG_OPEN_REPARSE_POINT` discipline,
handle-relative re-checks). That is security-critical new code and ships **only after its own
adversarial review round**, as the POSIX executor did. Windows agents run read-only until
then, regardless of server-side remediation settings (fail-closed on both ends).

## Consequences

- Catalogue, ingest, dedup and UI need **no schema or API changes** — the identity model and
  wire format hold as-is.
- `security/paths.py` becomes platform-branched and is the highest-risk surface of W1; it
  gets the same fail-closed test discipline (and the planned property-based fuzzing) as the
  POSIX rules.
- The deploy wizard's bundle generator gains a Windows bundle shape (service + config + certs)
  in a later wave; until then the wizard targets POSIX hosts only.
- Docs: README/comparison stop listing "no Windows agent" as a gap once W1 ships; the SMB
  remote path remains the zero-install option.
