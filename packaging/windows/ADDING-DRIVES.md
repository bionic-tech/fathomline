# Adding drives to the Windows agent

The win11-desktop agent currently runs in **Docker Desktop** (a Linux container). Inside that
container a Windows drive only exists if it was **mounted in** — that's the bit that trips people up.
A drive letter on Windows ≠ a path the agent can see. There are two layers:

1. **Mount** the Windows drive/folder into the container (host-side, edits a file on the PC).
2. **Scope** the in-container path so the agent actually scans it (can be done from the web app).

Your container today mounts `C:`, `D:`, `E:` as `/scan/c`, `/scan/d`, `/scan/e`, and scans
`/scan/d/mmarchive` + `/scan/e/mmarchive` (full-bit).

---

## Add a whole new drive (e.g. `F:`) — Docker Desktop agent

On the **Windows PC**, edit the agent's `docker-compose.yml` (next to where you launch the agent)
and add one volume line to the agent service, then add it to the scan scope:

```yaml
    volumes:
      - C:\:/scan/c:ro          # existing
      - D:\:/scan/d:ro          # existing
      - E:\:/scan/e:ro          # existing
      - F:\:/scan/f:ro          # <-- NEW drive, read-only
```

Then restart the agent container (Docker Desktop → the fathom agent → Restart, or
`docker compose up -d` in that folder). The drive now exists at `/scan/f` **inside** the container.

Now point a scan at it — **two ways**:

- **From the web app (no more file editing):** Agents → *win11-desktop* → **Advanced (agent config)**
  → the **scan scope** box has a drive-picker (it lists what the agent reports it can see). Add
  `/scan/f` (or a subfolder like `/scan/f/Photos`), **Save**. It applies on the agent's next run.
  *This only works after the mount above — the picker can't show a drive the container can't see.*
- **Or in the compose's agent config**, add `/scan/f` (and to `fullbit_scope` if you want content
  hashing — empty full-bit = metadata-only) and restart.

### Just a folder, not the whole drive
Mount the folder directly so you never touch the rest of the disk:
```yaml
      - F:\Photos:/scan/f-photos:ro
```
…then scope `/scan/f-photos`.

---

## Gotchas on Windows (learned the hard way)
- **Cloud / OneDrive "online-only" placeholder files HANG the walker** (drvfs reports them but the
  bytes aren't local). Point scans at *local* folders, or add the cloud folder to `exclude_scope`.
- **Full-bit vs metadata:** a path only gets content-hashed if it's in `fullbit_scope`. Leave a path
  out of `fullbit_scope` to keep it metadata-only (fast).
- **Use container paths, not Windows paths, in scan scope.** The scope wants `/scan/c/Users/...`,
  **not** `C:\Users\...`. A raw Windows path here is silently useless (see below).

---

## The easier long-term option: the native Windows agent (no Docker, no mounts)
The native `.exe` agent (ADR-027, `build-agent-exe.ps1`) scans local NTFS drives **directly** — you
list real Windows paths (`D:\mmarchive`, `F:\Photos`) in its config and there are **no container
mounts to manage at all**. Adding a drive is just another `scan_scope` line (and `fullbit_scope` line
for content hashing) — no `-v` mounts, no restarts of a daemon.

**It now does full-bit content hashing safely (ADR-027 W2, 2026-06-30).** Crucially, it solves the
exact OneDrive/placeholder **hang** the Docker agent hits: before hashing a file it checks the file's
attributes and **skips cloud placeholders and reparse points without opening them** (opening is what
would force a multi-GB download). So on the native agent you can point `fullbit_scope` at a folder
that contains cloud files and it just hashes the local ones and skips the rest — no hang, no
surprise hydration. Config example:

```yaml
scan_scope:
  - 'D:\mmarchive'
  - 'C:\Users\boywi\Documents'
fullbit_scope:
  - 'D:\mmarchive'        # content-hashed (dedup); cloud placeholders inside are skipped, not pulled
```

If you keep adding drives or want reliable full scans on Windows, finishing this install is the
lower-friction path. Build it on a Windows box with `packaging/windows/build-agent-exe.ps1`, then
enroll it (Deploy page → Windows) or drop the generated config + certs under
`C:\ProgramData\Fathomline`. (Note: the always-on *listen* daemon — i.e. **Scan Now** reaching a
Windows host — is not in the native agent yet; it scans on its scheduled task. Linux fleet hosts
have Scan Now via the dispatch listener.)

---

## Known cleanup: a malformed catalogue row
There's a stray volume `C:\Users\boywi\Documents` in the catalogue — a **raw Windows path** that was
entered where a container path (`/scan/c/Users/boywi/Documents`) belonged, so it scanned nothing
useful and shows up as junk. It's safe to remove (it's a deletion of catalogued data, so it needs a
deliberate confirm rather than an automatic sweep). Re-add it correctly as `/scan/c/Users/boywi/Documents`
once `C:` is mounted (it already is, as `/scan/c`).
