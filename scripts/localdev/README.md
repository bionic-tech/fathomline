# Local dev — run all of Fathom on this machine, with real data

No fleet, no mTLS proxy, no Postgres. This stands up the full Fathom API + SPA on **SQLite**,
then populates the catalogue by **really scanning local directories** through the same
ingest → finalize code the production agent uses — so every UI page renders against genuine,
non-mocked data.

## Quick start

```bash
scripts/localdev/run.sh            # build SPA, start API on :8099, bootstrap admin, seed real data
```

Then open **http://127.0.0.1:8099/** and log in as **admin / localdev-admin-pw**
(override with `FATHOM_LOCAL_ADMIN_PASS`). `Ctrl-C` stops the API; the catalogue persists in
`scripts/localdev/fathom-local.db`.

```bash
scripts/localdev/run.sh --reset    # wipe the catalogue and re-seed from scratch
scripts/localdev/run.sh --no-seed  # just (re)start the API against the existing catalogue
SEED_MAX_ENTRIES=20000 scripts/localdev/run.sh   # cap per-volume entries for a fast loop
```

## What gets seeded (and which page it feeds)

The default scan (`scripts/localdev/seed.py`, edit `HOSTS` to taste) carves two "hosts" out of
this workstation's real filesystem:

| Data | Source | UI page it makes real |
|------|--------|-----------------------|
| 2 hosts, 3 volumes | `/usr`, `/opt` (host *workstation-amd*); `/var/lib` (host *build-runner*) | **Agents**, top-bar volume picker |
| Real subtree sizes + counts | the metadata walk → `subtree_rollup` | **Dashboard** (treemap), **Explorer** (tree/listing) |
| Duplicate groups | BLAKE3 full-bit pass over `/usr/share/icons` + `/usr/share/doc` | **Duplicates** |
| Scan-run history with real totals | the snapshot rows ingest opens, stamped by finalize | **Scans** |
| Weekly growth trend | backdated `size_history` points (a dev fixture) | **Dashboard** (growth) |
| Hash-chained action log | demo records via the real audit chain (`actor=localdev-seed`, a fixture) | **Audit** |
| Cross-cloud duplicates | two simulated rclone remotes (gdrive + dropbox) with real md5 provider hashes | **Duplicates** → "Cross-cloud" section |

The duplicate groups and rollup sizes are **genuine** (your real files). The growth-history and
audit rows are clearly-labelled **fixtures** (one finalize only writes one history point, and no
remediation has run locally) so those two pages aren't empty.

The **cross-cloud duplicates** (ADR-028/029) are seeded through the real ingest path as two
remote volumes (`rclone://gdrive/Backups`, `rclone://dropbox/Sync`) with two files shared across
both — so the Duplicates page's "Cross-cloud" section shows genuine, zero-egress provider-hash
groups. No rclone binary or cloud account is needed: the md5 hashes are real; only the "cloud" is
simulated. Skip with `--no-cloud-dups`.

## Re-seed without a full re-scan

```bash
# refresh only the demo fixtures (history + audit), leave the scanned catalogue intact:
FATHOM_LOCAL_API=http://127.0.0.1:8099 uv run python scripts/localdev/seed.py \
  --fixtures-only --audit-rows 12 --history-weeks 10
```

## Add a USB NVMe drive (or any extra volume)

Mount it read-only, then add it to a host in `seed.py`'s `HOSTS` and re-seed:

```python
HostSpec(name="usb-archive", fingerprint="local-usb-0003", os="ext4",
         volumes=[VolumeSpec("/media/you/usb-nvme")], fullbit=["/media/you/usb-nvme/photos"])
```

A new `fingerprint` auto-enrols as a new host on first push (`ingest._upsert_host`), so it shows
up as its own host on the Agents page — the same mechanism the real fleet uses.

## Visual proof (screenshot every page)

```bash
npx playwright install chromium          # one-time
node scripts/localdev/screenshot.mjs     # logs in, screenshots all 7 pages -> /tmp/fathom-shots/
```

## Tuning knobs (env)

`FATHOM_LOCAL_PORT` (8099) · `FATHOM_LOCAL_ADMIN_PASS` · `SEED_MAX_ENTRIES` (0=all) ·
`SEED_FULLBIT_MAX` (8000) · `SEED_HISTORY_WEEKS` (10) · `SEED_AUDIT_ROWS` (12).
