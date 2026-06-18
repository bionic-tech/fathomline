# Fathom E2E feature-verification harness (Phase E)

A **non-interactive, destruction-free** end-to-end harness that exercises *every* Fathom feature,
asserts each result against **both** the HTTP API **and** a direct read of the server DB, captures
use-case "story" screenshots, and auto-recovers from transient failures.

```bash
scripts/e2e/run_e2e.sh                 # full run: build + seed + verify + screenshots
E2E_NO_SHOTS=1 scripts/e2e/run_e2e.sh  # verify only (no Playwright needed)
```

Exits non-zero if any feature check ultimately fails. Output under `/tmp/fathom-e2e/` (override with
`E2E_OUT`): `verify-report.json` (structured per-check results), `{api,seed,verify,stories}.log`,
and `shots/*.png`.

## What it does

1. **Stands up a throwaway stack** — SQLite catalogue + a mock Ollama (`mock_ollama.py`) so the
   AI-organize path is deterministic and fully offline. The API runs with the organize + remediation
   surfaces armed (HMAC signing key by env reference) so the build/plan paths are reachable.
2. **Seeds a controlled synthetic corpus** (`seed_e2e.py`) through the **real** ingest→finalize HTTP
   path, with *known expected tallies* written to `expected.json`. The corpus deliberately includes:
   - a genuine **cross-host duplicate** (same content native on two hosts) → reclaimable,
   - a **cross-mount alias** (the same physical file seen natively on `tiger-1:/raid` **and** through
     `nas-1`'s NFS mount `/nfsmnt`) → the NFS member flagged `is_mount_alias`, reclaimable 0 (ADR-032),
   - an organize-ready mixed-type folder, a reconcile mirror pair, and change/history/audit fixtures.
3. **Verifies every feature** (`verify.py`): volumes, agents, duplicates (summary + cross-host +
   cross-mount alias), largest files (top-n), treemap, search, AI organize (suggest→plan-build),
   reconcile, remediation plan-build, scans, changes, and audit-chain continuity — each cross-checked
   API-vs-DB-vs-expected.
4. **Verifies the UI + captures story screenshots** (`stories.mjs`, Playwright) driving real flows in
   one SPA session. It does not just screenshot — it **asserts the rendered page** shows the expected
   values (largest file, the by-type organize proposal, the cross-mount "mount alias" badge, the
   seeded hosts, search hits), so a UI that renders wrong/empty data against a correct backend
   **fails** the run (`ui-report.json`). Exits 0 (graceful skip) if Playwright/chromium is absent.
5. **Auto-recovers**: a failed verify triggers a rebuild-SPA + re-seed + re-test (bounded retries);
   a genuine assertion/code failure survives and is left in `verify-report.json` for a fix.

## Safety

Read-only and destruction-free. Only the **build/suggest/plan** paths are exercised; the harness
**never** calls remediation dry-run dispatch or execute, so no file is ever moved or deleted. The
remediation runtime is armed only enough to *persist* a plan row.

## Requirements

- `uv` (Python deps), and for screenshots: Playwright + chromium under `src/fathom/web/node_modules`
  (`cd src/fathom/web && npx playwright install chromium`). Screenshot failure is non-fatal.
