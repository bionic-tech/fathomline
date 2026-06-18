#!/usr/bin/env bash
# Non-interactive END-TO-END feature verification for Fathom (Phase E).
#
# Stands up a throwaway local stack (SQLite + a mock Ollama so AI-organize is deterministic and
# offline), seeds a controlled synthetic corpus through the REAL ingest->finalize path, then:
#   1. drives EVERY feature over HTTP and asserts each result against both the expected tally and a
#      direct read of the server DB (scripts/e2e/verify.py),
#   2. captures use-case "story" screenshots (scripts/e2e/stories.mjs),
#   3. on verify failure, attempts a mechanical recovery (rebuild SPA + re-seed) and re-tests,
#   4. writes full logs + a JSON report under $OUT.
#
# DESTRUCTION-FREE: only build/suggest/plan paths are exercised; no remediation execute/dry-run
# dispatch, so no file is ever moved or deleted. Exits non-zero if any check ultimately fails.
#
#   scripts/e2e/run_e2e.sh                 # full run (build + seed + verify + screenshots)
#   E2E_NO_SHOTS=1 scripts/e2e/run_e2e.sh  # skip screenshots (no Playwright needed)
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

OUT="${E2E_OUT:-/tmp/fathom-e2e}"
PORT="${E2E_PORT:-8097}"
MOCK_PORT="${E2E_MOCK_PORT:-11999}"
DB="$OUT/e2e.db"
DB_URL="sqlite+aiosqlite:///$DB"
DIST="$ROOT/src/fathom/web/dist"
ADMIN_PASS="${E2E_ADMIN_PASS:-localdev-admin-pw}"
API="http://127.0.0.1:$PORT"
mkdir -p "$OUT"
rm -f "$DB" "$DB"-wal "$DB"-shm

# `uv run uvicorn &` backgrounds the uv WRAPPER; uvicorn is a grandchild, so killing $! orphans it
# (it keeps the port + the deleted DB handle). Kill by pattern on the unique port instead.
cleanup() {
  pkill -f "uvicorn.*--port $PORT" 2>/dev/null
  pkill -f "mock_ollama.py --port $MOCK_PORT" 2>/dev/null
}
trap cleanup EXIT
cleanup  # clear any stale instance from a previous run on these ports
sleep 1

echo "== [1/6] build SPA dist (always — so the harness tests the CURRENT UI, not a stale dist) =="
# Building unconditionally is essential: a stale dist silently passes UI assertions that don't
# happen to change, hiding real UI regressions/fixes. The Vite build is only a few seconds.
npm --prefix src/fathom/web install --no-audit --no-fund >/dev/null 2>&1 || true
npm --prefix src/fathom/web run build 2>&1 | tail -3

echo "== [2/6] start mock Ollama on :$MOCK_PORT =="
uv run python scripts/e2e/mock_ollama.py --port "$MOCK_PORT" >"$OUT/mock-ollama.log" 2>&1 &
MOCK_PID=$!

echo "== [3/6] start API on $API =="
export FATHOM_DATABASE_URL="$DB_URL"
export FATHOM_AUTO_CREATE_SCHEMA=true
export FATHOM_WEB_DIST="$DIST"
export FATHOM_SESSION_COOKIE_SECURE=false
export FATHOM_API_BIND=127.0.0.1
export FATHOM_ORGANIZE_ENABLED=true
export FATHOM_REMEDIATION_ENABLED=true
# Arm the remediation runtime so build/plan paths work (HMAC signer; secret resolved by env ref).
# This only enables BUILD (persist a plan) — the harness NEVER calls dry-run dispatch or execute,
# so no file is ever moved or deleted.
export FATHOM_REMEDIATION_SIGNING_ALGORITHM=hmac
export FATHOM_REMEDIATION_SIGNING_KEY_REF=FATHOM_E2E_SIGNING_SECRET
export FATHOM_REMEDIATION_SIGNING_KEY_ID=e2e-hmac-1
export FATHOM_E2E_SIGNING_SECRET="e2e-harness-hmac-signing-secret-32bytes-minimum-abcdef"
export FATHOM_INFERENCE_PROVIDER=ollama
export FATHOM_INFERENCE_OLLAMA_URL="http://127.0.0.1:$MOCK_PORT"
export FATHOM_ORGANIZE_MODEL=e2e-mock
uv run uvicorn --factory fathom.api.app:create_app --host 127.0.0.1 --port "$PORT" \
  >"$OUT/api.log" 2>&1 &
for i in $(seq 1 90); do
  curl -sf "$API/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
if ! curl -sf "$API/healthz" >/dev/null 2>&1; then
  echo "!! API failed to come up; see $OUT/api.log"; tail -20 "$OUT/api.log"; exit 2
fi

echo "== [4/6] bootstrap admin =="
FATHOM_BOOTSTRAP_ADMIN_USER=admin FATHOM_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASS" \
  uv run python -m fathom.admin create-admin >"$OUT/bootstrap.log" 2>&1 || true
if grep -qiE "no such table|error|traceback" "$OUT/bootstrap.log"; then
  echo "!! bootstrap failed; see $OUT/bootstrap.log"; tail -8 "$OUT/bootstrap.log"; exit 3
fi

seed() {
  echo "== seed synthetic corpus =="
  FATHOM_LOCAL_API="$API" uv run python scripts/e2e/seed_e2e.py --api "$API" \
    --out "$OUT/expected.json" >"$OUT/seed.log" 2>&1
  sleep 1  # let the WAL settle so the verifier's read-only DB connection sees finalize's writes
}
verify() {
  uv run python scripts/e2e/verify.py --api "$API" --db "$DB" \
    --expected "$OUT/expected.json" --password "$ADMIN_PASS" \
    --report "$OUT/verify-report.json" 2>&1 | tee "$OUT/verify.log"
  return "${PIPESTATUS[0]}"
}

echo "== [5/6] seed + verify (with mechanical auto-recovery) =="
seed
attempt=1; MAX=2; RC=1
while :; do
  echo "--- verify attempt $attempt/$MAX ---"
  if verify; then RC=0; break; fi
  RC=1
  if [ "$attempt" -ge "$MAX" ]; then
    echo "!! verify still failing after $MAX attempts (see $OUT/verify-report.json)"; break
  fi
  # Mechanical recovery (no API restart — re-seed is change-guarded/idempotent; rebuild the SPA in
  # case a stale dist caused a UI-side check to fail). A genuine assertion/code failure survives
  # this and is left in the report for a human/agent to fix.
  echo "!! verify failed; mechanical recovery: rebuild SPA + re-seed, then retry"
  npm --prefix src/fathom/web run build >"$OUT/rebuild.log" 2>&1 | tail -2 || true
  seed
  attempt=$((attempt + 1))
done

echo "== [6/6] UI verification + use-case story screenshots =="
if [ "${E2E_NO_SHOTS:-0}" = "1" ]; then
  echo "  (skipped: E2E_NO_SHOTS=1)"
else
  # stories.mjs asserts rendered UI content AND captures screenshots. It exits 0 if playwright is
  # absent (graceful skip) and non-zero ONLY on a real UI-assertion failure — which fails the run.
  if FATHOM_LOCAL_API="$API" FATHOM_LOCAL_ADMIN_PASS="$ADMIN_PASS" E2E_OUT="$OUT" \
       node "$ROOT/scripts/e2e/stories.mjs" >"$OUT/stories.log" 2>&1; then
    grep -qE "screenshots ->" "$OUT/stories.log" && echo "  UI verified + screenshots -> $OUT/shots/" || echo "  (UI verify skipped — playwright absent)"
  else
    echo "  !! UI verification FAILED (see $OUT/ui-report.json + $OUT/stories.log)"; tail -10 "$OUT/stories.log"
    RC=1
  fi
fi

echo
echo "════════════════════════════════════════════════════════"
echo "  E2E result: $([ "$RC" = 0 ] && echo PASS || echo FAIL)"
echo "  report:     $OUT/verify-report.json"
echo "  logs:       $OUT/{api,seed,verify,stories}.log"
echo "  shots:      $OUT/shots/"
echo "════════════════════════════════════════════════════════"
exit "$RC"
