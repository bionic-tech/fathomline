#!/usr/bin/env bash
# Stand up a full local Fathom on this machine — no fleet, no mTLS proxy — populated with REAL
# data from local scans, so every UI page can be verified/built against genuine data.
#
#   scripts/localdev/run.sh            # build dist, start API on SQLite, bootstrap admin, seed
#   scripts/localdev/run.sh --no-seed  # just (re)start the API against the existing catalogue
#   scripts/localdev/run.sh --reset    # wipe the local catalogue first
#   SEED_MAX_ENTRIES=20000 scripts/localdev/run.sh   # cap per-volume entries for a fast loop
#
# Prints the URL + admin credentials and leaves the API running in the foreground (Ctrl-C stops).
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

PORT="${FATHOM_LOCAL_PORT:-8099}"
DB="$ROOT/scripts/localdev/fathom-local.db"
DIST="$ROOT/src/fathom/web/dist"
ADMIN_USER="admin"
ADMIN_PASS="${FATHOM_LOCAL_ADMIN_PASS:-localdev-admin-pw}"

NO_SEED=0
for a in "$@"; do
  case "$a" in
    --reset) echo "resetting local catalogue"; rm -f "$DB" "$DB"-wal "$DB"-shm ;;
    --no-seed) NO_SEED=1 ;;
  esac
done

export FATHOM_DATABASE_URL="sqlite+aiosqlite:///$DB"
export FATHOM_AUTO_CREATE_SCHEMA=true
export FATHOM_WEB_DIST="$DIST"
export FATHOM_SESSION_COOKIE_SECURE=false
export FATHOM_API_BIND=127.0.0.1

# 1. Build the SPA if the dist is missing (node only needed at build time).
if [ ! -f "$DIST/index.html" ]; then
  echo "== building SPA dist =="
  npm --prefix src/fathom/web install --no-audit --no-fund >/dev/null 2>&1 || true
  npm --prefix src/fathom/web run build
fi

# 2. Start the API (its lifespan creates the schema via auto_create_schema).
echo "== starting API on http://127.0.0.1:$PORT =="
uv run uvicorn --factory fathom.api.app:create_app --host 127.0.0.1 --port "$PORT" &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT
for i in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done

# 3. Bootstrap the local admin (idempotent — no-ops if it already exists).
echo "== bootstrapping admin =="
FATHOM_BOOTSTRAP_ADMIN_USER="$ADMIN_USER" FATHOM_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASS" \
  uv run python -m fathom.admin create-admin || true

# 4. Seed real data from local scans.
if [ "$NO_SEED" = 0 ]; then
  echo "== seeding from local scans (this is a real filesystem walk; may take a few minutes) =="
  FATHOM_LOCAL_API="http://127.0.0.1:$PORT" uv run python scripts/localdev/seed.py || \
    echo "!! seeding failed (API still up; inspect above)"
fi

cat <<EOF

────────────────────────────────────────────────────────────
  Fathom local dev is UP:
    URL:   http://127.0.0.1:$PORT/
    login: $ADMIN_USER / $ADMIN_PASS
    DB:    $DB
  Ctrl-C to stop. Re-seed without restart:
    FATHOM_LOCAL_API=http://127.0.0.1:$PORT uv run python scripts/localdev/seed.py
────────────────────────────────────────────────────────────
EOF
wait $API_PID
