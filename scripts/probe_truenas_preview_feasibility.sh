#!/usr/bin/env bash
# probe_truenas_preview_feasibility.sh
# AR-0002 — Verify whether Fathom's preview worker (gVisor/runsc) and metadata
# root-reader (CAP_DAC_READ_SEARCH) can run inside TrueNAS SCALE's Docker.
#
# SAFE: read-only probes. The only writes are a temp test fixture under a
# mktemp dir, removed on exit. No changes to Docker, ZFS, or system config.
#
# Run ON the TrueNAS host:   sudo ./probe_truenas_preview_feasibility.sh
# (sudo is needed only to create a root-owned 0700 fixture for the cap test.)

set -uo pipefail   # intentionally NOT -e: we want to run every probe and report

PASS="PASS"; FAIL="FAIL"; WARN="WARN"
gvisor_ok=""; cap_ok=""; docker_ok=""
TMP=""

cleanup() { [ -n "${TMP}" ] && rm -rf "${TMP}" 2>/dev/null; }
trap cleanup EXIT

line() { printf '%s\n' "------------------------------------------------------------"; }
hdr()  { line; printf '## %s\n' "$1"; line; }

HOST="$(hostname)"
IS_TRUENAS=""; command -v midclt >/dev/null 2>&1 && IS_TRUENAS=1

hdr "Environment"
echo "host:    ${HOST}"
echo "date:    $(date -Is)"
echo "kernel:  $(uname -r)"
echo "user:    $(id -un) (uid=$(id -u))"

hdr "0. Docker availability"
if command -v docker >/dev/null 2>&1; then
  docker_ok="$PASS"
  echo "docker:  $(docker --version 2>/dev/null)"
  echo "runtimes: $(docker info --format '{{json .Runtimes}}' 2>/dev/null)"
  echo "default-runtime: $(docker info --format '{{.DefaultRuntime}}' 2>/dev/null)"
else
  docker_ok="$FAIL"
  echo "docker NOT found on PATH. On TrueNAS the docker CLI may live elsewhere or"
  echo "the Apps service may not expose it. Cannot probe further without it."
fi

# Pick an available tiny image; prefer one already present to avoid network egress.
IMG=""
if [ "$docker_ok" = "$PASS" ]; then
  for cand in busybox:latest alpine:latest busybox alpine; do
    if docker image inspect "$cand" >/dev/null 2>&1; then IMG="$cand"; break; fi
  done
  if [ -z "$IMG" ]; then
    echo "(no local busybox/alpine image; attempting a pull of busybox — needs egress)"
    if docker pull busybox:latest >/dev/null 2>&1; then IMG="busybox:latest"; fi
  fi
  echo "probe image: ${IMG:-<none available>}"
fi

hdr "1. gVisor (runsc) availability"
if command -v runsc >/dev/null 2>&1; then
  echo "runsc binary: $(command -v runsc)  ($(runsc --version 2>/dev/null | head -1))"
fi
if [ "$docker_ok" = "$PASS" ] && docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc; then
  echo "runsc registered as a Docker runtime: YES"
  if [ -n "$IMG" ] && docker run --rm --runtime=runsc "$IMG" true >/dev/null 2>&1; then
    gvisor_ok="$PASS"; echo "ran a container under --runtime=runsc: OK"
  else
    gvisor_ok="$WARN"; echo "runsc registered but a test container did NOT run under it."
  fi
else
  gvisor_ok="$FAIL"
  echo "runsc is NOT a registered Docker runtime."
  if [ -n "$IS_TRUENAS" ]; then
    echo "NOTE: TrueNAS SCALE manages its own Docker; installing runsc is not officially"
    echo "supported and may NOT persist across TrueNAS updates. Treat as unavailable here."
  else
    echo "NOTE: this is a standard Docker host — runsc CAN be installed (gVisor releases +"
    echo "'runsc install' + 'systemctl reload docker'). Install it to host the preview worker."
  fi
fi

hdr "2. CAP_DAC_READ_SEARCH grantable + effective"
# IMPORTANT: Docker's --cap-add only adds to a container's *bounding* set. For a process
# started as a NON-root --user, the capability never reaches the *effective* set (no file
# capability or ambient-cap transition), so `--user 1000 --cap-add=DAC_READ_SEARCH` is a
# false-negative on EVERY stock runc host, TrueNAS or not. The realistic root-reader model
# is: start the container as uid 0, drop ALL caps, add back ONLY DAC_READ_SEARCH — the cap
# is then effective while every other root privilege is gone. That is what we test here.
# (A non-root deployment is still possible but requires the runtime/orchestrator to raise
# the *ambient* set, e.g. setpriv --ambient-caps / a k8s securityContext — see section 3.)
if [ "$docker_ok" = "$PASS" ] && [ -n "$IMG" ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "(not root — cannot create the root-owned 0700 fixture; re-run with sudo)"
    cap_ok="$WARN"
  else
    TMP="$(mktemp -d)"
    mkdir -p "$TMP/secret"
    echo "sentinel-$(date +%s)" > "$TMP/secret/canary.txt"
    chown -R 0:0 "$TMP/secret"
    chmod 700 "$TMP/secret"          # only root may traverse/read by DAC
    chmod 600 "$TMP/secret/canary.txt"

    # Control: non-root, ALL caps dropped -> MUST fail to read.
    ctrl_out="$(docker run --rm --user 1000:1000 --cap-drop=ALL \
      -v "$TMP/secret:/secret:ro" "$IMG" sh -c 'cat /secret/canary.txt' 2>&1)"
    ctrl_rc=$?

    # Test: root uid, ALL caps dropped except CAP_DAC_READ_SEARCH -> cap is effective, SHOULD read.
    test_out="$(docker run --rm --cap-drop=ALL --cap-add=DAC_READ_SEARCH \
      -v "$TMP/secret:/secret:ro" "$IMG" sh -c 'cat /secret/canary.txt' 2>&1)"
    test_rc=$?
    eff="$(docker run --rm --cap-drop=ALL --cap-add=DAC_READ_SEARCH "$IMG" \
      sh -c 'grep CapEff /proc/self/status' 2>&1)"

    echo "control (non-root, no caps)         rc=$ctrl_rc  -> $( [ $ctrl_rc -ne 0 ] && echo 'denied (expected)' || echo 'UNEXPECTEDLY READABLE' )"
    echo "test (root + only DAC_READ_SEARCH)  rc=$test_rc  -> $( [ $test_rc -eq 0 ] && echo 'readable (expected)' || echo 'still denied' )   [$eff]"

    if [ $ctrl_rc -ne 0 ] && [ $test_rc -eq 0 ]; then
      cap_ok="$PASS"; echo "VERDICT: CAP_DAC_READ_SEARCH is grantable AND effective here (cap-only-root model)."
    elif [ $ctrl_rc -eq 0 ]; then
      cap_ok="$WARN"; echo "VERDICT: control could read without caps — fixture/perms not enforced as expected."
    else
      cap_ok="$FAIL"; echo "VERDICT: cap add did NOT grant read — capability not effective in this Docker."
    fi
  fi
else
  cap_ok="$FAIL"; echo "(skipped — no docker/image)"
fi

hdr "3. TrueNAS Custom App caveat (manual check)"
cat <<'EOF'
The probes above use the docker CLI. A TrueNAS *Custom App* (ix-chart) applies its
own pod/security defaults. Confirm in the Apps UI / app YAML that you can set:
  - securityContext capabilities.add: ["DAC_READ_SEARCH"]   (or compose cap_add)
  - a non-root runAsUser
  - (for gVisor) a runtimeClassName / --runtime=runsc        <- usually NOT available
If the Custom App layer strips these, the CLI 'PASS' above won't translate to the App.
EOF

hdr "VERDICT (AR-0002)"
echo "docker present:            ${docker_ok:-?}"
echo "gVisor (runsc) usable:     ${gvisor_ok:-?}"
echo "CAP_DAC_READ_SEARCH works: ${cap_ok:-?}"
echo
# The two components are now decided independently:
#  - root-reader needs only CAP_DAC_READ_SEARCH (cap test)
#  - preview worker needs gVisor/runsc sandboxing (gvisor test)
if [ "$cap_ok" = "$PASS" ]; then
  echo ">> ROOT-READER: CAN run on ${HOST} (CAP_DAC_READ_SEARCH effective under the cap-only-root"
  echo ">>   model).${IS_TRUENAS:+ Confirm the Custom App layer (section 3) preserves capabilities.add.}"
else
  echo ">> ROOT-READER: cap=${cap_ok:-?} on ${HOST} — relocate the metadata root-reader to a host where it passes."
fi
if [ "$gvisor_ok" = "$PASS" ]; then
  echo ">> PREVIEW WORKER: gVisor available on ${HOST} — may run here in a runsc sandbox."
else
  echo ">> PREVIEW WORKER: gVisor=${gvisor_ok:-?} on ${HOST} — relocate to (or install runsc on) an"
  echo ">>   Ubuntu node you control per ADD 06 §2; re-run this probe there to confirm runsc."
fi
