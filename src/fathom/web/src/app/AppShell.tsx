// Application shell (frontend ADD §4): Dashboard ⇄ Explorer toggle, global scope/host
// selector, and the session/auth surface. Scope-aware: only in-scope volumes are offered, so
// out-of-scope hosts/volumes are never rendered (frontend ADD §2; the server enforces too).

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";

import { useVolumes, useWhoAmI } from "../api/queries";
import { volumeLabel } from "../api/types";
import { principalHas } from "../auth/rbac";
import { logout } from "../auth/session";
import { useUiStore } from "../state/uiStore";

export function AppShell(): JSX.Element {
  const me = useWhoAmI();
  const volumes = useVolumes();
  const selectVolume = useUiStore((s) => s.selectVolume);
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Default the global scope to the first in-scope volume ONCE, on first load, so the Dashboard,
  // Explorer, Scans and Duplicates show data immediately instead of an empty "select a volume"
  // state. The one-time guard is essential: selectedVolumeId === null is BOTH the initial state AND
  // the deliberate "All volumes (estate)" choice — without the guard, picking "All volumes" would
  // instantly snap back to the first volume. After this runs once, the user's scope (incl. All) sticks.
  const firstVolume = volumes.data?.[0];
  const didInitScope = useRef(false);
  useEffect(() => {
    if (didInitScope.current || !firstVolume) return;
    if (selectedVolumeId === null) {
      selectVolume(firstVolume.host_id, firstVolume.id, firstVolume.mountpoint);
    }
    didInitScope.current = true;
  }, [firstVolume, selectedVolumeId, selectVolume]);

  // RBAC-aware nav: hide surfaces the principal lacks the capability for. The server still
  // enforces deny-by-default on each request, so this is purely UX (frontend ADD §2; ADD 13 §4).
  const canViewDedup = principalHas(me.data, "view_dedup");
  const canReadAudit = principalHas(me.data, "read_audit");
  const canDeploy = principalHas(me.data, "deploy_agent");

  async function onSignOut(): Promise<void> {
    // Revoke the server session + clear client storage, then drop the cached principal so the
    // guard sees "logged out", and land back on /login.
    await logout();
    queryClient.clear();
    navigate("/login", { replace: true });
  }

  return (
    <div className="fathom-shell">
      <header className="fathom-topbar">
        <nav aria-label="Primary">
          <Link to="/dashboard" aria-current={location.pathname === "/dashboard" ? "page" : undefined}>
            Dashboard
          </Link>
          <Link to="/explore" aria-current={location.pathname === "/explore" ? "page" : undefined}>
            Explorer
          </Link>
          <Link to="/search" aria-current={location.pathname === "/search" ? "page" : undefined}>
            Search
          </Link>
          <Link to="/largest" aria-current={location.pathname === "/largest" ? "page" : undefined}>
            Largest
          </Link>
          <Link
            to="/organize"
            aria-current={location.pathname === "/organize" ? "page" : undefined}
          >
            Organize
          </Link>
          <Link to="/changes" aria-current={location.pathname === "/changes" ? "page" : undefined}>
            Changes
          </Link>
          {canViewDedup ? (
            <Link to="/duplicates" aria-current={location.pathname === "/duplicates" ? "page" : undefined}>
              Duplicates
            </Link>
          ) : null}
          <Link to="/reconcile" aria-current={location.pathname === "/reconcile" ? "page" : undefined}>
            Reconcile
          </Link>
          <Link to="/scans" aria-current={location.pathname === "/scans" ? "page" : undefined}>
            Scans
          </Link>
          <Link to="/agents" aria-current={location.pathname === "/agents" ? "page" : undefined}>
            Agents
          </Link>
          {canDeploy ? (
            <Link to="/deploy" aria-current={location.pathname === "/deploy" ? "page" : undefined}>
              Deploy
            </Link>
          ) : null}
          {canReadAudit ? (
            <Link to="/audit" aria-current={location.pathname === "/audit" ? "page" : undefined}>
              Audit
            </Link>
          ) : null}
          <Link to="/settings" aria-current={location.pathname === "/settings" ? "page" : undefined}>
            Settings
          </Link>
        </nav>

        <label className="fathom-scope">
          Volume
          <select
            value={selectedVolumeId ?? ""}
            onChange={(e) => {
              const vol = volumes.data?.find((v) => v.id === Number(e.target.value));
              selectVolume(vol?.host_id ?? null, vol?.id ?? null, vol?.mountpoint ?? null);
            }}
          >
            {/* The empty value = no single volume = estate-wide aggregate on the Dashboard. */}
            <option value="">All volumes (estate)</option>
            {(volumes.data ?? []).map((v) => (
              <option key={v.id} value={v.id}>
                {volumeLabel(v)}
              </option>
            ))}
          </select>
        </label>

        <div className="fathom-session">
          {me.data ? <span>{me.data.display_name ?? me.data.subject}</span> : <span>…</span>}
          <button type="button" onClick={() => void onSignOut()}>
            Sign out
          </button>
        </div>
      </header>

      <main>
        <Outlet />
      </main>
    </div>
  );
}
