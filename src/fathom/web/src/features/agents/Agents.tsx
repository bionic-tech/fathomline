// Agents (frontend ADD §4): the fleet view, grouped by HOST so it reads as "which machines are
// scanning, and how are their volumes doing". Each host is a card with one clear status badge
// (its last scan run: ok / partial / failed / never), a friendly list of its volumes
// ("host: /real/path" + size), an on-demand "Scan now" control (P3), and the advanced agent
// config/override editor folded behind a disclosure so the default view stays scannable (P5).
//
// Fathom's agents are SCHEDULED, one-shot scanners (not always-on daemons): they push to the core
// when a scan drains, then exit. So a live "online/offline" heartbeat is the wrong metaphor — a
// host that scanned this morning is healthy, not "offline". We show "active" if it pushed within
// the last day (covers the nightly cadence + an in-progress scan that has drained a batch), else
// "idle", and the status badge reflects the OUTCOME of its last run.

import { useState } from "react";

import { ApiError } from "../../api/client";
import {
  useAgents,
  useBrowseHost,
  useScanNow,
  useSetAgentConfig,
  useVolumes,
  useWhoAmI,
} from "../../api/queries";
import { DirTree } from "../common/DirTree";
import { DriveBadge } from "../common/DriveBadge";
import { principalHas } from "../../auth/rbac";
import type { AgentConfigOverride, HostOut, ScanMode, VolumeOut } from "../../api/types";
import { formatBytes, formatDate } from "../../lib/format";
import { useNames } from "../../lib/names";
import { QueryState } from "../common/QueryState";

// "Active" = pushed within this window. 26h spans a daily scan schedule plus clock skew.
const RECENT_WINDOW_MS = 26 * 60 * 60 * 1000;

function isActive(host: HostOut): boolean {
  if (!host.last_seen) return false;
  const seen = new Date(host.last_seen).getTime();
  if (Number.isNaN(seen)) return false;
  return Date.now() - seen <= RECENT_WINDOW_MS;
}

// The single host status badge: the OUTCOME of the last scan run, with a distinct "never" state for
// a host that has never reported a run (e.g. only ingested before run-reporting existed) — that is
// not a failure.
type HostStatus = "ok" | "partial" | "failed" | "never";

const STATUS_BADGE: Record<HostStatus, { cls: string; label: string }> = {
  ok: { cls: "fathom-badge-success", label: "ok" },
  partial: { cls: "fathom-badge-warning", label: "partial" },
  failed: { cls: "fathom-badge-danger", label: "failed" },
  never: { cls: "fathom-badge-neutral", label: "never scanned" },
};

function hostStatus(host: HostOut): HostStatus {
  return host.last_run_outcome ?? "never";
}

function lastRunTitle(host: HostOut): string {
  if (!host.last_run_outcome) return "No scan run reported yet";
  const when = host.last_run_finished_at ? formatDate(host.last_run_finished_at) : "unknown time";
  const entries = host.last_run_entries_seen ?? 0;
  const failed = host.last_run_scopes_failed ?? 0;
  const failedNote = failed > 0 ? `, ${failed} scope(s) errored` : "";
  return `Last scan ${host.last_run_outcome} at ${when} — ${entries} entries${failedNote}`;
}

function cfgList(cfg: Record<string, unknown> | null | undefined, key: string): string[] {
  const v = cfg?.[key];
  return Array.isArray(v) ? v.map(String) : [];
}

// --- Scan now (P3): dispatch an on-demand scan of one root on a host's agent --------------------
const SCAN_MODE_OPTIONS: { value: ScanMode; label: string }[] = [
  { value: "metadata", label: "Metadata (fast)" },
  { value: "fullbit", label: "Deep (full-bit)" },
];

// The dispatch channel 503s until it's armed on the core — that's expected for now, so it reads as
// an informational hint rather than a failure.
function scanDispatchMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 503) return "Scan dispatch isn't enabled on this server yet.";
    if (error.status === 404) return "This host is no longer registered.";
    if (error.status === 422) return error.problem.detail ?? "That scan root or mode was rejected.";
    return error.problem.detail ?? error.problem.title ?? "Couldn't dispatch the scan.";
  }
  return "Couldn't dispatch the scan.";
}

function ScanNowControl({
  hostId,
  roots,
}: {
  hostId: number;
  roots: { path: string; label: string }[];
}): JSX.Element {
  const scan = useScanNow();
  const [mode, setMode] = useState<ScanMode>("metadata");
  const [root, setRoot] = useState(roots[0]?.path ?? "/");
  // Roots can arrive after first render (volumes load async); fall back to a valid one so the
  // controlled <select> always matches an option and we never POST a stale/empty root.
  const effectiveRoot = roots.some((r) => r.path === root) ? root : (roots[0]?.path ?? "/");

  return (
    <span className="flex flex-wrap items-center gap-1">
      {roots.length > 1 ? (
        <select aria-label="Scan root" value={effectiveRoot} onChange={(e) => setRoot(e.target.value)}>
          {roots.map((r) => (
            <option key={r.path} value={r.path}>
              {r.label}
            </option>
          ))}
        </select>
      ) : null}
      <select aria-label="Scan mode" value={mode} onChange={(e) => setMode(e.target.value as ScanMode)}>
        {SCAN_MODE_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <button
        type="button"
        className="fathom-btn fathom-btn-mini"
        disabled={scan.isPending}
        onClick={() => scan.mutate({ hostId, root: effectiveRoot, mode })}
      >
        {scan.isPending ? "Dispatching…" : "Scan now"}
      </button>
      {scan.isError ? (
        <span role="alert" className="text-xs text-fathom-danger">
          {scanDispatchMessage(scan.error)}
        </span>
      ) : null}
      {scan.isSuccess ? (
        <span role="status" className="text-xs text-emerald-300">
          Scan queued.
        </span>
      ) : null}
    </span>
  );
}

// ADR-033: per-host config — the effective config the agent reported (#9, read-only) + an override
// editor (#10, MANAGE_AGENTS). The override is partial: a blank field is "don't override". The agent
// re-validates + applies it on its NEXT run, fail-safe. write_enabled is shown but not overridable.
// Folded behind the "Advanced" disclosure on each host card so the default fleet view stays clean.
function HostConfigPanel({ host, canManage }: { host: HostOut; canManage: boolean }): JSX.Element {
  const setConfig = useSetAgentConfig();
  const eff = host.reported_config;
  const desired = host.desired_config;
  const src = desired ?? eff;
  const [scan, setScan] = useState(cfgList(src, "scan_scope").join("\n"));
  const [fullbit, setFullbit] = useState(cfgList(src, "fullbit_scope").join("\n"));
  const [cross, setCross] = useState<"inherit" | "on" | "off">(
    desired && "cross_mounts" in desired ? (desired.cross_mounts ? "on" : "off") : "inherit",
  );
  const [throttle, setThrottle] = useState(
    desired?.throttle ? JSON.stringify(desired.throttle, null, 2) : "",
  );
  const [exclude, setExclude] = useState(cfgList(src, "exclude_scope").join("\n"));
  const [jsonError, setJsonError] = useState<string | null>(null);

  // df-style mounted-volume picker (ADR-034): the host's catalogued volumes (mountpoint = the
  // agent's last-seen `df` Mounted-on). Selecting one appends its mountpoint to a scope textarea.
  const volumes = useVolumes();
  const hostVolumes = (volumes.data ?? []).filter((v) => v.host_id === host.id);
  const appendPath = (
    current: string,
    setter: (v: string) => void,
    path: string,
  ): void => {
    const lines = current.split("\n").map((s) => s.trim()).filter(Boolean);
    if (!lines.includes(path)) setter([...lines, path].join("\n"));
  };

  // Live browse (ADR-034 Phase 2): an "Explore" tree over the host's real filesystem (MFA-gated).
  // Roots = the host's known volume mountpoints (else "/" — the agent lists anywhere it can read).
  const browseHost = useBrowseHost();
  const [showTree, setShowTree] = useState(false);
  const treeRoots = hostVolumes.length
    ? hostVolumes.map((v) => ({ path: v.mountpoint, label: v.mountpoint }))
    : [{ path: "/", label: "/" }];

  const save = (): void => {
    const override: AgentConfigOverride = {};
    const scanLines = scan.split("\n").map((s) => s.trim()).filter(Boolean);
    const fbLines = fullbit.split("\n").map((s) => s.trim()).filter(Boolean);
    const exLines = exclude.split("\n").map((s) => s.trim()).filter(Boolean);
    if (scanLines.length) override.scan_scope = scanLines;
    if (fbLines.length) override.fullbit_scope = fbLines;
    if (exLines.length) override.exclude_scope = exLines;
    if (cross !== "inherit") override.cross_mounts = cross === "on";
    if (throttle.trim()) {
      try {
        override.throttle = JSON.parse(throttle) as Record<string, unknown>;
      } catch {
        setJsonError("Throttle must be valid JSON (or leave it blank to not override).");
        return;
      }
    }
    setJsonError(null);
    setConfig.mutate({ hostId: host.id, override });
  };

  return (
    <div className="fathom-agent-config">
      <div className="fathom-agent-config-cols">
        <div>
          <h4>Effective config (reported by the agent)</h4>
          {eff ? (
            <dl className="fathom-deflist">
              <dt>Scan scope</dt>
              <dd className="fathom-path">{cfgList(eff, "scan_scope").join(", ") || "—"}</dd>
              <dt>Deep-scan (full-bit) scope</dt>
              <dd className="fathom-path">{cfgList(eff, "fullbit_scope").join(", ") || "—"}</dd>
              <dt>Excluded (pruned)</dt>
              <dd className="fathom-path">{cfgList(eff, "exclude_scope").join(", ") || "—"}</dd>
              <dt>Cross-mounts</dt>
              <dd>{String(eff.cross_mounts ?? "—")}</dd>
              <dt>Write enabled</dt>
              <dd>{String(eff.write_enabled ?? "—")}</dd>
              <dt>Throttle</dt>
              <dd>
                <pre className="fathom-codeblock">{JSON.stringify(eff.throttle ?? {}, null, 2)}</pre>
              </dd>
            </dl>
          ) : (
            <p className="fathom-muted">
              Not reported yet — this host&rsquo;s agent predates config reporting (ADR-033). It will
              appear after the agent runs on the updated image.
            </p>
          )}
        </div>

        {canManage ? (
          <div>
            <h4>Override (applied on the agent&rsquo;s next run)</h4>
            <p className="fathom-muted fathom-hint">
              Blank field = don&rsquo;t override. The agent re-validates + applies fail-safe.
            </p>
            {hostVolumes.length ? (
              <label className="fathom-field">
                Add a mounted volume to scan scope
                <select
                  value=""
                  onChange={(e) => {
                    if (e.target.value) appendPath(scan, setScan, e.target.value);
                  }}
                >
                  <option value="">Choose a volume…</option>
                  {hostVolumes.map((v) => (
                    <option key={v.id} value={v.mountpoint}>
                      {v.mountpoint} ({v.fs_type})
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
            <div className="fathom-tree-controls">
              <button
                type="button"
                className="fathom-btn fathom-btn-mini"
                aria-expanded={showTree}
                onClick={() => setShowTree((v) => !v)}
              >
                {showTree ? "Hide explorer" : "Explore live…"}
              </button>
              <span className="fathom-muted fathom-hint">
                Browse the host&rsquo;s real folders (incl. un-scanned) to pick scan/exclude paths.
              </span>
            </div>
            {showTree ? (
              <div className="fathom-tree-wrap">
                <DirTree
                  roots={treeRoots}
                  browse={(path) => browseHost.mutateAsync({ hostId: host.id, path })}
                  onInclude={(path) => appendPath(scan, setScan, path)}
                  onExclude={(path) => appendPath(exclude, setExclude, path)}
                />
              </div>
            ) : null}
            <label className="fathom-field">
              Scan scope (one path per line)
              <textarea rows={3} value={scan} onChange={(e) => setScan(e.target.value)} />
            </label>
            <label className="fathom-field">
              Deep-scan scope (subset of scan scope; one per line)
              <textarea rows={2} value={fullbit} onChange={(e) => setFullbit(e.target.value)} />
            </label>
            <label className="fathom-field">
              Exclude (subtrees to skip; one path per line — e.g. a volume&rsquo;s mountpoint above,
              then a sub-folder here)
              <textarea rows={2} value={exclude} onChange={(e) => setExclude(e.target.value)} />
            </label>
            <label className="fathom-field">
              Cross-mounts
              <select value={cross} onChange={(e) => setCross(e.target.value as "inherit" | "on" | "off")}>
                <option value="inherit">don&rsquo;t override</option>
                <option value="on">on</option>
                <option value="off">off</option>
              </select>
            </label>
            <label className="fathom-field">
              Throttle (JSON; blank = don&rsquo;t override)
              <textarea rows={4} value={throttle} onChange={(e) => setThrottle(e.target.value)} />
            </label>
            {jsonError ? <p role="alert" className="fathom-inline-error">{jsonError}</p> : null}
            {setConfig.isError ? (
              <p role="alert" className="fathom-inline-error">
                {setConfig.error instanceof ApiError
                  ? (setConfig.error.problem.detail ?? "Save failed.")
                  : "Save failed."}
              </p>
            ) : null}
            {setConfig.isSuccess ? (
              <p role="status" className="fathom-inline-ok">Saved — applies on the next run.</p>
            ) : null}
            <div className="fathom-toolbar-controls">
              <button type="button" className="fathom-btn fathom-btn-primary" onClick={save} disabled={setConfig.isPending}>
                {setConfig.isPending ? "Saving…" : "Save override"}
              </button>
              <button
                type="button"
                className="fathom-btn"
                disabled={setConfig.isPending || !desired}
                onClick={() => setConfig.mutate({ hostId: host.id, override: {} })}
              >
                Clear override
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

// One host card: status badge + a meta line, the host's volumes as friendly rows with size + a
// per-volume "Scan now", a host-level "Scan now", and the advanced config behind a disclosure.
function HostCard({
  host,
  volumes,
  volumeLabel,
  canManage,
  canScan,
}: {
  host: HostOut;
  volumes: VolumeOut[];
  volumeLabel: (volumeId: number) => string;
  canManage: boolean;
  canScan: boolean;
}): JSX.Element {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const status = hostStatus(host);
  const badge = STATUS_BADGE[status];
  const statusLabel =
    status === "partial" ? `partial (${host.last_run_scopes_failed ?? 0})` : badge.label;
  const active = isActive(host);
  const hostVolumes = volumes.filter((v) => v.host_id === host.id);

  // Candidate roots for the host-level scan: the agent's registered scan scope ∪ its mounted
  // volumes (deduped), else "/" so there's always something to dispatch.
  const rootPaths = Array.from(
    new Set([...cfgList(host.reported_config, "scan_scope"), ...hostVolumes.map((v) => v.mountpoint)]),
  );
  const agentRoots = rootPaths.length
    ? rootPaths.map((p) => ({ path: p, label: p }))
    : [{ path: "/", label: "whole host (/)" }];

  const lastScan = host.last_run_finished_at
    ? formatDate(host.last_run_finished_at)
    : host.last_seen
      ? formatDate(host.last_seen)
      : "never";

  return (
    <article className="fathom-card" aria-labelledby={`host-${host.id}-name`}>
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h2 id={`host-${host.id}-name`} className="fathom-card-title">
            {host.name}
          </h2>
          <span className={`fathom-badge ${badge.cls}`} title={lastRunTitle(host)}>
            {statusLabel}
          </span>
        </div>
        <p className="fathom-muted text-xs">
          {host.os ?? "unknown OS"} · agent {host.agent_version ?? "—"} ·{" "}
          {host.volume_count ?? hostVolumes.length} volume(s) · {active ? "active" : "idle"} · last
          scan {lastScan}
        </p>
      </header>

      {hostVolumes.length ? (
        <ul className="flex flex-col gap-1">
          {hostVolumes.map((v) => (
            <li
              key={v.id}
              className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 py-1 last:border-b-0"
            >
              <span className="flex flex-wrap items-center gap-2">
                <span className="fathom-path">
                  {host.name}: {volumeLabel(v.id)}
                </span>
                <DriveBadge fs_type={v.fs_type} transport={v.transport} />
              </span>
              <span className="flex flex-wrap items-center gap-3">
                <span className="fathom-muted tabular-nums text-xs">
                  {formatBytes(v.used)} of {formatBytes(v.total)} ({formatBytes(v.free)} free)
                </span>
                {canScan ? (
                  <ScanNowControl
                    hostId={host.id}
                    roots={[{ path: v.mountpoint, label: volumeLabel(v.id) }]}
                  />
                ) : null}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="fathom-muted text-sm">
          {host.volume_count
            ? `${host.volume_count} volume(s) catalogued — open the Volumes view for usage detail.`
            : "No catalogued volumes yet."}
        </p>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2">
        {canScan ? (
          <span className="flex flex-wrap items-center gap-1">
            <span className="fathom-muted text-xs">Scan this host:</span>
            <ScanNowControl hostId={host.id} roots={agentRoots} />
          </span>
        ) : (
          <span />
        )}
        <button
          type="button"
          className="fathom-disclosure"
          aria-expanded={showAdvanced}
          onClick={() => setShowAdvanced((v) => !v)}
        >
          {showAdvanced ? "▾ Hide advanced" : "▸ Advanced (agent config)"}
        </button>
      </div>

      {showAdvanced ? <HostConfigPanel host={host} canManage={canManage} /> : null}
    </article>
  );
}

export function Agents(): JSX.Element {
  const me = useWhoAmI();
  // Fleet health is metadata-readable; certificate enrol/revoke + config overrides need
  // MANAGE_AGENTS (admin). Scan Now is separately gated on TRIGGER_METADATA_SCAN (operator+) to
  // match the backend — an operator who can trigger scans gets the button even without admin.
  const canRead = principalHas(me.data, "view_metadata");
  const canManage = principalHas(me.data, "manage_agents");
  const canScan = principalHas(me.data, "trigger_metadata_scan");
  const agents = useAgents(canRead);
  const volumes = useVolumes();
  const { volumeLabel } = useNames();

  return (
    <section aria-labelledby="agents-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="agents-title">Agents</h1>
        <p className="fathom-muted">
          Collector fleet health, grouped by host. Agents are <strong>scheduled scanners</strong> —
          they push when a scan runs, not continuously, so a host&rsquo;s badge reflects its{" "}
          <em>last scan run</em> (ok / partial / failed / never) and <em>idle</em> just means no
          recent scan, not an error. Enrol/revoke and config overrides are admin-gated
          {canManage ? "" : " and not available to your role"}. Open <em>Advanced</em> on a host to
          see the config its agent is running{canManage ? " and set an override applied on its next run" : ""}.
        </p>
      </header>

      <QueryState
        isLoading={agents.isLoading}
        isError={agents.isError}
        error={agents.error}
        isEmpty={(agents.data?.length ?? 0) === 0}
        emptyLabel="No agents have registered with this core yet."
      >
        <div className="flex flex-col gap-4">
          {(agents.data ?? []).map((host) => (
            <HostCard
              key={host.id}
              host={host}
              volumes={volumes.data ?? []}
              volumeLabel={volumeLabel}
              canManage={canManage}
              canScan={canScan}
            />
          ))}
        </div>
      </QueryState>
    </section>
  );
}
