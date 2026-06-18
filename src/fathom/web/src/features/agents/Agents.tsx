// Agents (frontend ADD §4): the fleet view — hosts/agents with OS, agent version, volume count
// and a recency badge from last_seen. Enrol/revoke (PKI) is a MANAGE_AGENTS write surface owned by
// a separate component; this page is the read-only fleet health list.
//
// Fathom's agents are SCHEDULED, one-shot scanners (not always-on daemons): they push to the core
// when a scan drains, then exit. So a live "online/offline" heartbeat is the wrong metaphor — a
// host that scanned this morning is healthy, not "offline". We show "active" if it pushed within
// the last day (covers the nightly cadence + an in-progress scan that has drained a batch), else
// "idle", and always show the precise last-seen time.

import { useState } from "react";

import { ApiError } from "../../api/client";
import {
  useAgents,
  useBrowseHost,
  useSetAgentConfig,
  useVolumes,
  useWhoAmI,
} from "../../api/queries";
import { DirTree } from "../common/DirTree";
import { principalHas } from "../../auth/rbac";
import type { AgentConfigOverride, HostOut } from "../../api/types";
import { formatDate } from "../../lib/format";
import { QueryState } from "../common/QueryState";

// "Active" = pushed within this window. 26h spans a daily scan schedule plus clock skew.
const RECENT_WINDOW_MS = 26 * 60 * 60 * 1000;

function isActive(host: HostOut): boolean {
  if (!host.last_seen) return false;
  const seen = new Date(host.last_seen).getTime();
  if (Number.isNaN(seen)) return false;
  return Date.now() - seen <= RECENT_WINDOW_MS;
}

// Map a reported run outcome to a badge class + label. null = the host has never reported a run
// (e.g. only ingested before run-reporting existed) — distinct from a failed run.
const OUTCOME_BADGE: Record<"ok" | "partial" | "failed", string> = {
  ok: "fathom-badge-online",
  partial: "fathom-badge-fullbit",
  failed: "fathom-badge-offline",
};

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

// ADR-033: per-host config — the effective config the agent reported (#9, read-only) + an override
// editor (#10, MANAGE_AGENTS). The override is partial: a blank field is "don't override". The agent
// re-validates + applies it on its NEXT run, fail-safe. write_enabled is shown but not overridable.
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

function HostRow({ host, canManage }: { host: HostOut; canManage: boolean }): JSX.Element {
  const [open, setOpen] = useState(false);
  const active = isActive(host);
  return (
    <>
      <tr>
        <td>
          <button
            type="button"
            className="fathom-disclosure"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
            title="Show this agent's config"
          >
            {open ? "▾" : "▸"} {host.name}
          </button>
        </td>
        <td>
          <span
            className={`fathom-badge ${active ? "fathom-badge-online" : "fathom-badge-offline"}`}
            title={host.last_seen ? `Last scan push: ${formatDate(host.last_seen)}` : "No scan has pushed yet"}
          >
            {active ? "active" : "idle"}
          </span>
        </td>
        <td>
          {host.last_run_outcome ? (
            <span className={`fathom-badge ${OUTCOME_BADGE[host.last_run_outcome]}`} title={lastRunTitle(host)}>
              {host.last_run_outcome === "partial" ? `partial (${host.last_run_scopes_failed ?? 0})` : host.last_run_outcome}
            </span>
          ) : (
            <span className="fathom-muted" title="No scan run reported yet">—</span>
          )}
        </td>
        <td>{host.os ?? "—"}</td>
        <td className="tabular-nums">{host.agent_version ?? "—"}</td>
        <td className="tabular-nums">{host.volume_count ?? "—"}</td>
        <td>{host.last_seen ? formatDate(host.last_seen) : "never"}</td>
      </tr>
      {open ? (
        <tr>
          <td colSpan={7} className="fathom-detail-cell">
            <HostConfigPanel host={host} canManage={canManage} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

export function Agents(): JSX.Element {
  const me = useWhoAmI();
  // Fleet health is metadata-readable; certificate enrol/revoke needs MANAGE_AGENTS (admin).
  const canRead = principalHas(me.data, "view_metadata");
  const canManage = principalHas(me.data, "manage_agents");
  const agents = useAgents(canRead);

  return (
    <section aria-labelledby="agents-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="agents-title">Agents</h1>
        <p className="fathom-muted">
          Collector fleet health. Agents are <strong>scheduled scanners</strong> — they push when a
          scan runs, not continuously, so <em>active</em> means "scanned within the last day" and{" "}
          <em>idle</em> just means no recent scan (not an error). Agents reach only the mTLS ingest
          endpoint; enrol/revoke is admin-gated
          {canManage ? "" : " and not available to your role"}. Expand a host (▸) to see the config
          its agent is running{canManage ? " and set an override applied on its next run" : ""}.
        </p>
      </header>

      <QueryState
        isLoading={agents.isLoading}
        isError={agents.isError}
        error={agents.error}
        isEmpty={(agents.data?.length ?? 0) === 0}
        emptyLabel="No agents have registered with this core yet."
      >
        <table className="fathom-table">
          <caption className="sr-only">Registered hosts and their agents</caption>
          <thead>
            <tr>
              <th scope="col">Host</th>
              <th scope="col">Status</th>
              <th scope="col">Last run</th>
              <th scope="col">OS</th>
              <th scope="col">Agent</th>
              <th scope="col">Volumes</th>
              <th scope="col">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {(agents.data ?? []).map((host) => (
              <HostRow key={host.id} host={host} canManage={canManage} />
            ))}
          </tbody>
        </table>
      </QueryState>
    </section>
  );
}
