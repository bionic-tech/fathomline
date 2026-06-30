// Dashboard (frontend ADD §4): estate KPI header, per-volume capacity, an interactive
// composition view (treemap ⇄ sunburst, click-to-drill with a breadcrumb), and growth trend.
// Every chart fetches a server-capped/downsampled dataset and renders its a11y data-table
// alternative via the ChartAdapter (frontend ADD §9/§10).

import { useState } from "react";

import {
  useAgents,
  useDuplicatesSummary,
  useHistorySeries,
  useTreemap,
  useVolumes,
} from "../../api/queries";
import { GrowthSeries } from "../../charts/GrowthSeries";
import { Sunburst } from "../../charts/Sunburst";
import { Treemap } from "../../charts/Treemap";
import { VolumeUsageChart } from "../../charts/VolumeUsageChart";
import type { VolumeOut } from "../../api/types";
import { formatBytes, formatBytesExact } from "../../lib/format";
import { useUiStore } from "../../state/uiStore";
import { Breadcrumbs } from "../common/Breadcrumbs";
import { Tabs, type TabDef } from "../common/Tabs";

// Estate inventory modal — which hosts exist and which volumes live on each, so you can see at a
// glance "nas-1 has tank + nextcloud-data" etc. (answers "where does this data live?").
function InventoryModal({
  volumes,
  hostName,
  onClose,
}: {
  volumes: VolumeOut[];
  hostName: (hostId: number) => string;
  onClose: () => void;
}): JSX.Element {
  const byHost = new Map<number, VolumeOut[]>();
  for (const v of volumes) {
    const list = byHost.get(v.host_id) ?? [];
    list.push(v);
    byHost.set(v.host_id, list);
  }
  const hosts = [...byHost.entries()].sort((a, b) => hostName(a[0]).localeCompare(hostName(b[0])));
  return (
    <div className="fathom-modal-backdrop" role="presentation" onClick={onClose}>
      <div className="fathom-modal" role="dialog" aria-modal="true" aria-label="Estate inventory" onClick={(e) => e.stopPropagation()}>
        <header className="fathom-modal-head">
          <h2>Estate inventory — {hosts.length} host(s), {volumes.length} volume(s)</h2>
        </header>
        <div className="fathom-inv-body">
          {hosts.map(([hostId, vols]) => {
            const used = vols.reduce((s, v) => s + v.used, 0);
            return (
              <div key={hostId} className="fathom-inv-host">
                <h3>
                  {hostName(hostId)} <span className="fathom-muted">— {vols.length} volume(s), {formatBytes(used)} used</span>
                </h3>
                <table className="fathom-table">
                  <thead>
                    <tr><th>Volume</th><th>Type</th><th>Used</th><th>Capacity</th></tr>
                  </thead>
                  <tbody>
                    {vols.map((v) => (
                      <tr key={v.id}>
                        <td className="fathom-path">{v.display_name ?? v.mountpoint}</td>
                        <td>{v.fs_type}</td>
                        <td className="tabular-nums" title={formatBytesExact(v.used)}>{formatBytes(v.used)}</td>
                        <td className="tabular-nums">{v.total > 0 ? formatBytes(v.total) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          })}
        </div>
        <footer className="fathom-modal-foot">
          <button type="button" className="fathom-btn" onClick={onClose}>
            Close
          </button>
        </footer>
      </div>
    </div>
  );
}

function Kpi({
  label,
  value,
  sub,
  title,
}: {
  label: string;
  value: string;
  sub?: string;
  title?: string; // exact figure shown on hover (precision is "one hover away", not a raw inline number)
}): JSX.Element {
  return (
    <div className="fathom-kpi">
      <div className="fathom-kpi-value tabular-nums" title={title}>
        {value}
      </div>
      <div className="fathom-kpi-label">{label}</div>
      {sub ? <div className="fathom-kpi-sub">{sub}</div> : null}
    </div>
  );
}

export function Dashboard(): JSX.Element {
  const volumes = useVolumes();
  const agents = useAgents();
  const dupSummary = useDuplicatesSummary(null); // estate-wide reclaimable headline
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const selectedPath = useUiStore((s) => s.selectedPath);
  const selectVolume = useUiStore((s) => s.selectVolume);
  const selectPath = useUiStore((s) => s.selectPath);
  const treemap = useTreemap(selectedVolumeId, selectedPath, 150);
  const history = useHistorySeries(selectedVolumeId, selectedPath);
  const [view, setView] = useState<"treemap" | "sunburst">("treemap");

  const [showInventory, setShowInventory] = useState(false);
  const selectedVolume = volumes.data?.find((v) => v.id === selectedVolumeId);
  const estateUsed = (volumes.data ?? []).reduce((sum, v) => sum + v.used, 0);
  const estateTotal = (volumes.data ?? []).reduce((sum, v) => sum + v.total, 0);
  const hostCount = agents.data?.length ?? new Set((volumes.data ?? []).map((v) => v.host_id)).size;
  const hostName = (hostId: number): string =>
    agents.data?.find((h) => h.id === hostId)?.name ?? `host ${hostId}`;

  // Drill into a clicked composition node; re-rooting the volume's mountpoint resets to the top.
  const drill = (path: string): void => selectPath(path);
  const resetToVolumeRoot = (): void => {
    if (selectedVolume) selectVolume(selectedVolume.host_id, selectedVolume.id, selectedVolume.mountpoint);
  };

  // The three heavy chart panels become tabs (stop the long scroll, report part 3); the KPI
  // summary stays pinned above so the estate glance is always visible.
  const tabs: TabDef[] = [
    {
      id: "capacity",
      label: "Volume capacity",
      content: (
        <section aria-label="Volume capacity" className="fathom-card">
          {volumes.isError ? (
            <p role="alert" className="fathom-inline-error">
              Couldn't load volumes.{" "}
              <button type="button" className="fathom-btn" onClick={() => void volumes.refetch()}>
                Retry
              </button>
            </p>
          ) : volumes.data ? (
            <VolumeUsageChart volumes={volumes.data} variant="bar" hostName={hostName} />
          ) : (
            <p role="status">Loading volumes…</p>
          )}
        </section>
      ),
    },
    {
      id: "composition",
      label: "Composition",
      content: (
        <section aria-label="Estate composition" className="fathom-card">
          <div className="fathom-card-head">
            <span className="fathom-card-title">Composition</span>
            <div className="fathom-view-toggle" role="group" aria-label="Composition view">
              <button
                type="button"
                className={`fathom-btn ${view === "treemap" ? "fathom-btn-active" : ""}`}
                aria-pressed={view === "treemap"}
                onClick={() => setView("treemap")}
              >
                Treemap
              </button>
              <button
                type="button"
                className={`fathom-btn ${view === "sunburst" ? "fathom-btn-active" : ""}`}
                aria-pressed={view === "sunburst"}
                onClick={() => setView("sunburst")}
              >
                Sunburst
              </button>
            </div>
          </div>
          {selectedVolume && selectedPath ? (
            <Breadcrumbs
              mount={selectedVolume.mountpoint}
              path={selectedPath}
              onNavigate={(p) =>
                p === selectedVolume.mountpoint ? resetToVolumeRoot() : selectPath(p)
              }
            />
          ) : null}
          {treemap.isError ? (
            // Branch on the error BEFORE the empty state: a failed/timed-out query must not be
            // mistaken for "no data — run a scan" (EC-charts-18/19). Offer a retry instead.
            <p role="alert" className="fathom-inline-error">
              Couldn't load composition data.{" "}
              <button type="button" className="fathom-btn" onClick={() => void treemap.refetch()}>
                Retry
              </button>
            </p>
          ) : treemap.data && treemap.data.length > 0 ? (
            view === "treemap" ? (
              <Treemap nodes={treemap.data} onDrill={drill} />
            ) : (
              <Sunburst nodes={treemap.data} onDrill={drill} />
            )
          ) : (
            <p role="status">
              {selectedVolumeId === null
                ? "Select a volume to view its composition."
                : "No composition data — run a scan + finalize for this subtree."}
            </p>
          )}
          <p className="fathom-muted fathom-hint">
            Tip: click a block to drill in; use the breadcrumb to go back up.
          </p>
        </section>
      ),
    },
    {
      id: "growth",
      label: "Growth trend",
      content: (
        <section aria-label="Growth trend" className="fathom-card">
          {history.isError ? (
            <p role="alert" className="fathom-inline-error">
              Couldn't load the growth series.{" "}
              <button type="button" className="fathom-btn" onClick={() => void history.refetch()}>
                Retry
              </button>
            </p>
          ) : history.data && history.data.points.length > 0 ? (
            <GrowthSeries series={history.data} />
          ) : (
            // Branch on selection like the composition panel (EC-charts-19): once a volume IS
            // selected, an empty series means "not enough history yet", not "pick a volume".
            <p role="status">
              {selectedVolumeId === null
                ? "Select a volume to view growth over time."
                : "Not enough history yet — growth appears after a few scans of this volume."}
            </p>
          )}
        </section>
      ),
    },
  ];

  return (
    <section aria-labelledby="dash-title" className="fathom-dashboard">
      <h1 id="dash-title">Estate dashboard</h1>

      <section aria-label="Estate summary" className="fathom-kpi-row">
        <Kpi
          label="Estate used"
          value={formatBytes(estateUsed)}
          title={formatBytesExact(estateUsed)}
          sub={estateTotal > 0 ? `of ${formatBytes(estateTotal)} capacity` : undefined}
        />
        {/* Click to see exactly which hosts + volumes make up the estate. */}
        <button
          type="button"
          className="fathom-kpi-button"
          onClick={() => setShowInventory(true)}
          title="Show hosts and their volumes"
        >
          <Kpi
            label="Volumes ▸"
            value={String(volumes.data?.length ?? "—")}
            sub={`${hostCount} host(s) — click for details`}
          />
        </button>
        <Kpi
          label="Reclaimable (dupes)"
          value={dupSummary.data ? formatBytes(dupSummary.data.total_reclaimable_bytes) : "—"}
          sub={dupSummary.data ? `${dupSummary.data.group_count.toLocaleString()} groups` : undefined}
        />
        <Kpi
          label="Selected volume"
          value={selectedVolume ? formatBytes(selectedVolume.used) : "—"}
          title={selectedVolume ? formatBytesExact(selectedVolume.used) : undefined}
          sub={selectedVolume ? `${hostName(selectedVolume.host_id)} · ${selectedVolume.mountpoint}` : undefined}
        />
      </section>

      {showInventory ? (
        <InventoryModal
          volumes={volumes.data ?? []}
          hostName={hostName}
          onClose={() => setShowInventory(false)}
        />
      ) : null}

      <Tabs tabs={tabs} ariaLabel="Dashboard sections" />
    </section>
  );
}
