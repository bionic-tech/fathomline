// Changes (frontend ADD §4): the "what changed" churn feed — created / modified / removed paths
// over a time window, from the append-only change_log the incremental reconciliation populates
// (ADR-006). The "why did my disk fill up this week" view. Read-only, scope-filtered; optionally
// narrowed to the currently-selected subtree.

import { useMemo, useState } from "react";

import { useChanges, useVolumes } from "../../api/queries";
import { formatBytes, formatDate } from "../../lib/format";
import { useUiStore } from "../../state/uiStore";
import { QueryState } from "../common/QueryState";

const WINDOWS: { label: string; hours: number | null }[] = [
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
  { label: "All", hours: null },
];

const TYPE_BADGE: Record<string, string> = {
  created: "fathom-badge-online",
  modified: "fathom-badge-metadata",
  removed: "fathom-badge-offline",
};

function SignedBytes({ delta }: { delta: number }): JSX.Element {
  if (delta === 0) return <span className="tabular-nums">0 B</span>;
  const sign = delta > 0 ? "+" : "−";
  const cls = delta > 0 ? "fathom-delta-up" : "fathom-delta-down";
  return (
    <span className={`tabular-nums ${cls}`}>
      {sign}
      {formatBytes(Math.abs(delta))}
    </span>
  );
}

export function Changes(): JSX.Element {
  const volumes = useVolumes();
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const selectedPath = useUiStore((s) => s.selectedPath);
  const [winIdx, setWinIdx] = useState(1); // default 7 days
  const [scopeToPath, setScopeToPath] = useState(false);

  // Recompute the `since` ISO timestamp from the chosen window. Derived per render is fine — the
  // query key rounds on the value so it doesn't refetch every second (string changes by the ms,
  // so we floor to the minute for a stable key). The Date.now() impurity is deliberate: "now" is
  // a query parameter anchored when the window changes, not render-stable UI state.
  const since = useMemo(() => {
    const hours = WINDOWS[winIdx].hours;
    if (hours === null) return null;
    // eslint-disable-next-line react-hooks/purity -- intentional time anchor (see above)
    const d = new Date(Date.now() - hours * 3600_000);
    d.setSeconds(0, 0);
    return d.toISOString();
  }, [winIdx]);

  const path = scopeToPath ? selectedPath : null;
  const changes = useChanges(selectedVolumeId, path, since, 500);

  const net = (changes.data ?? []).reduce((sum, c) => sum + c.size_delta, 0);
  const volumeLabel =
    volumes.data?.find((v) => v.id === selectedVolumeId)?.mountpoint ?? "the selected volume";

  return (
    <section aria-labelledby="changes-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="changes-title">Changes</h1>
        <p className="fathom-muted">
          What was created, modified, or removed in {volumeLabel} — the churn feed. Net change in
          this window: <SignedBytes delta={net} />.
        </p>
      </header>

      {selectedVolumeId === null ? (
        <p className="fathom-muted">Select a volume from the top bar to see its churn.</p>
      ) : (
        <>
          <div className="fathom-toolbar">
            <div className="fathom-toolbar-controls">
              <label className="fathom-inline-field">
                Window
                <select value={winIdx} onChange={(e) => setWinIdx(Number(e.target.value))}>
                  {WINDOWS.map((w, i) => (
                    <option key={w.label} value={i}>
                      {w.label}
                    </option>
                  ))}
                </select>
              </label>
              {selectedPath ? (
                <label className="fathom-inline-checkbox">
                  <input
                    type="checkbox"
                    checked={scopeToPath}
                    onChange={(e) => setScopeToPath(e.target.checked)}
                  />
                  Only under {selectedPath}
                </label>
              ) : null}
            </div>
          </div>

          <QueryState
            isLoading={changes.isLoading}
            isError={changes.isError}
            error={changes.error}
            isEmpty={(changes.data?.length ?? 0) === 0}
            emptyLabel="No recorded changes in this window — churn appears after an incremental re-scan."
          >
            <table className="fathom-table">
              <caption className="sr-only">Change feed for {volumeLabel}</caption>
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Change</th>
                  <th scope="col">Path</th>
                  <th scope="col">Size Δ</th>
                </tr>
              </thead>
              <tbody>
                {(changes.data ?? []).map((c, i) => (
                  <tr key={`${c.path}-${c.ts}-${i}`}>
                    <td>{formatDate(c.ts)}</td>
                    <td>
                      <span
                        className={`fathom-badge ${TYPE_BADGE[c.change_type] ?? "fathom-badge-role"}`}
                      >
                        {c.change_type}
                      </span>
                    </td>
                    <td className="fathom-path">{c.path}</td>
                    <td>
                      <SignedBytes delta={c.size_delta} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </QueryState>
        </>
      )}
    </section>
  );
}
