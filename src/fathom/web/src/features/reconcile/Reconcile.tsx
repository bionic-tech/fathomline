// Reconcile (ADR-024): cross-host divergence detection. Pick a DEFINITIVE (volume + folder) — your
// source of truth — and a COMPARISON (volume + folder); the server matches files by their path
// relative to each root and classifies every one: identical, content-same-but-dates-differ,
// DIVERGED (different size/checksum → investigate), size-match-but-unhashed (run a full-bit scan),
// or present-on-only-one-side. Read-only — it flags what drifted; it never moves anything.

import { useState } from "react";

import { ApiError } from "../../api/client";
import { useReconcile, useVolumes } from "../../api/queries";
import type { ReconcileItemOut, ReconcileOut, VolumeOut } from "../../api/types";
import { formatBytes } from "../../lib/format";
import { Tabs, type TabDef } from "../common/Tabs";

const CLASS_LABEL: Record<string, string> = {
  identical: "Identical",
  content_same_meta_diff: "Same content · dates differ",
  diverged: "Diverged (check)",
  size_match_unhashed: "Same size · unhashed",
  missing_on_comparison: "Only on definitive",
  missing_on_definitive: "Only on comparison",
};
const CLASS_BADGE: Record<string, string> = {
  identical: "fathom-badge-online",
  content_same_meta_diff: "fathom-badge-metadata",
  diverged: "fathom-badge-offline",
  size_match_unhashed: "fathom-badge-metadata",
  missing_on_comparison: "fathom-badge-offline",
  missing_on_definitive: "fathom-badge-offline",
};
const ORDER = [
  "diverged",
  "size_match_unhashed",
  "missing_on_comparison",
  "missing_on_definitive",
  "content_same_meta_diff",
  "identical",
];

function VolumePicker({
  volumes,
  value,
  onChange,
  label,
}: {
  volumes: VolumeOut[];
  value: number | null;
  onChange: (id: number) => void;
  label: string;
}): JSX.Element {
  return (
    <label className="fathom-inline-field">
      {label}
      <select
        value={value ?? ""}
        onChange={(e) => onChange(Number(e.target.value))}
        aria-label={`${label} volume`}
      >
        <option value="" disabled>
          Select a volume…
        </option>
        {volumes.map((v) => (
          <option key={v.id} value={v.id}>
            host {v.host_id} · {v.mountpoint}
          </option>
        ))}
      </select>
    </label>
  );
}

function gateMessage(e: unknown): string | null {
  if (e instanceof ApiError) {
    if (e.status === 403) return "One of those volumes is out of your scope.";
    if (e.status === 422) return "A folder path must be absolute and inside the chosen volume.";
    if (e.status === 404) return "Unknown volume.";
    // Too large (413) / timed out (504): the server's detail explains how to narrow the comparison.
    if (e.status === 413 || e.status === 504) {
      return e.problem.detail ?? "That comparison is too large — narrow each side to a subfolder.";
    }
  }
  return null;
}

export function Reconcile(): JSX.Element {
  const volumes = useVolumes();
  const compare = useReconcile();
  const [defVol, setDefVol] = useState<number | null>(null);
  const [defPath, setDefPath] = useState("");
  const [cmpVol, setCmpVol] = useState<number | null>(null);
  const [cmpPath, setCmpPath] = useState("");
  // Bumped on each successful comparison; the Tabs below remount on the new key so a fresh result
  // auto-focuses the Results tab (the form lives in Compare, so re-runs jump back to Results too).
  const [resultKey, setResultKey] = useState(0);

  const vols = volumes.data ?? [];
  const result: ReconcileOut | undefined = compare.data;
  const gate = gateMessage(compare.error);

  const run = (): void => {
    if (defVol !== null && cmpVol !== null && defPath && cmpPath) {
      compare.mutate(
        {
          definitive_volume_id: defVol,
          definitive_path: defPath,
          comparison_volume_id: cmpVol,
          comparison_path: cmpPath,
        },
        { onSuccess: () => setResultKey((k) => k + 1) },
      );
    }
  };

  const ready = defVol !== null && cmpVol !== null && defPath !== "" && cmpPath !== "";

  const comparePanel = (
    <>
      <div className="fathom-reconcile-form">
        <fieldset>
          <legend>Definitive (source of truth)</legend>
          <VolumePicker volumes={vols} value={defVol} onChange={setDefVol} label="Host/volume" />
          <label className="fathom-inline-field">
            Folder
            <input
              type="text"
              placeholder="/scan/nextcloud-data"
              value={defPath}
              onChange={(e) => setDefPath(e.target.value)}
            />
          </label>
        </fieldset>
        <fieldset>
          <legend>Comparison</legend>
          <VolumePicker volumes={vols} value={cmpVol} onChange={setCmpVol} label="Host/volume" />
          <label className="fathom-inline-field">
            Folder
            <input
              type="text"
              placeholder="/scan/ncdata"
              value={cmpPath}
              onChange={(e) => setCmpPath(e.target.value)}
            />
          </label>
        </fieldset>
        <button
          type="button"
          className="fathom-btn fathom-btn-primary"
          onClick={run}
          disabled={!ready || compare.isPending}
        >
          {compare.isPending ? "Comparing…" : "Compare"}
        </button>
      </div>

      {gate ? (
        <p role="alert" className="fathom-inline-error">
          {gate}
        </p>
      ) : compare.error ? (
        <p role="alert" className="fathom-inline-error">
          Comparison failed.
        </p>
      ) : null}
      {result ? (
        <p role="status" className="fathom-inline-ok">
          Comparison complete — see the Results tab.
        </p>
      ) : null}
    </>
  );

  const resultsPanel = result ? (
    <>
      <div className="fathom-reconcile-summary" role="group" aria-label="Counts by class">
        {ORDER.filter((k) => (result.counts[k] ?? 0) > 0).map((k) => (
          <span key={k} className={`fathom-badge ${CLASS_BADGE[k] ?? ""}`}>
            {CLASS_LABEL[k] ?? k}: <strong className="tabular-nums">{result.counts[k]}</strong>
          </span>
        ))}
      </div>
      <p className="fathom-muted">
        {result.considered.toLocaleString()} file(s) compared ·{" "}
        <span className="fathom-path">{result.definitive_root}</span> vs{" "}
        <span className="fathom-path">{result.comparison_root}</span>
      </p>
      {result.items.length > 0 ? (
        <table className="fathom-table">
          <caption className="sr-only">Files needing attention</caption>
          <thead>
            <tr>
              <th scope="col">Status</th>
              <th scope="col">File (relative)</th>
              <th scope="col">Definitive</th>
              <th scope="col">Comparison</th>
            </tr>
          </thead>
          <tbody>
            {result.items.map((it: ReconcileItemOut) => (
              <tr key={`${it.classification}:${it.relpath}`}>
                <td>
                  <span className={`fathom-badge ${CLASS_BADGE[it.classification] ?? ""}`}>
                    {CLASS_LABEL[it.classification] ?? it.classification}
                  </span>
                </td>
                <td className="fathom-path">{it.relpath}</td>
                <td className="tabular-nums">
                  {it.definitive_size === null ? "—" : formatBytes(it.definitive_size)}
                </td>
                <td className="tabular-nums">
                  {it.comparison_size === null ? "—" : formatBytes(it.comparison_size)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p role="status" className="fathom-inline-ok">
          No divergences or one-sided files in the sample — the two trees line up.
        </p>
      )}
      {result.truncated ? (
        <p className="fathom-muted fathom-hint">
          Showing the first {result.items.length} flagged files; the counts above are exact.
        </p>
      ) : null}
    </>
  ) : (
    <p className="fathom-muted">Run a comparison from the Compare tab to see the results here.</p>
  );

  const tabs: TabDef[] = [
    { id: "compare", label: "Compare", content: comparePanel },
    { id: "results", label: "Results", content: resultsPanel },
  ];

  return (
    <section aria-labelledby="reconcile-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="reconcile-title">Reconcile</h1>
        <p className="fathom-muted">
          Compare two copies of a folder across hosts. Pick the <strong>definitive</strong> version
          (your source of truth) and a <strong>comparison</strong>; every file is matched by its path
          within each folder and flagged as identical, same-content-but-dates-differ,{" "}
          <strong>diverged</strong> (different size/checksum), or present on only one side. Read-only
          — nothing is moved. A content verdict needs a full-bit (checksum) scan on both sides.
        </p>
      </header>

      <Tabs
        key={resultKey}
        tabs={tabs}
        ariaLabel="Reconcile sections"
        initialId={resultKey > 0 ? "results" : "compare"}
      />
    </section>
  );
}
