// Scans (frontend ADD §4): snapshot/scan history per volume — immutable scan runs with mode,
// start/finish, totals, and the operator's impact acknowledgement. Operators (TRIGGER_FULLBIT_
// SCAN) also get the impact-ACK request form; the non-impact contract requires the ack to name
// the backing device class, which the server re-validates (the heavy full-bit pass runs on the
// owning host's agent — this only records intent, ADD 02; report-only, no write here).

import { useState } from "react";

import { ApiError } from "../../api/client";
import { useCreateFullBitScan, useScans, useVolumes, useWhoAmI } from "../../api/queries";
import { principalHas } from "../../auth/rbac";
import { formatBytes, formatDate } from "../../lib/format";
import { useUiStore } from "../../state/uiStore";
import { QueryState } from "../common/QueryState";
import { Tabs, type TabDef } from "../common/Tabs";

// Friendlier labels for the two scan modes (the API uses the internal terms metadata/fullbit).
const MODE_LABEL: Record<string, string> = { metadata: "Metadata (fast)", fullbit: "Deep — content fingerprint" };
const modeLabel = (mode: string): string => MODE_LABEL[mode] ?? mode;

function FullBitRequestForm({ volumeId }: { volumeId: number }): JSX.Element {
  const create = useCreateFullBitScan();
  const [ack, setAck] = useState("");

  const onSubmit = (e: React.FormEvent): void => {
    e.preventDefault();
    create.mutate({ volume_id: volumeId, impact_ack: ack.trim() });
  };

  return (
    <form className="fathom-form" onSubmit={onSubmit} aria-label="Request deep (full-bit) scan">
      <label className="fathom-field">
        Confirm you understand the impact
        <span className="fathom-muted fathom-hint">
          A deep scan reads <strong>every byte</strong> of every file to fingerprint it — heavy,
          sustained disk I/O that can take hours on a large or slow volume. Type a short note naming
          the backing storage so it&rsquo;s clear you&rsquo;ve considered the impact (the server
          requires it; the agent also backs off automatically under load).
        </span>
        <input
          type="text"
          value={ack}
          minLength={8}
          required
          placeholder='e.g. "nas-1 tank ZFS — off-peak; reads all bytes, expect heavy IO"'
          onChange={(e) => setAck(e.target.value)}
        />
      </label>
      <button type="submit" className="fathom-btn fathom-btn-primary" disabled={create.isPending}>
        {create.isPending ? "Requesting…" : "Request deep scan"}
      </button>
      {create.isError ? (
        <p role="alert" className="fathom-inline-error">
          {create.error instanceof ApiError
            ? (create.error.problem.detail ?? create.error.problem.title ?? "Request failed.")
            : "Request failed."}
        </p>
      ) : null}
      {create.isSuccess ? (
        <p role="status" className="fathom-inline-ok">
          Recorded. The owning host&rsquo;s agent runs the deep pass on its schedule.
        </p>
      ) : null}
    </form>
  );
}

export function Scans(): JSX.Element {
  const me = useWhoAmI();
  const canRead = principalHas(me.data, "view_metadata");
  const canTrigger = principalHas(me.data, "trigger_fullbit_scan");
  const volumes = useVolumes();
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const scans = useScans(selectedVolumeId, canRead);

  const volumeLabel =
    volumes.data?.find((v) => v.id === selectedVolumeId)?.mountpoint ?? "the selected volume";

  return (
    <section aria-labelledby="scans-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="scans-title">Scans</h1>
        <p className="fathom-muted">
          Snapshot history for {volumeLabel}. Snapshots are append-only — this is how
          growth-over-time and &ldquo;what changed&rdquo; stay possible.
        </p>
        <details className="fathom-explainer">
          <summary>What&rsquo;s the difference between a metadata scan and a deep scan?</summary>
          <p>
            A <strong>metadata scan</strong> is the fast, routine one: it records each file&rsquo;s
            name, size, and dates (it never opens file contents), powering the Explorer, sizes, and
            growth charts.
          </p>
          <p>
            A <strong>deep scan</strong> (internally &ldquo;full-bit&rdquo;) additionally reads
            <strong> every byte</strong> of each file to compute a content fingerprint (BLAKE3
            hash). That fingerprint is what makes <strong>duplicate detection</strong> possible —
            two files are true duplicates only if their contents match. Because it reads everything,
            it&rsquo;s heavy I/O, so it&rsquo;s opt-in per volume and requires the impact note below.
          </p>
        </details>
      </header>

      {selectedVolumeId === null ? (
        <p className="fathom-muted">Select a volume from the top bar to see its scan history.</p>
      ) : (
        <ScansBody volumeId={selectedVolumeId} volumeLabel={volumeLabel} canTrigger={canTrigger}>
          <QueryState
            isLoading={scans.isLoading}
            isError={scans.isError}
            error={scans.error}
            isEmpty={(scans.data?.length ?? 0) === 0}
            emptyLabel="No scans recorded for this volume yet."
          >
            <table className="fathom-table">
              <caption className="sr-only">Scan history for {volumeLabel}</caption>
              <thead>
                <tr>
                  <th scope="col">Snapshot</th>
                  <th scope="col">Mode</th>
                  <th scope="col">Started</th>
                  <th scope="col">Finished</th>
                  <th scope="col">Entries</th>
                  <th scope="col">On-disk</th>
                </tr>
              </thead>
              <tbody>
                {(scans.data ?? []).map((s) => (
                  <tr key={s.id}>
                    <td className="tabular-nums">{s.id}</td>
                    <td>
                      <span className={`fathom-badge fathom-badge-${s.mode}`}>{modeLabel(s.mode)}</span>
                    </td>
                    <td>{s.started_at ? formatDate(s.started_at) : "—"}</td>
                    <td>{s.finished_at ? formatDate(s.finished_at) : "running…"}</td>
                    <td className="tabular-nums">{s.entry_count?.toLocaleString() ?? "—"}</td>
                    <td className="tabular-nums">
                      {s.total_size_on_disk != null ? formatBytes(s.total_size_on_disk) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </QueryState>
        </ScansBody>
      )}
    </section>
  );
}

// Operators get a tabbed layout — History (the snapshot table) by default, with the heavy deep-scan
// request form tucked behind its own tab so it doesn't push the table below the fold. Read-only
// viewers (no TRIGGER_FULLBIT_SCAN) just see the history table, no tabs.
function ScansBody({
  volumeId,
  volumeLabel,
  canTrigger,
  children,
}: {
  volumeId: number;
  volumeLabel: string;
  canTrigger: boolean;
  children: JSX.Element;
}): JSX.Element {
  if (!canTrigger) return children;
  const tabs: TabDef[] = [
    { id: "history", label: "History", content: children },
    {
      id: "deep",
      label: "Deep scan",
      content: (
        <section aria-label="Request a deep scan" className="fathom-card">
          <h2 className="fathom-card-title">Request a deep scan (content fingerprint)</h2>
          <FullBitRequestForm volumeId={volumeId} />
        </section>
      ),
    },
  ];
  return <Tabs tabs={tabs} ariaLabel={`Scan sections for ${volumeLabel}`} />;
}
