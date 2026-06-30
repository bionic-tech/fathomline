// Audit (frontend ADD §4, ADD 03 §8): the hash-chained, append-only action log. READ_AUDIT-
// gated (auditor/admin) — the page is hidden from the nav and refuses to query for principals
// without the capability. Each row shows who/when/what/result plus the chain hashes; a
// client-side continuity check flags any row whose prev_hash does not match the previous row's
// row_hash (a tamper-evidence hint; the server is authoritative on the real chain).

import { useState } from "react";

import { useAudit, useWhoAmI } from "../../api/queries";
import { principalHas } from "../../auth/rbac";
import type { AuditRecordOut } from "../../api/types";
import { semanticBadgeClass } from "../../lib/badge";
import { formatDate } from "../../lib/format";
import { QueryState } from "../common/QueryState";
import { Tabs, type TabDef } from "../common/Tabs";

function chainBroken(rows: AuditRecordOut[]): Set<number> {
  // Rows arrive newest-first or oldest-first depending on the server; we sort by id ascending
  // for the continuity check so prev_hash[n] must equal row_hash[n-1].
  const ordered = [...rows].sort((a, b) => a.id - b.id);
  const broken = new Set<number>();
  for (let i = 1; i < ordered.length; i += 1) {
    if (ordered[i].prev_hash !== ordered[i - 1].row_hash) broken.add(ordered[i].id);
  }
  return broken;
}

export function Audit(): JSX.Element {
  const me = useWhoAmI();
  const canRead = principalHas(me.data, "read_audit");
  const [cursor, setCursor] = useState<string | null>(null);
  const audit = useAudit(cursor, canRead);

  if (me.data && !canRead) {
    return (
      <section aria-labelledby="audit-title" className="fathom-page">
        <h1 id="audit-title">Audit</h1>
        <p className="fathom-muted">The audit log is restricted to auditors and admins.</p>
      </section>
    );
  }

  const rows = audit.data?.items ?? [];
  const broken = chainBroken(rows);

  const logPanel = (
    <>
      <QueryState
        isLoading={audit.isLoading}
        isError={audit.isError}
        error={audit.error}
        isEmpty={rows.length === 0}
        emptyLabel="No audit records on this page."
      >
        <table className="fathom-table">
          <caption className="sr-only">Hash-chained audit records</caption>
          <thead>
            <tr>
              <th scope="col">When</th>
              <th scope="col">Actor</th>
              <th scope="col">Action</th>
              <th scope="col">Target</th>
              <th scope="col">Result</th>
              <th scope="col">Row hash</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className={broken.has(r.id) ? "fathom-row-broken" : undefined}>
                <td>{formatDate(r.ts)}</td>
                <td>{r.actor}</td>
                <td className="fathom-mono">{r.action}</td>
                <td className="fathom-path">{r.target}</td>
                <td>
                  <span className={`fathom-badge ${semanticBadgeClass(r.result)}`}>{r.result}</span>
                </td>
                <td className="fathom-hash" title={r.row_hash}>
                  {r.row_hash.slice(0, 12)}…
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </QueryState>

      <div className="fathom-pager">
        <button
          type="button"
          className="fathom-btn"
          disabled={cursor === null}
          onClick={() => setCursor(null)}
        >
          First page
        </button>
        <button
          type="button"
          className="fathom-btn"
          disabled={!audit.data?.next_cursor}
          onClick={() => setCursor(audit.data?.next_cursor ?? null)}
        >
          Next page
        </button>
      </div>
    </>
  );

  const integrityPanel = (
    <div className="fathom-card">
      <h3 className="fathom-card-title">Tamper-evidence (hash chain)</h3>
      <p className="fathom-muted">
        Every record stores the hash of the one before it, so the log forms a chain: altering or
        removing any past entry breaks every hash after it. The check below re-links the rows on this
        page (<code>prev_hash[n]</code> must equal <code>row_hash[n-1]</code>) as a quick client-side
        hint — the server remains authoritative on the full chain.
      </p>
      {broken.size > 0 ? (
        <p role="alert" className="fathom-inline-error">
          Chain continuity check failed for {broken.size} row(s) on this page — verify server-side.
        </p>
      ) : (
        <p role="status" className="fathom-inline-ok">
          {rows.length > 0
            ? `Chain intact across all ${rows.length} row(s) on this page.`
            : "No records on this page to verify."}
        </p>
      )}
    </div>
  );

  const tabs: TabDef[] = [
    { id: "log", label: "Log", content: logPanel },
    { id: "integrity", label: "Integrity", content: integrityPanel },
  ];

  return (
    <section aria-labelledby="audit-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="audit-title">Audit</h1>
        <p className="fathom-muted">
          Hash-chained, append-only action log. Every mutation is recorded with its before-state
          and result.
        </p>
        {broken.size > 0 ? (
          <p role="alert" className="fathom-inline-error">
            Chain continuity check failed for {broken.size} row(s) on this page — see the Integrity
            tab.
          </p>
        ) : null}
      </header>

      <Tabs tabs={tabs} ariaLabel="Audit sections" />
    </section>
  );
}
