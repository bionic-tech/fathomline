// Danger-zone acknowledgement modal: before any move/delete, the operator must TYPE the target
// host's name to confirm WHICH server they are acting on (GitHub-style). It also shows the risk
// classes the plan touches (OS/service data → a stronger warning). The typed value is sent to the
// server as `confirm_host`, which the server re-validates against the plan's host (this modal is a
// UX aid; the server is the authority) and audits. Step-up MFA is enforced separately by the route.

import { useState } from "react";

import { RISK_META, riskSummary } from "../../lib/riskClass";

export interface DangerAckProps {
  hostName: string; // the host to type to confirm
  paths: string[]; // the affected paths (for the risk summary)
  actionLabel: string; // e.g. "move" / "quarantine"
  pending: boolean;
  onConfirm: (typedHost: string) => void;
  onCancel: () => void;
}

export function DangerAck({
  hostName,
  paths,
  actionLabel,
  pending,
  onConfirm,
  onCancel,
}: DangerAckProps): JSX.Element {
  const [typed, setTyped] = useState("");
  const { classes, highRisk } = riskSummary(paths);
  const matches = typed.trim().toLowerCase() === hostName.trim().toLowerCase() && hostName !== "";

  return (
    <div className="fathom-modal-backdrop" role="presentation" onClick={onCancel}>
      <div
        className="fathom-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="danger-ack-title"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="fathom-modal-head">
          <h2 id="danger-ack-title">Confirm action on a server</h2>
        </header>

        <p className="fathom-muted">
          You are about to <strong>{actionLabel}</strong> {paths.length} file(s) on host{" "}
          <strong className="fathom-path">{hostName || "(unknown)"}</strong>. This changes data on a
          specific server — confirm you mean to.
        </p>

        {classes.length > 0 ? (
          <p className={highRisk ? "fathom-inline-error" : "fathom-muted"} role="alert">
            This plan touches{" "}
            {classes.map((c) => (
              <span key={c} className={`fathom-badge ${RISK_META[c].badge}`}>
                {RISK_META[c].label}
              </span>
            ))}{" "}
            {highRisk
              ? "— operating-system or service data. Deleting/moving it can break the host or its apps. Step-up MFA is required."
              : "— configuration files. Make sure you have a backup."}
          </p>
        ) : null}

        <label className="fathom-inline-field">
          Type the host name <code>{hostName}</code> to confirm
          <input
            type="text"
            autoComplete="off"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            aria-label="Type the host name to confirm"
          />
        </label>

        <footer className="fathom-modal-foot">
          <button type="button" className="fathom-btn" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            className="fathom-btn fathom-btn-danger"
            disabled={!matches || pending}
            onClick={() => onConfirm(typed.trim())}
          >
            {pending ? "Working…" : `Confirm ${actionLabel}`}
          </button>
        </footer>
      </div>
    </div>
  );
}
