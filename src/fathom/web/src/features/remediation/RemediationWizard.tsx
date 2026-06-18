// Remediation wizard (ADR-011): the gated write-mode "reclaim space" flow for one confirmed
// duplicate group. Steps: choose the keeper → build a plan → dry-run drift check → execute
// (quarantine), with step-up MFA enforced server-side before any file is touched. Quarantine is
// reversible; the destructive surface is default-OFF on the server, so this fails closed with a
// clear message when remediation isn't enabled. Every act is hash-chain audited (Audit page).

import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ApiError } from "../../api/client";
import {
  useAgents,
  useBuildPlan,
  useDryRunPlan,
  useDuplicateGroup,
  useExecutePlan,
  useMfaVerify,
} from "../../api/queries";
import type { DuplicateGroupOut, DryRunOut, ExecuteOut, PlanOut } from "../../api/types";
import { formatBytes } from "../../lib/format";
import { DangerAck } from "../common/DangerAck";
import { QueryState } from "../common/QueryState";
import { RiskBadge } from "../common/RiskBadge";

type Step = "choose" | "review" | "drift" | "ack" | "mfa" | "done";

function gateMessage(e: unknown): string | null {
  if (e instanceof ApiError) {
    if (e.status === 403)
      return "Remediation is disabled on this server, or you lack the capability. Enable it via the runbook (deploy) to reclaim space.";
    if (e.status === 503) return "The remediation runtime is not provisioned on this server.";
  }
  return null;
}

function errorText(e: unknown, fallback: string): string {
  return gateMessage(e) ?? (e instanceof ApiError ? (e.problem.detail ?? e.problem.title ?? fallback) : fallback);
}

export interface RemediationWizardProps {
  group: DuplicateGroupOut;
  onClose: () => void;
}

export function RemediationWizard({ group, onClose }: RemediationWizardProps): JSX.Element {
  const detail = useDuplicateGroup(group.id);
  const agents = useAgents();
  const qc = useQueryClient();
  const build = useBuildPlan();
  const dryRun = useDryRunPlan();
  const execute = useExecutePlan();
  const mfa = useMfaVerify();

  const [step, setStep] = useState<Step>("choose");
  const [keeper, setKeeper] = useState<number | null>(group.suggested_keeper_entry_id);
  const [plan, setPlan] = useState<PlanOut | null>(null);
  const [drift, setDrift] = useState<DryRunOut | null>(null);
  const [result, setResult] = useState<ExecuteOut | null>(null);
  const [code, setCode] = useState("");
  const [confirmHost, setConfirmHost] = useState("");
  const [error, setError] = useState<string | null>(null);

  const members = detail.data?.members ?? [];
  // Resolve the plan's host name (the operator must type it to confirm). Fall back to the id.
  const hostName =
    agents.data?.find((a) => String(a.id) === plan?.host_id)?.name ?? plan?.host_id ?? "";

  const doBuild = async (): Promise<void> => {
    if (keeper == null) return;
    setError(null);
    try {
      const p = await build.mutateAsync({ group_id: group.id, keep_entry_id: keeper, action: "quarantine" });
      setPlan(p);
      setStep("review");
    } catch (e) {
      setError(errorText(e, "Failed to build the plan."));
    }
  };

  const doDryRun = async (): Promise<void> => {
    if (!plan) return;
    setError(null);
    try {
      setDrift(await dryRun.mutateAsync(plan.plan_id));
      setStep("drift");
    } catch (e) {
      setError(errorText(e, "Dry-run failed."));
    }
  };

  const doExecute = async (host: string): Promise<void> => {
    if (!plan) return;
    setError(null);
    try {
      const r = await execute.mutateAsync({
        planId: plan.plan_id,
        confirmBlast: true,
        confirmHost: host,
      });
      setResult(r);
      setStep("done");
      void qc.invalidateQueries({ queryKey: ["duplicates"] });
      void qc.invalidateQueries({ queryKey: ["duplicates-summary"] });
      void qc.invalidateQueries({ queryKey: ["audit"] });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setStep("mfa"); // step-up MFA required before the destructive act
        return;
      }
      setError(errorText(e, "Execute failed."));
    }
  };

  // The operator typed the host name in DangerAck → record it and run the guarded execute.
  const onAckConfirm = (typedHost: string): void => {
    setConfirmHost(typedHost);
    void doExecute(typedHost);
  };

  const doVerifyMfa = async (): Promise<void> => {
    setError(null);
    try {
      await mfa.mutateAsync(code.trim());
      setStep("review");
      await doExecute(confirmHost); // retry now that step-up is fresh
    } catch (e) {
      setError(errorText(e, "Invalid code. Enrol TOTP in Settings if you have not yet."));
    }
  };

  return (
    <div className="fathom-modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="fathom-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="rem-title"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="fathom-modal-head">
          <h2 id="rem-title">Reclaim space — {formatBytes(group.reclaimable_bytes)}</h2>
          <button type="button" className="fathom-btn" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        <ol className="fathom-wizard-steps" aria-hidden="true">
          {(["choose", "review", "drift", "done"] as const).map((s) => (
            <li key={s} className={step === s ? "is-active" : undefined}>
              {s === "choose" ? "Keeper" : s === "review" ? "Plan" : s === "drift" ? "Verify" : "Done"}
            </li>
          ))}
        </ol>

        {error ? (
          <p role="alert" className="fathom-inline-error">
            {error}
          </p>
        ) : null}

        {step === "choose" ? (
          <QueryState isLoading={detail.isLoading} isError={detail.isError} error={detail.error}>
            <p className="fathom-muted">
              {group.member_count} identical copies. Choose the one to <strong>keep</strong>; the
              rest are moved to a reversible quarantine.
            </p>
            <fieldset className="fathom-keeper-list">
              <legend className="sr-only">Keeper</legend>
              {members.map((m) => (
                <label key={m.entry_id} className="fathom-keeper-row">
                  <input
                    type="radio"
                    name="keeper"
                    checked={keeper === m.entry_id}
                    onChange={() => setKeeper(m.entry_id)}
                  />
                  <span className="fathom-path">{m.path}</span> <RiskBadge path={m.path} />
                  {group.suggested_keeper_entry_id === m.entry_id ? (
                    <span className="fathom-badge fathom-badge-keeper">suggested</span>
                  ) : null}
                </label>
              ))}
            </fieldset>
            <footer className="fathom-modal-foot">
              <button
                type="button"
                className="fathom-btn fathom-btn-primary"
                disabled={keeper == null || build.isPending}
                onClick={() => void doBuild()}
              >
                {build.isPending ? "Building…" : "Build plan"}
              </button>
            </footer>
          </QueryState>
        ) : null}

        {step === "review" && plan ? (
          <>
            <dl className="fathom-keyvals">
              <dt>Keeper</dt>
              <dd className="fathom-path">{plan.keeper_path}</dd>
              <dt>Quarantines</dt>
              <dd className="tabular-nums">{plan.blast_count} file(s)</dd>
              <dt>Reclaims</dt>
              <dd className="tabular-nums">{formatBytes(plan.reclaimable_bytes)}</dd>
            </dl>
            <ul className="fathom-plan-items">
              {plan.items.map((it) => (
                <li key={it.entry_id} className="fathom-path">
                  {it.action}: {it.path} <RiskBadge path={it.path} />
                </li>
              ))}
            </ul>
            <footer className="fathom-modal-foot">
              <button
                type="button"
                className="fathom-btn fathom-btn-primary"
                disabled={dryRun.isPending}
                onClick={() => void doDryRun()}
              >
                {dryRun.isPending ? "Verifying…" : "Dry-run (verify no drift)"}
              </button>
            </footer>
          </>
        ) : null}

        {step === "drift" && drift ? (
          <>
            {drift.ok ? (
              <p role="status" className="fathom-inline-ok">
                Verified — every file still matches what was approved. Safe to quarantine.
              </p>
            ) : (
              <>
                <p role="alert" className="fathom-inline-error">
                  {drift.drifted.length} file(s) changed since the scan — execution is blocked for
                  those (TOCTOU guard). Re-scan and rebuild.
                </p>
                <ul className="fathom-plan-items">
                  {drift.drifted.map((d) => (
                    <li key={d.entry_id}>
                      {d.entry_id}: {d.reason}
                    </li>
                  ))}
                </ul>
              </>
            )}
            <footer className="fathom-modal-foot">
              <button
                type="button"
                className="fathom-btn fathom-btn-danger"
                disabled={!drift.ok || execute.isPending}
                onClick={() => setStep("ack")}
              >
                Quarantine duplicates…
              </button>
            </footer>
          </>
        ) : null}

        {step === "ack" && plan ? (
          <DangerAck
            hostName={hostName}
            paths={plan.items.map((it) => it.path)}
            actionLabel="quarantine"
            pending={execute.isPending}
            onConfirm={onAckConfirm}
            onCancel={() => setStep("drift")}
          />
        ) : null}

        {step === "mfa" ? (
          <>
            <p className="fathom-muted">
              Step-up MFA is required before a destructive action. Enter your current authenticator
              code.
            </p>
            <form
              className="fathom-form-inline"
              onSubmit={(e) => {
                e.preventDefault();
                void doVerifyMfa();
              }}
            >
              <label className="fathom-inline-field">
                TOTP code
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  minLength={6}
                  maxLength={8}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  required
                />
              </label>
              <button
                type="submit"
                className="fathom-btn fathom-btn-primary"
                disabled={mfa.isPending || execute.isPending}
              >
                {mfa.isPending || execute.isPending ? "Verifying…" : "Verify & quarantine"}
              </button>
            </form>
          </>
        ) : null}

        {step === "done" && result ? (
          <>
            <p role="status" className="fathom-inline-ok">
              Done. {result.results.filter((r) => r.status === "quarantined").length} file(s)
              quarantined (reversible). The action is recorded on the Audit log.
            </p>
            <ul className="fathom-plan-items">
              {result.results.map((r) => (
                <li key={r.entry_id}>
                  {r.status}: {r.action} #{r.entry_id}
                </li>
              ))}
            </ul>
            <footer className="fathom-modal-foot">
              <button type="button" className="fathom-btn fathom-btn-primary" onClick={onClose}>
                Close
              </button>
            </footer>
          </>
        ) : null}
      </div>
    </div>
  );
}
