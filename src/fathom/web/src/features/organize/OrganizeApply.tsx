// Organize apply (ADR-023): turn an approved subset of a reorganisation proposal into a
// reversible MOVE plan, then drive it through the SAME gated remediation spine the dedup wizard
// uses — build → dry-run (drift check) → step-up MFA → execute. Moves preserve the inode (a
// one-step undo) and are default-OFF on the server, so this fails closed with a clear message when
// organize/remediation isn't enabled. Every act is hash-chain audited (Audit page).

import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ApiError } from "../../api/client";
import {
  useAgents,
  useDryRunPlan,
  useExecutePlan,
  useMfaVerify,
  useOrganizePlan,
} from "../../api/queries";
import type { DryRunOut, ExecuteOut, OrganizeItemOut, OrganizePlanOut } from "../../api/types";
import { DangerAck } from "../common/DangerAck";

type Step = "select" | "review" | "drift" | "ack" | "mfa" | "done";

function gateMessage(e: unknown): string | null {
  if (e instanceof ApiError) {
    if (e.status === 403)
      return "Applying is disabled on this server (organize/remediation off) or you lack the remediation capability.";
    if (e.status === 503) return "The remediation runtime is not provisioned on this server.";
  }
  return null;
}

function errorText(e: unknown, fallback: string): string {
  return (
    gateMessage(e) ??
    (e instanceof ApiError ? (e.problem.detail ?? e.problem.title ?? fallback) : fallback)
  );
}

export interface OrganizeApplyProps {
  volumeId: number;
  root: string;
  /** The "move" items from the reviewed proposal (rejected/keep items are not applicable). */
  moves: OrganizeItemOut[];
}

export function OrganizeApply({ volumeId, root, moves }: OrganizeApplyProps): JSX.Element {
  const qc = useQueryClient();
  const agents = useAgents();
  const build = useOrganizePlan();
  const dryRun = useDryRunPlan();
  const execute = useExecutePlan();
  const mfa = useMfaVerify();

  const [step, setStep] = useState<Step>("select");
  const [selected, setSelected] = useState<Set<number>>(() => new Set(moves.map((m) => m.entry_id)));
  const [plan, setPlan] = useState<OrganizePlanOut | null>(null);
  const [drift, setDrift] = useState<DryRunOut | null>(null);
  const [result, setResult] = useState<ExecuteOut | null>(null);
  const [code, setCode] = useState("");
  const [confirmHost, setConfirmHost] = useState("");
  const [error, setError] = useState<string | null>(null);

  const hostName =
    agents.data?.find((a) => String(a.id) === plan?.host_id)?.name ?? plan?.host_id ?? "";

  const toggle = (entryId: number): void => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(entryId)) next.delete(entryId);
      else next.add(entryId);
      return next;
    });
  };

  const doBuild = async (): Promise<void> => {
    setError(null);
    const picked = moves.filter((m) => selected.has(m.entry_id));
    if (picked.length === 0) {
      setError("Select at least one file to move.");
      return;
    }
    try {
      const p = await build.mutateAsync({
        volume_id: volumeId,
        path: root,
        moves: picked.map((m) => ({ entry_id: m.entry_id, dest_rel: m.proposed_relpath })),
      });
      setPlan(p);
      setStep("review");
    } catch (e) {
      setError(errorText(e, "Failed to build the move plan."));
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
        confirmBlast: false,
        confirmHost: host,
      });
      setResult(r);
      setStep("done");
      void qc.invalidateQueries({ queryKey: ["audit"] });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setStep("mfa"); // step-up MFA required before the destructive act
        return;
      }
      setError(errorText(e, "Apply failed."));
    }
  };

  const onAckConfirm = (typedHost: string): void => {
    setConfirmHost(typedHost);
    void doExecute(typedHost);
  };

  const doVerifyMfa = async (): Promise<void> => {
    setError(null);
    try {
      await mfa.mutateAsync(code.trim());
      await doExecute(confirmHost); // retry now that step-up is fresh
    } catch (e) {
      setError(errorText(e, "Invalid code. Enrol TOTP in Settings if you have not yet."));
    }
  };

  const movedCount = result?.results.filter((r) => r.status === "moved").length ?? 0;

  return (
    <section className="fathom-apply-panel" aria-labelledby="organize-apply-title">
      <h2 id="organize-apply-title">Apply moves</h2>
      {error ? (
        <p role="alert" className="fathom-inline-error">
          {error}
        </p>
      ) : null}

      {step === "select" ? (
        <>
          <p className="fathom-muted">
            Choose which proposed moves to apply. Each is a <strong>reversible</strong> relocation
            within this folder (the inode is preserved); a dry-run + step-up MFA gate the act.
          </p>
          <fieldset className="fathom-keeper-list">
            <legend className="sr-only">Moves to apply</legend>
            {moves.map((m) => (
              <label key={m.entry_id} className="fathom-keeper-row">
                <input
                  type="checkbox"
                  checked={selected.has(m.entry_id)}
                  onChange={() => toggle(m.entry_id)}
                />
                <span className="fathom-path">{m.current_name}</span>
                <span className="fathom-muted"> → </span>
                <span className="fathom-path fathom-delta-down">{m.proposed_relpath}</span>
              </label>
            ))}
          </fieldset>
          <footer className="fathom-modal-foot">
            <button
              type="button"
              className="fathom-btn fathom-btn-primary"
              disabled={build.isPending || selected.size === 0}
              onClick={() => void doBuild()}
            >
              {build.isPending ? "Building…" : `Build move plan (${selected.size})`}
            </button>
          </footer>
        </>
      ) : null}

      {step === "review" && plan ? (
        <>
          <dl className="fathom-keyvals">
            <dt>Within</dt>
            <dd className="fathom-path">{plan.move_root}</dd>
            <dt>Moves</dt>
            <dd className="tabular-nums">{plan.blast_count} file(s)</dd>
          </dl>
          <ul className="fathom-plan-items">
            {plan.items.map((it) => (
              <li key={it.entry_id} className="fathom-path">
                {it.path} → {it.dest_rel}
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
              Verified — every file still matches what was scanned. Safe to move.
            </p>
          ) : (
            <>
              <p role="alert" className="fathom-inline-error">
                {drift.drifted.length} file(s) changed since the scan — those are blocked (TOCTOU
                guard). Re-scan and rebuild.
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
              Apply moves…
            </button>
          </footer>
        </>
      ) : null}

      {step === "ack" && plan ? (
        <DangerAck
          hostName={hostName}
          paths={plan.items.map((it) => it.path)}
          actionLabel="move"
          pending={execute.isPending}
          onConfirm={onAckConfirm}
          onCancel={() => setStep("drift")}
        />
      ) : null}

      {step === "mfa" ? (
        <>
          <p className="fathom-muted">
            Step-up MFA is required before a write action. Enter your current authenticator code.
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
              {mfa.isPending || execute.isPending ? "Verifying…" : "Verify & move"}
            </button>
          </form>
        </>
      ) : null}

      {step === "done" && result ? (
        <>
          <p role="status" className="fathom-inline-ok">
            Done. {movedCount} file(s) moved (reversible — the inode is preserved). The action is on
            the Audit log.
          </p>
          <ul className="fathom-plan-items">
            {result.results.map((r) => (
              <li key={r.entry_id}>
                {r.status}: {r.action} #{r.entry_id}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}
