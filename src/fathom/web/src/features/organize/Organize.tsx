// Organize (frontend ADD §4, ADR-021/023): content-aware reorganisation for the selected folder.
// It asks the local LLM for a tidier structure and shows a before→after diff (suggest, read-only);
// the operator can then apply an approved subset as a reversible MOVE plan through the gated
// remediation spine (OrganizeApply). Fails closed with a clear message when organize/remediation is
// disabled server-side.

import { ApiError } from "../../api/client";
import { useOrganizeActivity, useOrganizeSuggest, useVolumes } from "../../api/queries";
import type { OrganizeItemOut } from "../../api/types";
import { displayPath } from "../../lib/format";
import { useNames } from "../../lib/names";
import { useUiStore } from "../../state/uiStore";
import { OrganizeApply } from "./OrganizeApply";

const STATUS_BADGE: Record<string, string> = {
  move: "fathom-badge-metadata",
  keep: "fathom-badge-online",
  rejected: "fathom-badge-offline",
};

function gateMessage(e: unknown): string | null {
  if (e instanceof ApiError) {
    if (e.status === 403)
      return (
        "Organize is turned OFF on this server. It's opt-in because it sends a compact digest of " +
        "file names to a local AI model. To enable it, set FATHOM_ORGANIZE_ENABLED=true on the core " +
        "and point FATHOM_INFERENCE_OLLAMA_URL at a reachable Ollama with the model pulled. " +
        "(Or this folder may be out of your scope.)"
      );
    if (e.status === 504)
      return "The model took too long. Try a smaller folder (fewer files), raise the inference timeout, or use a faster/larger model.";
    if (e.status === 503 || e.status === 502)
      return "The local inference model is unavailable — is Ollama running at FATHOM_INFERENCE_OLLAMA_URL and the model pulled?";
  }
  return null;
}

function ProposedCell({ item }: { item: OrganizeItemOut }): JSX.Element {
  if (item.status === "rejected") return <span className="fathom-muted">{item.reason}</span>;
  if (item.status === "keep") return <span className="fathom-muted">— (already well placed)</span>;
  return <span className="fathom-path fathom-delta-down">{item.proposed_relpath}</span>;
}

export function Organize(): JSX.Element {
  const volumes = useVolumes();
  const { hostName } = useNames();
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const selectedPath = useUiStore((s) => s.selectedPath);
  const suggest = useOrganizeSuggest();
  const activity = useOrganizeActivity(selectedVolumeId, selectedPath);

  const volume = volumes.data?.find((v) => v.id === selectedVolumeId);
  const proposal = suggest.data;
  const error = suggest.error;
  const gated = gateMessage(error);
  const nudge = activity.data?.suggests_reorganise ? activity.data : null;

  const run = (): void => {
    if (selectedVolumeId !== null && selectedPath) {
      suggest.mutate({ volumeId: selectedVolumeId, path: selectedPath });
    }
  };

  return (
    <section aria-labelledby="organize-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="organize-title">Organize</h1>
        <p className="fathom-muted">
          A content-aware reorganisation suggestion for the selected folder, from a local model.
          This is a <strong>preview only</strong> — nothing is moved; every target is clamped to the
          folder server-side.
        </p>
        <details className="fathom-explainer">
          <summary>Why might this be disabled?</summary>
          <p>
            Organize is <strong>off by default</strong>: it sends a compact digest of file names to a
            local AI model (Ollama), so it&rsquo;s opt-in. To turn it on, set
            <code> FATHOM_ORGANIZE_ENABLED=true</code> on the core and point
            <code> FATHOM_INFERENCE_OLLAMA_URL</code> at a reachable Ollama with the configured model
            pulled. Suggestions stay preview-only; applying moves is separately gated (MFA).
          </p>
        </details>
      </header>

      {selectedVolumeId === null || !selectedPath ? (
        <p className="fathom-muted">
          Select a volume (and drill to a folder in the Explorer) to get a suggestion.
        </p>
      ) : (
        <>
          <div className="fathom-toolbar">
            <div>
              Organising <span className="fathom-path">{displayPath(selectedPath)}</span>
              {volume ? (
                <span className="fathom-muted"> on {hostName(volume.host_id)} · {volume.display_name ?? displayPath(volume.mountpoint)}</span>
              ) : null}
            </div>
            <button
              type="button"
              className="fathom-btn fathom-btn-primary"
              onClick={run}
              disabled={suggest.isPending}
            >
              {suggest.isPending ? "Thinking…" : "Suggest reorganisation"}
            </button>
          </div>

          {nudge && !proposal ? (
            <p role="status" className="fathom-inline-ok">
              {nudge.created + nudge.modified} new or changed file(s) here in the last{" "}
              {nudge.since_hours}h{nudge.capped ? "+" : ""} — a good moment to re-organise.
            </p>
          ) : null}

          {gated ? (
            <p role="alert" className="fathom-inline-error">
              {gated}
            </p>
          ) : error ? (
            <p role="alert" className="fathom-inline-error">
              {error instanceof ApiError
                ? (error.problem.detail ?? error.problem.title ?? "Suggestion failed.")
                : "Suggestion failed."}
            </p>
          ) : null}

          {proposal ? (
            <>
              <p className="fathom-muted">
                {proposal.considered} file(s) considered ·{" "}
                {proposal.items.filter((i) => i.status === "move").length} to move ·{" "}
                {proposal.rejected} rejected · model <code>{proposal.model}</code>
              </p>
              <table className="fathom-table">
                <caption className="sr-only">Proposed reorganisation of {proposal.root}</caption>
                <thead>
                  <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Current</th>
                    <th scope="col">Proposed</th>
                    <th scope="col">Why</th>
                  </tr>
                </thead>
                <tbody>
                  {proposal.items.map((it) => (
                    <tr key={it.entry_id}>
                      <td>
                        <span className={`fathom-badge ${STATUS_BADGE[it.status] ?? ""}`}>
                          {it.status}
                        </span>
                      </td>
                      <td className="fathom-path">{it.current_name}</td>
                      <td>
                        <ProposedCell item={it} />
                      </td>
                      <td className="fathom-muted">{it.status === "rejected" ? "" : it.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(() => {
                const moves = proposal.items.filter((i) => i.status === "move");
                return moves.length > 0 && selectedVolumeId !== null ? (
                  <OrganizeApply
                    // Re-mount per suggestion so the apply state machine resets cleanly.
                    key={`${proposal.root}:${moves.length}`}
                    volumeId={selectedVolumeId}
                    root={proposal.root}
                    moves={moves}
                  />
                ) : (
                  <p className="fathom-muted fathom-hint">
                    Nothing to apply — the model proposed no moves for this folder.
                  </p>
                );
              })()}
            </>
          ) : null}
        </>
      )}
    </section>
  );
}
