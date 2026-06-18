// Explorer preview/detail pane (frontend ADD §4, ADR-014).
//
// Shows the full per-entry metadata the scanner captured (owner, modified-time, inode, sizes,
// storage flags, content hash) and, on demand, the sandboxed DERIVED-ARTIFACT preview (image
// thumbnail / PDF first-page raster / text highlight) from GET /api/v1/preview/{entry_id}. The
// viewer NEVER requests or renders raw file bytes — every artifact is a derived transform produced
// inside the gVisor sandbox (security_constraint). Preview is content disclosure and uses sandbox
// resources, so it is fetched only when the operator clicks "Generate preview", not on every select.

import { useState } from "react";

import { ApiError, apiGet } from "../../api/client";
import type { PreviewArtifactOut, PreviewResultOut, TreeChildOut } from "../../api/types";
import { formatBytes, formatBytesExact, formatUnixTime } from "../../lib/format";

// The open FsEntry.flags vocabulary (backends/base.py) → short human labels for the detail pane.
const FLAG_LABELS: Record<string, string> = {
  sparse: "sparse",
  reflink: "reflink (CoW)",
  compressed: "compressed",
  ads: "NTFS ADS",
  synthetic_owner: "no ownership model",
  snapshot_skipped: "snapshot dir skipped",
};

export interface PreviewDetailPaneProps {
  entry: TreeChildOut | null;
}

type PreviewState =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "done"; result: PreviewResultOut }
  | { phase: "error"; message: string };

// Map the route's sanitised problem statuses to friendly, non-leaky copy (no path/stack ever).
function friendlyPreviewError(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 403:
        return "You don't have permission to preview this file.";
      case 404:
        return "This entry is no longer available.";
      case 413:
        return "This file is too large to preview.";
      case 415:
        return "Preview isn't supported for this file type.";
      case 503:
        return "Preview isn't enabled on this server.";
      case 502:
        return "The preview worker is unavailable.";
      case 504:
        return "The preview render timed out.";
      default:
        return "Couldn't generate a preview.";
    }
  }
  return "Couldn't generate a preview.";
}

// Decode base64 → UTF-8 text for the text/code artifacts (rendered as inert <pre>, never as HTML).
function decodeText(b64: string): string {
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function ArtifactView({ artifact }: { artifact: PreviewArtifactOut }): JSX.Element {
  if (artifact.kind === "thumbnail" || artifact.kind === "page_raster") {
    return (
      <img
        className="fathom-preview-image"
        alt={artifact.kind === "thumbnail" ? "Thumbnail" : "First page"}
        src={`data:${artifact.media_type};base64,${artifact.data_b64}`}
      />
    );
  }
  // text_snippet / code_render: derived text only — rendered as preformatted text, never as HTML.
  return <pre className="fathom-preview-text">{decodeText(artifact.data_b64)}</pre>;
}

// Keyed by entry_id at the call site, so React remounts it (fresh "idle" state) when the selection
// changes — no stale preview lingers, and no setState-in-effect (the idiomatic reset is the key).
function PreviewSection({ entryId }: { entryId: number }): JSX.Element {
  const [state, setState] = useState<PreviewState>({ phase: "idle" });

  async function generate(): Promise<void> {
    setState({ phase: "loading" });
    try {
      const result = await apiGet<PreviewResultOut>(`/preview/${entryId}`);
      setState({ phase: "done", result });
    } catch (err) {
      setState({ phase: "error", message: friendlyPreviewError(err) });
    }
  }

  return (
    <section className="fathom-preview-section" aria-label="Preview">
      <div className="fathom-preview-head">
        <h3 className="fathom-detail-subhead">Preview</h3>
        {state.phase !== "done" ? (
          <button
            type="button"
            className="fathom-btn"
            disabled={state.phase === "loading"}
            onClick={() => void generate()}
          >
            {state.phase === "loading" ? "Rendering…" : "Generate preview"}
          </button>
        ) : null}
      </div>
      {state.phase === "idle" ? (
        <p className="fathom-muted">
          Derived artifacts only — the original file is never sent to your browser.
        </p>
      ) : null}
      {state.phase === "error" ? (
        <p role="alert" className="fathom-muted">
          {state.message}
        </p>
      ) : null}
      {state.phase === "done" ? (
        <div className="fathom-preview-artifacts">
          {state.result.artifacts.length === 0 ? (
            <p className="fathom-muted">Nothing to preview.</p>
          ) : (
            state.result.artifacts.map((artifact, index) => (
              <ArtifactView key={`${artifact.kind}-${index}`} artifact={artifact} />
            ))
          )}
        </div>
      ) : null}
    </section>
  );
}

export function PreviewDetailPane({ entry }: PreviewDetailPaneProps): JSX.Element {
  if (entry === null) {
    return (
      <aside aria-label="Details" className="fathom-preview-pane">
        <p role="status">Select an entry to see details.</p>
      </aside>
    );
  }
  const activeFlags = Object.entries(entry.flags ?? {})
    .filter(([, on]) => on)
    .map(([key]) => key);
  const kind = entry.is_dir ? "directory" : entry.is_symlink ? "symlink" : "file";
  return (
    <aside aria-label="Details" className="fathom-preview-pane">
      <h2 className="fathom-detail-name">{entry.name}</h2>
      <dl className="fathom-keyvals">
        <dt>Path</dt>
        <dd className="fathom-path">{entry.path}</dd>
        <dt>Type</dt>
        <dd>{kind}</dd>
        {entry.is_dir ? (
          <>
            <dt>Items</dt>
            <dd className="tabular-nums">{entry.file_count.toLocaleString()} files</dd>
            <dt>Subtree (logical)</dt>
            <dd className="tabular-nums" title={formatBytesExact(entry.subtree_size_logical)}>
              {formatBytes(entry.subtree_size_logical)}
            </dd>
            <dt>Subtree (on-disk)</dt>
            <dd className="tabular-nums" title={formatBytesExact(entry.subtree_size_on_disk)}>
              {formatBytes(entry.subtree_size_on_disk)}
            </dd>
          </>
        ) : (
          <>
            <dt>Logical size</dt>
            <dd className="tabular-nums" title={formatBytesExact(entry.size_logical)}>
              {formatBytes(entry.size_logical)}
            </dd>
            <dt>On-disk size</dt>
            <dd className="tabular-nums" title={formatBytesExact(entry.size_on_disk)}>
              {formatBytes(entry.size_on_disk)}
            </dd>
          </>
        )}
        <dt>Modified</dt>
        <dd>{formatUnixTime(entry.mtime)}</dd>
        <dt>Owner</dt>
        <dd className="tabular-nums">
          {activeFlags.includes("synthetic_owner")
            ? "— (no ownership model)"
            : `${entry.uid}:${entry.gid}`}
        </dd>
        <dt>Inode</dt>
        <dd className="tabular-nums">{entry.inode}</dd>
        {entry.content_hash ? (
          <>
            <dt>Content hash</dt>
            <dd className="fathom-hash" title={entry.content_hash}>
              {entry.content_hash.slice(0, 16)}…
            </dd>
          </>
        ) : null}
      </dl>
      {activeFlags.length > 0 ? (
        <div className="fathom-flag-row" aria-label="Storage flags">
          {activeFlags.map((f) => (
            <span key={f} className="fathom-badge fathom-badge-flag">
              {FLAG_LABELS[f] ?? f}
            </span>
          ))}
        </div>
      ) : null}
      {/* A real file gets the on-demand sandboxed preview; directories/symlinks have no content. */}
      {!entry.is_dir && !entry.is_symlink ? (
        <PreviewSection key={entry.entry_id} entryId={entry.entry_id} />
      ) : null}
    </aside>
  );
}
