// Lazy directory tree for the scan-scope builder (ADR-034 Phase 2). Given a `browse(path)` function
// (live, MFA-gated) it lets an operator navigate a host's REAL directories — including un-scanned
// ones — and add a folder to the include (scan_scope) or exclude (exclude_scope) list. Directories
// only (you scope folders, not files), each annotated with its bounded subtree size + file-count.
//
// Per-request step-up MFA: a browse call may 401; the node surfaces an inline MFA prompt, and on a
// successful verify it retries the expand. One verify stamps freshness for the window, so subsequent
// expands within it don't re-prompt (the server still re-checks every request).

import { useState } from "react";

import { ApiError } from "../../api/client";
import { useMfaVerify } from "../../api/queries";
import type { BrowseEntry, BrowseResult } from "../../api/types";
import { formatBytes } from "../../lib/format";

export type BrowseFn = (path: string) => Promise<BrowseResult>;

interface NodeProps {
  path: string;
  label: string;
  browse: BrowseFn;
  onInclude: (path: string) => void;
  onExclude?: (path: string) => void;
  includeLabel: string;
  depth: number;
}

function sizeLabel(e: BrowseEntry): string {
  if (e.subtree_size === null) return "";
  const n = e.subtree_file_count;
  const files = n === null ? "" : ` · ${n}${e.subtree_truncated ? "+" : ""} files`;
  return ` (${e.subtree_truncated ? "≥" : ""}${formatBytes(e.subtree_size)}${files})`;
}

function TreeNode({
  path,
  label,
  browse,
  onInclude,
  onExclude,
  includeLabel,
  depth,
}: NodeProps): JSX.Element {
  const [open, setOpen] = useState(false);
  const [children, setChildren] = useState<BrowseEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needsMfa, setNeedsMfa] = useState(false);
  const [code, setCode] = useState("");
  const mfa = useMfaVerify();

  const load = async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const res = await browse(path);
      if (res.error) setError(res.error);
      else setChildren(res.entries.filter((e) => e.is_dir && !e.is_symlink));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setNeedsMfa(true);
      else setError(e instanceof ApiError ? (e.problem.detail ?? e.message) : "browse failed");
    } finally {
      setLoading(false);
    }
  };

  const toggle = (): void => {
    const next = !open;
    setOpen(next);
    if (next && children === null && !loading) void load();
  };

  const verifyAndRetry = async (): Promise<void> => {
    try {
      await mfa.mutateAsync(code);
      setNeedsMfa(false);
      setCode("");
      await load();
    } catch {
      /* useMfaVerify surfaces its own error state */
    }
  };

  return (
    <li className="fathom-tree-node">
      <div className="fathom-tree-row" style={{ paddingLeft: `${depth * 1.1}rem` }}>
        <button type="button" className="fathom-disclosure" aria-expanded={open} onClick={toggle}>
          {open ? "▾" : "▸"} {label}
        </button>
        <span className="fathom-tree-actions">
          <button type="button" className="fathom-btn fathom-btn-mini" onClick={() => onInclude(path)}>
            {includeLabel}
          </button>
          {onExclude ? (
            <button
              type="button"
              className="fathom-btn fathom-btn-mini"
              onClick={() => onExclude(path)}
            >
              − exclude
            </button>
          ) : null}
        </span>
      </div>
      {open ? (
        <div style={{ paddingLeft: `${(depth + 1) * 1.1}rem` }}>
          {loading ? <p className="fathom-muted">Listing…</p> : null}
          {error ? <p className="fathom-inline-error">{error}</p> : null}
          {needsMfa ? (
            <div className="fathom-field fathom-tree-mfa">
              <span className="fathom-muted">Step-up MFA required to browse live.</span>
              <input
                inputMode="numeric"
                placeholder="6-digit code"
                value={code}
                onChange={(ev) => setCode(ev.target.value)}
              />
              <button
                type="button"
                className="fathom-btn fathom-btn-primary"
                disabled={mfa.isPending || code.length < 6}
                onClick={() => void verifyAndRetry()}
              >
                {mfa.isPending ? "Verifying…" : "Verify + retry"}
              </button>
              {mfa.isError ? <span className="fathom-inline-error">Code rejected.</span> : null}
            </div>
          ) : null}
          {children !== null && children.length === 0 && !loading ? (
            <p className="fathom-muted">No sub-folders.</p>
          ) : null}
          {children?.map((c) => (
            <ul key={c.path} className="fathom-tree">
              <TreeNode
                path={c.path}
                label={`${c.name}${sizeLabel(c)}`}
                browse={browse}
                onInclude={onInclude}
                onExclude={onExclude}
                includeLabel={includeLabel}
                depth={depth + 1}
              />
            </ul>
          ))}
        </div>
      ) : null}
    </li>
  );
}

export function DirTree({
  roots,
  browse,
  onInclude,
  onExclude,
  includeLabel = "+ scan",
}: {
  roots: { path: string; label: string }[];
  browse: BrowseFn;
  onInclude: (path: string) => void;
  onExclude?: (path: string) => void;
  includeLabel?: string;
}): JSX.Element {
  return (
    <ul className="fathom-tree fathom-tree-root">
      {roots.map((r) => (
        <TreeNode
          key={r.path}
          path={r.path}
          label={r.label}
          browse={browse}
          onInclude={onInclude}
          onExclude={onExclude}
          includeLabel={includeLabel}
          depth={0}
        />
      ))}
    </ul>
  );
}
