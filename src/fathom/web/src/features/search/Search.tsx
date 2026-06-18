// Search (frontend ADD §4): estate find-a-file. Type a name fragment and get the biggest matching
// live entries across in-scope volumes (or one volume), each a jump straight into the Explorer.
// Read-only, scope-filtered server-side.

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useSearch, useVolumes } from "../../api/queries";
import type { SearchResultOut } from "../../api/types";
import { displayPath, formatBytes, formatBytesExact } from "../../lib/format";
import { useNames } from "../../lib/names";
import { useUiStore } from "../../state/uiStore";
import { QueryState } from "../common/QueryState";

function parentDir(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  const idx = trimmed.lastIndexOf("/");
  return idx <= 0 ? trimmed : trimmed.slice(0, idx);
}

export function Search(): JSX.Element {
  const volumes = useVolumes();
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const selectVolume = useUiStore((s) => s.selectVolume);
  const selectPath = useUiStore((s) => s.selectPath);
  const setView = useUiStore((s) => s.setView);
  const navigate = useNavigate();

  const [input, setInput] = useState("");
  const [term, setTerm] = useState("");
  const [thisVolumeOnly, setThisVolumeOnly] = useState(false);

  // Debounce the live query so we don't fire on every keystroke.
  useEffect(() => {
    const id = setTimeout(() => setTerm(input), 300);
    return () => clearTimeout(id);
  }, [input]);

  const scopeVolume = thisVolumeOnly ? selectedVolumeId : null;
  const results = useSearch(term, scopeVolume);

  const jumpTo = (r: SearchResultOut): void => {
    const vol = volumes.data?.find((v) => v.id === r.volume_id);
    if (!vol) return;
    selectVolume(vol.host_id, vol.id, vol.mountpoint);
    selectPath(r.is_dir ? r.path : parentDir(r.path));
    setView("explorer");
    navigate("/explore");
  };

  const { hostName, volumeLabel } = useNames();

  return (
    <section aria-labelledby="search-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="search-title">Search</h1>
        <p className="fathom-muted">
          Find a file or folder by name across your estate — largest matches first. Click a result
          to open it in the Explorer.
        </p>
      </header>

      <form
        className="fathom-search-bar"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          setTerm(input);
        }}
      >
        <input
          type="search"
          aria-label="Search by name"
          placeholder="e.g. .mkv, node_modules, backup…"
          value={input}
          autoFocus
          onChange={(e) => setInput(e.target.value)}
        />
        <label className="fathom-inline-checkbox">
          <input
            type="checkbox"
            checked={thisVolumeOnly}
            disabled={selectedVolumeId === null}
            onChange={(e) => setThisVolumeOnly(e.target.checked)}
          />
          This volume only
        </label>
      </form>

      {term.trim().length < 2 ? (
        <p className="fathom-muted">Type at least two characters to search.</p>
      ) : (
        <QueryState
          isLoading={results.isLoading}
          isError={results.isError}
          error={results.error}
          isEmpty={(results.data?.length ?? 0) === 0}
          emptyLabel={`No live entries match “${term}”.`}
        >
          <table className="fathom-table">
            <caption className="sr-only">Search results for {term}</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Type</th>
                <th scope="col">On-disk</th>
                <th scope="col">Host</th>
                <th scope="col">Location</th>
              </tr>
            </thead>
            <tbody>
              {(results.data ?? []).map((r) => (
                <tr key={`${r.volume_id}:${r.path}`}>
                  <td>
                    <button
                      type="button"
                      className="fathom-listing-name"
                      onClick={() => jumpTo(r)}
                      title={`${hostName(r.host_id)}:${displayPath(r.path)}`}
                    >
                      {r.name}
                      {r.is_dir ? "/" : ""}
                    </button>
                  </td>
                  <td>{r.is_dir ? "dir" : "file"}</td>
                  <td className="tabular-nums" title={formatBytesExact(r.size_on_disk)}>
                    {formatBytes(r.size_on_disk)}
                  </td>
                  <td>{hostName(r.host_id)}</td>
                  <td className="fathom-path" title={displayPath(r.path)}>{volumeLabel(r.volume_id)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </QueryState>
      )}
    </section>
  );
}
