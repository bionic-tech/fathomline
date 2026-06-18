// Largest (frontend ADD §4): the "what's eating my space?" view — the biggest files/dirs under
// the selected volume/subtree, server-ranked (top-n endpoint, capped). Toggle by on-disk vs
// logical size and by kind (any/dir/file); click a directory to drill into it in the Explorer.

import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { useTopN, useVolumes } from "../../api/queries";
import type { SizeBasis, TopNKind } from "../../api/types";
import { formatBytes, formatBytesExact } from "../../lib/format";
import { useUiStore } from "../../state/uiStore";
import { Breadcrumbs } from "../common/Breadcrumbs";
import { QueryState } from "../common/QueryState";

export function Largest(): JSX.Element {
  const volumes = useVolumes();
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const selectedPath = useUiStore((s) => s.selectedPath);
  const selectVolume = useUiStore((s) => s.selectVolume);
  const selectPath = useUiStore((s) => s.selectPath);
  const setView = useUiStore((s) => s.setView);
  const navigate = useNavigate();
  const [by, setBy] = useState<SizeBasis>("on_disk");
  const [kind, setKind] = useState<TopNKind>("any");
  const top = useTopN(selectedVolumeId, selectedPath, 50, by, kind);

  const selectedVolume = volumes.data?.find((v) => v.id === selectedVolumeId);

  const openInExplorer = (path: string): void => {
    selectPath(path);
    setView("explorer");
    navigate("/explore");
  };

  return (
    <section aria-labelledby="largest-title" className="fathom-page">
      <header className="fathom-page-head">
        <h1 id="largest-title">Largest</h1>
        <p className="fathom-muted">
          The biggest space consumers under the selected subtree, ranked server-side.
        </p>
      </header>

      {selectedVolumeId === null ? (
        <p className="fathom-muted">Select a volume from the top bar to rank its largest items.</p>
      ) : (
        <>
          <div className="fathom-toolbar">
            {selectedVolume && selectedPath ? (
              <Breadcrumbs
                mount={selectedVolume.mountpoint}
                path={selectedPath}
                onNavigate={(p) =>
                  p === selectedVolume.mountpoint
                    ? selectVolume(selectedVolume.host_id, selectedVolume.id, selectedVolume.mountpoint)
                    : selectPath(p)
                }
              />
            ) : null}
            <div className="fathom-toolbar-controls">
              <label className="fathom-inline-field">
                Size
                <select value={by} onChange={(e) => setBy(e.target.value as SizeBasis)}>
                  <option value="on_disk">on-disk</option>
                  <option value="logical">logical</option>
                </select>
              </label>
              <label className="fathom-inline-field">
                Kind
                <select value={kind} onChange={(e) => setKind(e.target.value as TopNKind)}>
                  <option value="any">any</option>
                  <option value="dir">directories</option>
                  <option value="file">files</option>
                </select>
              </label>
            </div>
          </div>

          <QueryState
            isLoading={top.isLoading}
            isError={top.isError}
            error={top.error}
            isEmpty={(top.data?.length ?? 0) === 0}
            emptyLabel="No ranked items — run a scan + finalize for this subtree."
          >
            <table className="fathom-table">
              <caption className="sr-only">Largest items under {selectedPath}</caption>
              <thead>
                <tr>
                  <th scope="col">#</th>
                  <th scope="col">Name</th>
                  <th scope="col">Type</th>
                  <th scope="col">Size ({by === "on_disk" ? "on-disk" : "logical"})</th>
                  <th scope="col">Files</th>
                </tr>
              </thead>
              <tbody>
                {(top.data ?? []).map((item, i) => {
                  const size = by === "on_disk" ? item.size_on_disk : item.size_logical;
                  return (
                    <tr key={item.path}>
                      <td className="tabular-nums">{i + 1}</td>
                      <td>
                        {item.is_dir ? (
                          <button
                            type="button"
                            className="fathom-link"
                            onClick={() => openInExplorer(item.path)}
                            title={item.path}
                          >
                            {item.name}/
                          </button>
                        ) : (
                          <span title={item.path}>{item.name}</span>
                        )}
                      </td>
                      <td>{item.is_dir ? "dir" : "file"}</td>
                      <td className="tabular-nums" title={formatBytesExact(size)}>
                        {formatBytes(size)}
                      </td>
                      <td className="tabular-nums">
                        {item.is_dir ? item.file_count.toLocaleString() : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </QueryState>
        </>
      )}
    </section>
  );
}
