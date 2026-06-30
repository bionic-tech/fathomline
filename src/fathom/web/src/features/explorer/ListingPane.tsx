// Explorer listing pane (frontend ADD §4): sortable rows — name, type, sizes, modified. Single
// click selects (shows detail); a directory name drills in. Sorted client-side; to keep a huge
// directory responsive only the first PAGE rows render, with a "showing N of M" note (server-side
// keyset paging of the listing is a later step — for now this bounds the DOM, not the data).

import { useMemo, useState } from "react";

import { useTree } from "../../api/queries";
import { formatBytes, formatUnixTime } from "../../lib/format";
import type { TreeChildOut } from "../../api/types";
import { RiskBadge } from "../common/RiskBadge";

export interface ListingPaneProps {
  volumeId: number | null;
  path: string | null;
  onSelect: (child: TreeChildOut) => void;
  onOpen: (child: TreeChildOut) => void;
}

type SortKey = "name" | "type" | "logical" | "on_disk" | "mtime";
const PAGE = 500;

function sortValue(e: TreeChildOut, key: SortKey): number | string {
  switch (key) {
    case "name":
      return e.name.toLowerCase();
    case "type":
      return e.is_dir ? 0 : 1;
    case "logical":
      return e.subtree_size_logical;
    case "on_disk":
      return e.subtree_size_on_disk;
    case "mtime":
      return e.mtime;
  }
}

export function ListingPane({ volumeId, path, onSelect, onOpen }: ListingPaneProps): JSX.Element {
  const tree = useTree(volumeId, path);
  const [sortKey, setSortKey] = useState<SortKey>("on_disk");
  const [asc, setAsc] = useState(false);

  const rows = useMemo(() => {
    const data = [...(tree.data ?? [])];
    data.sort((a, b) => {
      const va = sortValue(a, sortKey);
      const vb = sortValue(b, sortKey);
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return asc ? cmp : -cmp;
    });
    return data;
  }, [tree.data, sortKey, asc]);

  const toggleSort = (key: SortKey): void => {
    if (key === sortKey) setAsc((v) => !v);
    else {
      setSortKey(key);
      setAsc(key === "name" || key === "type"); // names/types ascend by default, sizes descend
    }
  };

  const header = (key: SortKey, label: string): JSX.Element => (
    <th scope="col" aria-sort={sortKey === key ? (asc ? "ascending" : "descending") : "none"}>
      <button type="button" className="fathom-sort-th" onClick={() => toggleSort(key)}>
        {label}
        {sortKey === key ? <span aria-hidden="true">{asc ? " ▲" : " ▼"}</span> : null}
      </button>
    </th>
  );

  const shown = rows.slice(0, PAGE);

  return (
    <section aria-label="Directory listing" className="fathom-listing-pane">
      {tree.isError ? (
        <p role="alert" className="fathom-inline-error">
          Couldn't load this directory.
        </p>
      ) : (
        <>
          <table className="fathom-table">
            <caption className="sr-only">Entries under {path ?? "—"}</caption>
            <thead>
              <tr>
                {header("name", "Name")}
                {header("type", "Type")}
                {header("logical", "Logical")}
                {header("on_disk", "On-disk")}
                {header("mtime", "Modified")}
              </tr>
            </thead>
            <tbody>
              {shown.map((entry) => (
                <tr key={entry.path}>
                  <td>
                    <button
                      type="button"
                      className="fathom-listing-name"
                      onClick={() => (entry.is_dir ? onOpen(entry) : onSelect(entry))}
                      title={entry.path}
                    >
                      {entry.name}
                      {entry.is_dir ? "/" : ""}
                    </button>{" "}
                    <RiskBadge path={entry.path} name={entry.name} />
                  </td>
                  <td>{entry.is_dir ? "dir" : entry.is_symlink ? "link" : "file"}</td>
                  <td className="tabular-nums">{formatBytes(entry.subtree_size_logical)}</td>
                  <td className="tabular-nums">{formatBytes(entry.subtree_size_on_disk)}</td>
                  <td>{formatUnixTime(entry.mtime)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length > PAGE ? (
            <p className="fathom-muted fathom-hint">
              Showing the {PAGE.toLocaleString()} largest of {rows.length.toLocaleString()} entries —
              drill into a subfolder to narrow.
            </p>
          ) : null}
        </>
      )}
    </section>
  );
}
