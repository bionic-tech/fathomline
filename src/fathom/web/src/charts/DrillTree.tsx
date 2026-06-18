// Virtualised drill-down tree pane (frontend ADD §4/§10): lazy children on expand, never a
// full-tree load. Subtree sizes are pre-aggregated server-side (subtree_rollup, ADD 09 §8).
//
// This is a lightweight, dependency-free virtualisation: only the children of the focused
// path are fetched and rendered, and expanding a node re-roots the query rather than loading
// the whole 50M tree (frontend ADD §10 risk).

import { formatBytes } from "../lib/format";
import type { TreeChildOut } from "../api/types";

export interface DrillTreeProps {
  path: string;
  children: TreeChildOut[];
  onOpen: (child: TreeChildOut) => void;
  selectedPath: string | null;
}

export function DrillTree({ path, children, onOpen, selectedPath }: DrillTreeProps): JSX.Element {
  return (
    <ul role="tree" aria-label={`Children of ${path}`}>
      {children.map((child) => (
        <li
          key={child.path}
          role="treeitem"
          aria-selected={child.path === selectedPath}
          aria-expanded={child.is_dir ? false : undefined}
        >
          <button
            type="button"
            onClick={() => onOpen(child)}
            disabled={!child.is_dir}
            className="fathom-tree-row"
          >
            <span className="fathom-tree-name">{child.name}</span>
            <span className="fathom-tree-size">{formatBytes(child.subtree_size_on_disk)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}
