// Explorer tree pane (frontend ADD §4): virtualised, lazy children on expand. Re-roots the
// drill query on open rather than loading the whole tree (frontend ADD §10).

import { useTree } from "../../api/queries";
import { DrillTree } from "../../charts/DrillTree";
import type { TreeChildOut } from "../../api/types";

export interface TreePaneProps {
  volumeId: number | null;
  path: string | null;
  selectedPath: string | null;
  onOpen: (child: TreeChildOut) => void;
}

export function TreePane({ volumeId, path, selectedPath, onOpen }: TreePaneProps): JSX.Element {
  const tree = useTree(volumeId, path);
  return (
    <nav aria-label="Directory tree" className="fathom-tree-pane">
      {tree.isError ? (
        <p role="alert" className="fathom-inline-error">
          Couldn't load the directory tree.
        </p>
      ) : path && tree.data ? (
        <DrillTree
          path={path}
          children={tree.data}
          onOpen={onOpen}
          selectedPath={selectedPath}
        />
      ) : (
        <p role="status">Select a volume to browse.</p>
      )}
    </nav>
  );
}
