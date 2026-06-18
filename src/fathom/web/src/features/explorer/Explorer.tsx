// Explorer (three-pane file-manager, frontend ADD §4): a path breadcrumb over
// TreePane | ListingPane | PreviewDetailPane. Drill-down is lazy (re-roots on open) and never
// loads the full tree (frontend ADD §10). Selection/path live in the Zustand UI store; server
// data in TanStack Query.

import { useState } from "react";

import { useVolumes } from "../../api/queries";
import { useUiStore } from "../../state/uiStore";
import type { TreeChildOut } from "../../api/types";
import { Breadcrumbs } from "../common/Breadcrumbs";
import { ListingPane } from "./ListingPane";
import { PreviewDetailPane } from "./PreviewDetailPane";
import { TreePane } from "./TreePane";

export function Explorer(): JSX.Element {
  const volumes = useVolumes();
  const volumeId = useUiStore((s) => s.selectedVolumeId);
  const path = useUiStore((s) => s.selectedPath);
  const selectPath = useUiStore((s) => s.selectPath);
  const selectVolume = useUiStore((s) => s.selectVolume);
  const [selected, setSelected] = useState<TreeChildOut | null>(null);

  const volume = volumes.data?.find((v) => v.id === volumeId);

  const openDir = (child: TreeChildOut): void => {
    if (child.is_dir) selectPath(child.path);
    setSelected(child);
  };

  if (volumeId === null) {
    return (
      <section aria-labelledby="explorer-title" className="fathom-page">
        <h1 id="explorer-title">Explorer</h1>
        <p className="fathom-muted">Select a volume from the top bar to browse it.</p>
      </section>
    );
  }

  return (
    <section aria-labelledby="explorer-title" className="fathom-explorer">
      <h1 id="explorer-title" className="sr-only">
        File explorer
      </h1>
      {volume && path ? (
        <Breadcrumbs
          mount={volume.mountpoint}
          path={path}
          onNavigate={(p) =>
            p === volume.mountpoint
              ? selectVolume(volume.host_id, volume.id, volume.mountpoint)
              : selectPath(p)
          }
        />
      ) : null}
      <div className="fathom-three-pane">
        <TreePane volumeId={volumeId} path={path} selectedPath={path} onOpen={openDir} />
        <ListingPane volumeId={volumeId} path={path} onSelect={setSelected} onOpen={openDir} />
        <PreviewDetailPane entry={selected} />
      </div>
    </section>
  );
}
