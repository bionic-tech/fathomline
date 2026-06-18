// Client/UI state (Zustand) — selection, pane layout, view toggle, scope/host (frontend ADD
// §4/§5). Server data lives in TanStack Query; this store holds only ephemeral UI state and is
// never persisted to localStorage (frontend ADD §12).

import { create } from "zustand";

export type ViewMode = "dashboard" | "explorer";

export interface UiState {
  /** Dashboard ⇄ Explorer (file-manager) toggle (frontend ADD §4 AppShell). */
  view: ViewMode;
  /** The globally selected host/volume scope (drives every scoped query). */
  selectedHostId: number | null;
  selectedVolumeId: number | null;
  /** The currently focused path in the explorer/treemap drill-down. */
  selectedPath: string | null;
  /** Multi-select set for dedup/remediation selection (path keys). */
  selection: Set<string>;
  setView: (view: ViewMode) => void;
  selectVolume: (hostId: number | null, volumeId: number | null, mountpoint: string | null) => void;
  selectPath: (path: string | null) => void;
  toggleSelected: (path: string) => void;
  clearSelection: () => void;
}

export const useUiStore = create<UiState>((set) => ({
  view: "dashboard",
  selectedHostId: null,
  selectedVolumeId: null,
  selectedPath: null,
  selection: new Set<string>(),
  setView: (view) => set({ view }),
  selectVolume: (selectedHostId, selectedVolumeId, mountpoint) =>
    set({ selectedHostId, selectedVolumeId, selectedPath: mountpoint, selection: new Set() }),
  selectPath: (selectedPath) => set({ selectedPath }),
  toggleSelected: (path) =>
    set((state) => {
      const next = new Set(state.selection);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return { selection: next };
    }),
  clearSelection: () => set({ selection: new Set() }),
}));
