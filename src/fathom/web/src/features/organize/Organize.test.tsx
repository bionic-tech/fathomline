// Organize page (ADR-021/023): suggest a content-aware reorganisation for the selected folder.
// Covers the three render states the page can be in — no selection, the default-OFF gate message
// (403), and a rendered proposal with its apply panel — so the gate copy and table don't regress.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { ApiError } = await import("../../api/client");
const { Organize } = await import("./Organize");
const { useUiStore } = await import("../../state/uiStore");

const VOLUME = {
  id: 1,
  host_id: 1,
  mountpoint: "/mnt/pool",
  display_name: null,
  fs_type: "zfs",
  used: 100,
  total: 200,
  free: 100,
};

function wrap(node: JSX.Element): ReturnType<typeof render> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function selectFolder(): void {
  useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 1, selectedPath: "/mnt/pool/movies" });
}

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ selectedHostId: null, selectedVolumeId: null, selectedPath: null });
});

describe("Organize page", () => {
  it("prompts to select a volume + folder when nothing is selected", async () => {
    apiGet.mockResolvedValue([]);
    wrap(<Organize />);
    expect(
      await screen.findByText(/select a volume .* to get a suggestion/i),
    ).toBeInTheDocument();
    // No run button until a folder is chosen.
    expect(screen.queryByRole("button", { name: /suggest reorganisation/i })).not.toBeInTheDocument();
  });

  it("shows the default-OFF gate message when /organize/suggest returns 403", async () => {
    selectFolder();
    apiGet.mockResolvedValue([VOLUME]); // volumes + activity + agents
    apiPost.mockRejectedValue(new ApiError(403, { detail: "organize is disabled" }));

    wrap(<Organize />);
    fireEvent.click(await screen.findByRole("button", { name: /suggest reorganisation/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/organize is turned off on this server/i);
  });

  it("renders the proposal table and apply panel on a successful suggestion", async () => {
    selectFolder();
    apiGet.mockResolvedValue([VOLUME]);
    apiPost.mockResolvedValue({
      root: "/mnt/pool/movies",
      volume_id: 1,
      model: "llama3",
      considered: 2,
      rejected: 0,
      items: [
        {
          entry_id: 1,
          current_name: "a.mkv",
          proposed_relpath: "films/a.mkv",
          status: "move",
          reason: "group films together",
        },
        {
          entry_id: 2,
          current_name: "ok.txt",
          proposed_relpath: "",
          status: "keep",
          reason: "already placed",
        },
      ],
    });

    wrap(<Organize />);
    fireEvent.click(await screen.findByRole("button", { name: /suggest reorganisation/i }));

    // The "keep" row is unique to the proposal table (the apply panel only lists moves).
    expect(await screen.findByText("ok.txt")).toBeInTheDocument();
    expect(screen.getByText("llama3")).toBeInTheDocument(); // model code in the summary
    // The moved file appears (both in the table and the apply checklist).
    expect(screen.getAllByText("a.mkv").length).toBeGreaterThanOrEqual(1);
    // One move → the apply panel mounts.
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: /apply moves/i })).toBeInTheDocument(),
    );
  });
});
