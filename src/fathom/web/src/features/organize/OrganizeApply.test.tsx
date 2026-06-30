// OrganizeApply: the gated apply flow for an organize proposal. Covers the move checklist, the
// default-OFF gate message when the plan build is refused (403), and the advance to the review
// step on a successful build. Downstream dry-run/execute/MFA steps fire only on later clicks.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { OrganizeItemOut } from "../../api/types";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));
vi.mock("../../api/client", async (orig) => ({
  ...(await orig<typeof import("../../api/client")>()), // keep ApiError + toQuery
  apiGet,
  apiPost,
}));

const { OrganizeApply } = await import("./OrganizeApply");
const { ApiError } = await import("../../api/client");

const MOVES: OrganizeItemOut[] = [
  { entry_id: 1, current_name: "a.mkv", current_path: "/mnt/pool/movies/a.mkv", proposed_relpath: "films/a.mkv", proposed_name: "a.mkv", status: "move", reason: "group" },
  { entry_id: 2, current_name: "b.mkv", current_path: "/mnt/pool/movies/b.mkv", proposed_relpath: "films/b.mkv", proposed_name: "b.mkv", status: "move", reason: "group" },
];

function wrap(): void {
  apiGet.mockResolvedValue([]); // useAgents
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <OrganizeApply volumeId={1} root="/mnt/pool/movies" moves={MOVES} />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.clearAllMocks());

describe("OrganizeApply", () => {
  it("lists the proposed moves with a build button selecting all", () => {
    wrap();
    expect(screen.getByText("a.mkv")).toBeInTheDocument();
    expect(screen.getByText("b.mkv")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /build move plan \(2\)/i })).toBeEnabled();
  });

  it("shows the default-OFF gate message when the build is refused (403)", async () => {
    apiPost.mockRejectedValue(new ApiError(403, { detail: "remediation disabled" }));
    wrap();
    fireEvent.click(screen.getByRole("button", { name: /build move plan/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/applying is disabled on this server/i);
  });

  it("advances to the review step on a successful build", async () => {
    apiPost.mockResolvedValue({
      plan_id: "org-1",
      move_root: "/mnt/pool/movies",
      blast_count: 2,
      host_id: "1",
      items: [
        { entry_id: 1, path: "/mnt/pool/movies/a.mkv", dest_rel: "films/a.mkv" },
        { entry_id: 2, path: "/mnt/pool/movies/b.mkv", dest_rel: "films/b.mkv" },
      ],
    });
    wrap();
    fireEvent.click(screen.getByRole("button", { name: /build move plan/i }));
    expect(await screen.findByRole("button", { name: /dry-run/i })).toBeInTheDocument();
    expect(screen.getByText(/2 file\(s\)/i)).toBeInTheDocument();
  });
});
