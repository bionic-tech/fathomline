// Remediation wizard (ADR-011): the gated "reclaim space" flow for one duplicate group. Covers the
// keeper-choice step (members + suggested badge), the default-OFF gate message when the build is
// refused (403), and the detail-query error state — the states most likely to silently regress.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { ApiError } = await import("../../api/client");
const { RemediationWizard } = await import("./RemediationWizard");

const GROUP = {
  id: 7,
  full_hash: "abc123",
  size: 100,
  member_count: 2,
  reclaimable_bytes: 100,
  suggested_keeper_entry_id: 11,
  suggested_keeper_reason: "oldest copy",
};

const DETAIL = {
  ...GROUP,
  members: [
    { entry_id: 11, host_id: 1, volume_id: 1, path: "/mnt/pool/keep.mkv", is_mount_alias: false },
    { entry_id: 12, host_id: 1, volume_id: 1, path: "/mnt/pool/dupe.mkv", is_mount_alias: false },
  ],
};

function wrap(node: JSX.Element): ReturnType<typeof render> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => vi.clearAllMocks());

describe("RemediationWizard", () => {
  it("lists the members and marks the suggested keeper", async () => {
    apiGet.mockImplementation((url: string) =>
      url.startsWith("/duplicates/") ? Promise.resolve(DETAIL) : Promise.resolve([]),
    );
    wrap(<RemediationWizard group={GROUP} onClose={vi.fn()} />);

    expect(await screen.findByText("/mnt/pool/keep.mkv")).toBeInTheDocument();
    expect(screen.getByText("/mnt/pool/dupe.mkv")).toBeInTheDocument();
    expect(screen.getByText(/suggested/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /build plan/i })).toBeEnabled();
  });

  it("shows the default-OFF gate message when the build is refused (403)", async () => {
    apiGet.mockImplementation((url: string) =>
      url.startsWith("/duplicates/") ? Promise.resolve(DETAIL) : Promise.resolve([]),
    );
    apiPost.mockRejectedValue(new ApiError(403, { detail: "remediation disabled" }));

    wrap(<RemediationWizard group={GROUP} onClose={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: /build plan/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/remediation is disabled on this server/i);
  });

  it("surfaces an error state when the group detail fails to load", async () => {
    apiGet.mockImplementation((url: string) =>
      url.startsWith("/duplicates/")
        ? Promise.reject(new ApiError(500, { detail: "boom" }))
        : Promise.resolve([]),
    );
    wrap(<RemediationWizard group={GROUP} onClose={vi.fn()} />);

    // QueryState renders the error in place of the keeper list — never the member radios.
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText("/mnt/pool/keep.mkv")).not.toBeInTheDocument();
  });
});
