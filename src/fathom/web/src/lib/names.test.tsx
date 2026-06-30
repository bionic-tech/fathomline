// useNames: resolve a host id → name and a volume id → a short label, from the agents + volumes
// queries, with stable fallbacks for unknown ids.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet } = vi.hoisted(() => ({ apiGet: vi.fn() }));
vi.mock("../api/client", () => ({ apiGet, apiPost: vi.fn() }));

const { useNames } = await import("./names");

function Probe(): JSX.Element {
  const { hostName, volumeLabel } = useNames();
  return (
    <ul>
      <li>host1:{hostName(1)}</li>
      <li>host9:{hostName(9)}</li>
      <li>vol1:{volumeLabel(1)}</li>
      <li>vol9:{volumeLabel(9)}</li>
    </ul>
  );
}

function wrap(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <Probe />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.clearAllMocks());

describe("useNames", () => {
  it("resolves known ids and falls back for unknown ones", async () => {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/agents")) return Promise.resolve([{ id: 1, name: "nas-1" }]);
      if (url.startsWith("/volumes")) {
        return Promise.resolve([
          { id: 1, mountpoint: "/scan/mnt/pool", display_name: null, host_id: 1 },
        ]);
      }
      return Promise.resolve([]);
    });
    wrap();

    expect(await screen.findByText("host1:nas-1")).toBeInTheDocument();
    expect(screen.getByText("host9:host 9")).toBeInTheDocument(); // unknown host fallback
    // "/scan" mount alias stripped, leading slash removed.
    expect(screen.getByText("vol1:mnt/pool")).toBeInTheDocument();
    expect(screen.getByText("vol9:vol 9")).toBeInTheDocument(); // unknown volume fallback
  });

  it("prefers a volume display_name when set", async () => {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/volumes")) {
        return Promise.resolve([
          { id: 1, mountpoint: "/synthetic/x", display_name: "Cloud archive", host_id: 1 },
        ]);
      }
      return Promise.resolve([]);
    });
    wrap();
    expect(await screen.findByText("vol1:Cloud archive")).toBeInTheDocument();
  });
});
