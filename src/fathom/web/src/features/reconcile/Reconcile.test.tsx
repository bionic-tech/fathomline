// Reconcile tabs (ADR-043): the long compare form and the results table are split into Compare /
// Results tabs so neither pushes the other below the fold. Compare is the default; a completed
// comparison auto-focuses Results (see the resultKey remount in Reconcile.tsx).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { Reconcile } = await import("./Reconcile");

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => vi.clearAllMocks());

describe("Reconcile page", () => {
  it("splits the form and results into Compare / Results tabs, Compare first", async () => {
    apiGet.mockResolvedValue([]); // /volumes

    wrap(<Reconcile />);

    // Both tabs exist; Compare is active and shows the form.
    expect(await screen.findByRole("tab", { name: /^compare$/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^results$/i })).toBeInTheDocument();
    expect(screen.getByText(/definitive \(source of truth\)/i)).toBeInTheDocument();

    // Results tab shows the empty-state prompt until a comparison runs.
    fireEvent.click(screen.getByRole("tab", { name: /^results$/i }));
    expect(
      await screen.findByText(/run a comparison from the compare tab/i),
    ).toBeInTheDocument();
  });
});
