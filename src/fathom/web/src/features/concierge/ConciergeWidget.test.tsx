// Concierge widget tests (ADR-035): the floating launcher is shown only when the concierge is
// enabled server-side, and opens the docked sidebar chat on click.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { ConciergeWidget } = await import("./ConciergeWidget");
const { useUiStore } = await import("../../state/uiStore");

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  localStorage.clear();
  useUiStore.setState({ conciergeOpen: false, conciergePinned: false });
});
afterEach(() => vi.clearAllMocks());

it("renders nothing when the concierge is disabled", async () => {
  apiGet.mockResolvedValue({ concierge_enabled: false });
  const { container } = wrap(<ConciergeWidget />);
  // Give the config query a tick; the gate keeps it empty.
  await Promise.resolve();
  expect(screen.queryByLabelText(/open concierge/i)).not.toBeInTheDocument();
  expect(container.querySelector(".fathom-cc-fab")).toBeNull();
});

it("shows the floating launcher when enabled and opens the sidebar", async () => {
  apiGet.mockResolvedValue({ concierge_enabled: true });
  wrap(<ConciergeWidget />);
  const fab = await screen.findByLabelText(/open concierge/i);
  fireEvent.click(fab);
  expect(await screen.findByLabelText("Concierge")).toBeInTheDocument(); // the <aside> sidebar
  expect(screen.getByLabelText(/your question/i)).toBeInTheDocument();
});

// --- pin persistence (UC-concierge-14) ----------------------------------------------------

it("pinning writes localStorage and reopens docked on a fresh remount", async () => {
  apiGet.mockResolvedValue({ concierge_enabled: true });
  const { unmount } = wrap(<ConciergeWidget />);

  fireEvent.click(await screen.findByLabelText(/open concierge/i)); // open the sidebar
  fireEvent.click(await screen.findByRole("button", { name: /pin/i })); // pin it
  expect(localStorage.getItem("fathom.concierge.pinned")).toBe("1");

  // Simulate a fresh session: the ephemeral open/pinned UI state resets, but localStorage persists.
  unmount();
  useUiStore.setState({ conciergeOpen: false, conciergePinned: false });
  wrap(<ConciergeWidget />);

  // It reopens docked from the persisted pin — the sidebar is shown with no fab click.
  expect(await screen.findByLabelText("Concierge")).toBeInTheDocument();
  expect(screen.queryByLabelText(/open concierge/i)).not.toBeInTheDocument();
});

it("unpinning clears the persisted pin", async () => {
  localStorage.setItem("fathom.concierge.pinned", "1");
  useUiStore.setState({ conciergeOpen: true, conciergePinned: true });
  apiGet.mockResolvedValue({ concierge_enabled: true });
  wrap(<ConciergeWidget />);

  fireEvent.click(await screen.findByRole("button", { name: /pinned/i })); // toggle off
  expect(localStorage.getItem("fathom.concierge.pinned")).toBeNull();
});
