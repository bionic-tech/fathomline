// First-run setup wizard modal (Build P4): auto-shows for an admin until the estate's
// onboarding_completed flag is set. Non-admins never see it; once completed it stays closed.
// "Finish" records completion (PUT onboarding_completed=true) and dismisses; "Skip" closes without
// recording. The api client is mocked so no real fetch happens.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, type RenderResult } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPut } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPut: vi.fn() }));
vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPut };
});

const { SetupWizardModal } = await import("./SetupWizardModal");

// The wizard renders GettingStarted, which fetches /suitability — return a harmless empty estate.
const SUITABILITY = { egress_allowed: false, hosts: [] };

function meWith(role: string) {
  return {
    subject: `${role}-user`,
    source: "local",
    display_name: null,
    groups: [],
    grants: [{ role, scope_kind: "global", host_id: null, volume_id: null }],
    mfa_fresh: false,
    mfa_enrolled: false,
  };
}

function routeApi(me: object, config: Record<string, unknown> = {}): void {
  apiGet.mockImplementation((url: string) => {
    if (url.startsWith("/auth/me")) return Promise.resolve(me);
    if (url.startsWith("/config")) return Promise.resolve(config);
    if (url.startsWith("/suitability")) return Promise.resolve(SUITABILITY);
    return Promise.resolve({});
  });
}

function wrap(): RenderResult {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SetupWizardModal />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const dialog = () => screen.queryByRole("dialog", { name: /first-run setup/i });

afterEach(() => vi.clearAllMocks());

describe("SetupWizardModal (first-run)", () => {
  it("auto-shows for an admin when onboarding is incomplete", async () => {
    routeApi(meWith("admin"), { onboarding_completed: false });
    wrap();
    expect(await screen.findByRole("dialog", { name: /first-run setup/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /finish setup/i })).toBeInTheDocument();
  });

  it("does not show for a non-admin even when onboarding is incomplete", async () => {
    routeApi(meWith("operator"), { onboarding_completed: false });
    wrap();
    await waitFor(() => expect(apiGet).toHaveBeenCalledWith("/config"));
    await waitFor(() => expect(apiGet).toHaveBeenCalledWith("/auth/me"));
    expect(dialog()).not.toBeInTheDocument();
  });

  it("does not show once onboarding is complete", async () => {
    routeApi(meWith("admin"), { onboarding_completed: true });
    wrap();
    await waitFor(() => expect(apiGet).toHaveBeenCalledWith("/config"));
    expect(dialog()).not.toBeInTheDocument();
  });

  it("Finish setup records completion and dismisses the modal", async () => {
    routeApi(meWith("admin"), { onboarding_completed: false });
    apiPut.mockResolvedValue({
      key: "onboarding_completed",
      overridden: true,
      restart_required: false,
      version: 1,
    });
    wrap();

    fireEvent.click(await screen.findByRole("button", { name: /finish setup/i }));

    await waitFor(() =>
      expect(apiPut).toHaveBeenCalledWith("/settings/onboarding_completed", { value: true }),
    );
    await waitFor(() => expect(dialog()).not.toBeInTheDocument());
  });

  it("Skip for now dismisses without recording completion", async () => {
    routeApi(meWith("admin"), { onboarding_completed: false });
    wrap();

    fireEvent.click(await screen.findByRole("button", { name: /skip for now/i }));

    await waitFor(() => expect(dialog()).not.toBeInTheDocument());
    expect(apiPut).not.toHaveBeenCalled();
  });
});
