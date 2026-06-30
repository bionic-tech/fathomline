// Re-run setup control (Build P4): admin-only. When the estate has completed onboarding it offers a
// "Run setup wizard again" button that PUTs onboarding_completed=false to re-arm the first-run
// modal. It is hidden for non-admins and disabled while the wizard is still armed.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, type RenderResult } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPut } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPut: vi.fn() }));
vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPut };
});

const { RerunSetupControl } = await import("./RerunSetupControl");

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
    return Promise.resolve({});
  });
}

function wrap(): RenderResult {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <RerunSetupControl />
    </QueryClientProvider>,
  );
}

const rerunBtn = () => screen.queryByRole("button", { name: /run setup wizard again/i });

afterEach(() => vi.clearAllMocks());

describe("RerunSetupControl", () => {
  it("re-arms the wizard (PUT false) for an admin once onboarding is complete", async () => {
    routeApi(meWith("admin"), { onboarding_completed: true });
    apiPut.mockResolvedValue({
      key: "onboarding_completed",
      overridden: true,
      restart_required: false,
      version: 1,
    });
    wrap();

    const btn = await screen.findByRole("button", { name: /run setup wizard again/i });
    expect(btn).toBeEnabled();
    fireEvent.click(btn);

    await waitFor(() =>
      expect(apiPut).toHaveBeenCalledWith("/settings/onboarding_completed", { value: false }),
    );
  });

  it("is hidden for a non-admin", async () => {
    routeApi(meWith("viewer"), { onboarding_completed: true });
    wrap();
    await waitFor(() => expect(apiGet).toHaveBeenCalledWith("/auth/me"));
    expect(rerunBtn()).not.toBeInTheDocument();
  });

  it("disables the button while the wizard is still armed (not completed)", async () => {
    routeApi(meWith("admin"), { onboarding_completed: false });
    wrap();
    expect(await screen.findByRole("button", { name: /run setup wizard again/i })).toBeDisabled();
  });
});
