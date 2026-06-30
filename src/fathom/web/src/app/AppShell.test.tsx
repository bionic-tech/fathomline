// AppShell: the primary nav (RBAC-gated links), the volume scope selector, and sign-out. The
// concierge widget + notification bell are stubbed so the test stays focused on the shell chrome;
// useNavigate is spied and session.logout is mocked.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, type RenderResult } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const navigate = vi.fn();
vi.mock("react-router-dom", async (orig) => ({
  ...(await orig<typeof import("react-router-dom")>()),
  useNavigate: () => navigate,
}));

const { apiGet, logout } = vi.hoisted(() => ({ apiGet: vi.fn(), logout: vi.fn() }));
vi.mock("../api/client", () => ({ apiGet, apiPost: vi.fn() }));
vi.mock("../auth/session", () => ({ logout }));
vi.mock("../features/concierge/ConciergeWidget", () => ({ ConciergeWidget: () => null }));
// Stubbed to a marker so the bell's PRESENCE (notifications gating) is observable, not its internals.
vi.mock("../features/notifications/NotificationBell", () => ({
  NotificationBell: () => <span data-testid="notification-bell">bell</span>,
}));

const { AppShell } = await import("./AppShell");
const { useUiStore } = await import("../state/uiStore");

const VOL = {
  id: 1,
  host_id: 1,
  mountpoint: "/mnt/pool",
  fs_type: "zfs",
  device: "t",
  transport: "sata",
  raid_role: null,
  total: 200,
  used: 50,
  free: 150,
  display_name: null,
};

// A second in-scope volume so the scope selector has a non-default choice to switch to.
const VOL2 = { ...VOL, id: 2, mountpoint: "/mnt/tank", display_name: "tank" };

function meWith(role: string) {
  return {
    subject: role + "-user",
    source: "local",
    display_name: null,
    groups: [],
    grants: [{ role, scope_kind: "global", host_id: null, volume_id: null }],
    mfa_fresh: false,
    mfa_enrolled: false,
  };
}

function routeApi(me: object, config: object = {}, vols: object[] = [VOL]) {
  apiGet.mockImplementation((url: string) => {
    if (url.startsWith("/auth/me")) return Promise.resolve(me);
    if (url.startsWith("/volumes")) return Promise.resolve(vols);
    if (url.startsWith("/config")) return Promise.resolve(config);
    return Promise.resolve({});
  });
}

function wrap(): RenderResult {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <AppShell />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Mount AppShell as a LAYOUT route with child routes so the <Outlet/> actually renders a page —
// this is what lets us assert route mounting + aria-current as the active link changes.
function wrapRoutes(initial = "/dashboard"): RenderResult {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="dashboard" element={<div>DASHBOARD ROUTE</div>} />
            <Route path="explore" element={<div>EXPLORER ROUTE</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.clearAllMocks();
  // The zustand store is a module singleton: reset the shared scope/concierge selection so one
  // test's choice can't leak into the next (and the first-load default stays deterministic).
  useUiStore.setState({
    selectedHostId: null,
    selectedVolumeId: null,
    selectedPath: null,
    conciergeOpen: false,
    conciergePinned: false,
  });
});

describe("AppShell", () => {
  it("renders the always-on primary nav links", async () => {
    routeApi(meWith("admin"));
    wrap();
    for (const name of ["Dashboard", "Explorer", "Search", "Largest", "Changes", "Settings"]) {
      expect(await screen.findByRole("link", { name })).toBeInTheDocument();
    }
  });

  it("hides Audit + Deploy for a viewer but shows Duplicates", async () => {
    routeApi(meWith("viewer"));
    wrap();
    expect(await screen.findByRole("link", { name: "Duplicates" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Audit" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Deploy" })).not.toBeInTheDocument();
  });

  it("shows Audit + Deploy for an admin", async () => {
    routeApi(meWith("admin"));
    wrap();
    expect(await screen.findByRole("link", { name: "Audit" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Deploy" })).toBeInTheDocument();
  });

  it("offers the estate option plus one option per volume", async () => {
    routeApi(meWith("admin"));
    wrap();
    expect(await screen.findByRole("option", { name: /all volumes \(estate\)/i })).toBeInTheDocument();
    expect(await screen.findByRole("option", { name: /mnt\/pool|pool/i })).toBeInTheDocument();
  });

  // UC-nav-3: an auditor holds read_audit + view_dedup but NOT deploy_agent, so the nav itself
  // offers Audit + Duplicates and withholds Deploy.
  it("shows Audit + Duplicates but hides Deploy for an auditor", async () => {
    routeApi(meWith("auditor"));
    wrap();
    expect(await screen.findByRole("link", { name: "Audit" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Duplicates" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Deploy" })).not.toBeInTheDocument();
  });

  // UC-nav-2: clicking a nav link mounts the target route in the Outlet and moves aria-current.
  it("mounts the clicked route in the outlet and moves aria-current to the active link", async () => {
    routeApi(meWith("admin"));
    wrapRoutes("/dashboard");
    expect(await screen.findByText("DASHBOARD ROUTE")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Dashboard" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Explorer" })).not.toHaveAttribute("aria-current");

    fireEvent.click(screen.getByRole("link", { name: "Explorer" }));

    expect(await screen.findByText("EXPLORER ROUTE")).toBeInTheDocument();
    expect(screen.queryByText("DASHBOARD ROUTE")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Explorer" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Dashboard" })).not.toHaveAttribute("aria-current");
  });

  // UC-nav-4: choosing a volume drives the global scope (selectVolume's effect on the store).
  it("selecting a volume sets it as the global scope", async () => {
    routeApi(meWith("admin"), {}, [VOL, VOL2]);
    wrap();
    // First-load default lands on the first volume; switch to the second.
    await waitFor(() => expect(useUiStore.getState().selectedVolumeId).toBe(VOL.id));
    fireEvent.change(await screen.findByRole("combobox"), { target: { value: String(VOL2.id) } });
    const s = useUiStore.getState();
    expect(s.selectedVolumeId).toBe(VOL2.id);
    expect(s.selectedHostId).toBe(VOL2.host_id);
    expect(s.selectedPath).toBe(VOL2.mountpoint);
  });

  // UC-nav-5 + EC-nav-8: first-load defaults to the first volume exactly once; a deliberate
  // "All volumes" (null) choice afterwards must NOT be snapped back by the one-time init guard.
  it("defaults scope to the first volume on first load but keeps an explicit All-volumes choice", async () => {
    routeApi(meWith("admin"), {}, [VOL, VOL2]);
    wrap();
    await waitFor(() => expect(useUiStore.getState().selectedVolumeId).toBe(VOL.id));

    fireEvent.change(await screen.findByRole("combobox"), { target: { value: "" } });
    await waitFor(() => expect(useUiStore.getState().selectedVolumeId).toBeNull());
    // Give the init effect (re-run on the null change) a chance to wrongly re-default; it must not.
    await act(async () => {
      await new Promise((r) => setTimeout(r, 30));
    });
    expect(useUiStore.getState().selectedVolumeId).toBeNull();
  });

  // UC-nav-7 / EC-notifications-1: the bell renders only when notifications_enabled === true.
  it("renders the notification bell when notifications are enabled", async () => {
    routeApi(meWith("admin"), { notifications_enabled: true });
    wrap();
    expect(await screen.findByTestId("notification-bell")).toBeInTheDocument();
  });

  // EC-nav-9: the bell is absent when the feature flag is off.
  it("hides the notification bell when notifications are disabled", async () => {
    routeApi(meWith("admin"), { notifications_enabled: false });
    wrap();
    // Wait for both the principal AND the config query to settle before asserting absence.
    await screen.findByText("admin-user");
    await waitFor(() => expect(apiGet).toHaveBeenCalledWith("/config"));
    expect(screen.queryByTestId("notification-bell")).not.toBeInTheDocument();
  });

  it("signs out: revokes the session and lands on /login", async () => {
    routeApi(meWith("admin"));
    logout.mockResolvedValue(undefined);
    wrap();
    fireEvent.click(await screen.findByRole("button", { name: /sign out/i }));
    await waitFor(() => expect(logout).toHaveBeenCalled());
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/login", { replace: true }));
  });

  // UC-auth-3: sign-out also drops the cached principal by clearing the whole query client.
  it("sign out clears the query cache", async () => {
    routeApi(meWith("admin"));
    logout.mockResolvedValue(undefined);
    const clearSpy = vi.spyOn(QueryClient.prototype, "clear");
    wrap();
    fireEvent.click(await screen.findByRole("button", { name: /sign out/i }));
    await waitFor(() => expect(clearSpy).toHaveBeenCalled());
    clearSpy.mockRestore();
  });

  // UC-nav-8: pinning the concierge open docks the shell (CSS class) and nudges a window resize so
  // charts re-fit under the narrower main pane.
  it("docks the shell and nudges a window resize when the concierge is pinned open", async () => {
    routeApi(meWith("admin"));
    const dispatchSpy = vi.spyOn(window, "dispatchEvent");
    const { container } = wrap();
    await screen.findByRole("link", { name: "Dashboard" });
    // Let the background queries (+ first-load scope default) settle before we toggle, so their
    // state updates don't land outside act().
    await waitFor(() => expect(useUiStore.getState().selectedVolumeId).toBe(VOL.id));
    const shell = container.querySelector(".fathom-shell") as HTMLElement;
    expect(shell.className).not.toContain("fathom-shell-docked");

    dispatchSpy.mockClear();
    act(() => {
      useUiStore.setState({ conciergeOpen: true, conciergePinned: true });
    });
    expect(shell.className).toContain("fathom-shell-docked");
    await waitFor(() =>
      expect(dispatchSpy.mock.calls.some(([e]) => (e as Event).type === "resize")).toBe(true),
    );
    dispatchSpy.mockRestore();
  });
});
