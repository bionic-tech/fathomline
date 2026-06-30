// Auth guard + login wiring (BUG 1 regression). We mock the typed api client so no real fetch
// happens, then assert the guard's three states: unauthenticated -> /login, authenticated ->
// protected content, and that a successful login flips the guard from /login to the app.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RouterProvider, createMemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";

// Hoisted mock of the api client used by queries.ts and session.ts.
const { apiGet, apiPost } = vi.hoisted(() => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return { ...actual, apiGet, apiPost };
});

// Import after the mock is registered so routes/queries pick up the mocked client.
const { routes } = await import("../app/routes");
const { RequireAuth } = await import("./RequireAuth");

function renderApp(initial: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createMemoryRouter(routes, { initialEntries: [initial] });
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

const ME = {
  subject: "admin",
  source: "local",
  display_name: "Admin",
  groups: [],
  grants: [],
  mfa_fresh: true,
};

afterEach(() => {
  vi.clearAllMocks();
});

describe("auth guard", () => {
  it("redirects an unauthenticated user to the login page", async () => {
    apiGet.mockRejectedValue(new ApiError(401, { status: 401, title: "Unauthorized" }));

    renderApp("/dashboard");

    expect(await screen.findByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });

  it("renders the protected app shell when authenticated", async () => {
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") return Promise.resolve(ME);
      return Promise.resolve([]);
    });

    renderApp("/dashboard");

    // The "Sign out" chrome only renders inside the authenticated AppShell.
    expect(await screen.findByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });

  it("logs in and navigates into the app on success", async () => {
    // First whoami (guard for /dashboard) is unauthenticated -> /login. After login() we resolve.
    let authed = false;
    apiGet.mockImplementation((path: string) => {
      if (path === "/auth/me") {
        return authed
          ? Promise.resolve(ME)
          : Promise.reject(new ApiError(401, { status: 401, title: "Unauthorized" }));
      }
      return Promise.resolve([]);
    });
    apiPost.mockImplementation(() => {
      authed = true;
      return Promise.resolve(undefined);
    });

    renderApp("/dashboard");

    const username = await screen.findByLabelText("Username");
    fireEvent.change(username, { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith("/auth/login", {
        username: "admin",
        password: "hunter2",
      }),
    );
    expect(await screen.findByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });
});

describe("auth guard error branches", () => {
  // Render RequireAuth alone behind a known errorElement + a stub /login, so a thrown render error
  // is unambiguously distinguishable from a redirect-to-login (EC-nav-10 / EC-auth-22 / EC-auth-33).
  function renderGuard() {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const router = createMemoryRouter(
      [
        { path: "/dashboard", element: <RequireAuth />, errorElement: <div>error-boundary</div> },
        { path: "/login", element: <div>login-page</div> },
      ],
      { initialEntries: ["/dashboard"] },
    );
    return render(
      <QueryClientProvider client={client}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
  }

  it("bubbles a 5xx to the error boundary instead of masquerading as logged-out", async () => {
    apiGet.mockRejectedValue(new ApiError(503, { status: 503, title: "Service Unavailable" }));
    renderGuard();
    expect(await screen.findByText("error-boundary")).toBeInTheDocument();
    expect(screen.queryByText("login-page")).not.toBeInTheDocument();
  });

  it("redirects a non-401 4xx (e.g. 403) to the login page", async () => {
    apiGet.mockRejectedValue(new ApiError(403, { status: 403, title: "Forbidden" }));
    renderGuard();
    expect(await screen.findByText("login-page")).toBeInTheDocument();
    expect(screen.queryByText("error-boundary")).not.toBeInTheDocument();
  });

  it("redirects an undefined-status (non-ApiError network) failure to the login page", async () => {
    apiGet.mockRejectedValue(new Error("network down"));
    renderGuard();
    expect(await screen.findByText("login-page")).toBeInTheDocument();
    expect(screen.queryByText("error-boundary")).not.toBeInTheDocument();
  });
});
