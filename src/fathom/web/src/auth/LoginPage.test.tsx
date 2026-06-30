// LoginPage: posts credentials, navigates to /dashboard on success, and shows a sanitised inline
// error on failure (401 → "incorrect username or password"; anything else → generic).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const navigate = vi.fn();
vi.mock("react-router-dom", async (orig) => ({
  ...(await orig<typeof import("react-router-dom")>()),
  useNavigate: () => navigate,
}));

const { login } = vi.hoisted(() => ({ login: vi.fn() }));
vi.mock("./session", () => ({ login }));

const { LoginPage } = await import("./LoginPage");
const { ApiError } = await import("../api/client");

function wrap(): ReturnType<typeof render> {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function fillAndSubmit(): void {
  fireEvent.change(screen.getByLabelText(/username/i), { target: { value: "alice" } });
  fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
}

afterEach(() => vi.clearAllMocks());

describe("LoginPage", () => {
  it("logs in and navigates to /dashboard on success", async () => {
    login.mockResolvedValue(undefined);
    wrap();
    fillAndSubmit();
    await waitFor(() =>
      expect(login).toHaveBeenCalledWith({ username: "alice", password: "pw" }),
    );
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/dashboard", { replace: true }),
    );
  });

  it("shows a credential error on a 401", async () => {
    login.mockRejectedValue(new ApiError(401, {}));
    wrap();
    fillAndSubmit();
    expect(await screen.findByRole("alert")).toHaveTextContent(/incorrect username or password/i);
    expect(navigate).not.toHaveBeenCalled();
  });

  it("shows a generic error on a non-401 failure", async () => {
    login.mockRejectedValue(new Error("network"));
    wrap();
    fillAndSubmit();
    expect(await screen.findByRole("alert")).toHaveTextContent(/sign in failed/i);
  });
});
