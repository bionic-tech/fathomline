// Deploy wizard render tests: RBAC gating (admin-only) + the pull-enrolment happy path. The api
// client is mocked so no real fetch happens; we assert the UX surfaces the server contract.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { ApiError } = await import("../../api/client");
const { Deploy } = await import("./Deploy");

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function meWith(role: string) {
  return {
    subject: "u",
    source: "local",
    display_name: "U",
    groups: [],
    grants: [{ role, scope_kind: "global", host_id: null, volume_id: null }],
    mfa_fresh: true,
  };
}

afterEach(() => vi.clearAllMocks());

describe("Deploy page", () => {
  it("refuses to render for a non-admin principal", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("viewer")) : Promise.resolve({}),
    );
    wrap(<Deploy />);
    expect(
      await screen.findByText(/requires the deploy_agent capability/i),
    ).toBeInTheDocument();
  });

  it("shows push/pull modes for an admin and generates a pull command", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("admin")) : Promise.resolve({}),
    );
    apiPost.mockImplementation((path: string) =>
      path === "/deployment/enroll"
        ? Promise.resolve({
            host_id: "node-2",
            token: "TOK123",
            command: "curl -fsSL http://core/api/v1/deployment/enroll/TOK123/bundle | sh",
            expires_at: "2026-06-10T10:00:00+00:00",
          })
        : Promise.resolve({}),
    );
    wrap(<Deploy />);

    // Switch to pull mode, fill the host id, generate.
    fireEvent.click(await screen.findByRole("tab", { name: /pull/i }));
    fireEvent.change(screen.getByPlaceholderText("nas-1"), {
      target: { value: "node-2" },
    });
    fireEvent.click(screen.getByRole("button", { name: /generate command/i }));

    await waitFor(() =>
      expect(screen.getByText(/enroll\/TOK123\/bundle/)).toBeInTheDocument(),
    );
    expect(apiPost).toHaveBeenCalledWith(
      "/deployment/enroll",
      expect.objectContaining({ host_id: "node-2" }),
    );
  });

  it("prompts for step-up MFA on 401, then retries the enrol after verify (round-3)", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("admin")) : Promise.resolve({}),
    );
    let enrollCalls = 0;
    apiPost.mockImplementation((path: string) => {
      if (path === "/deployment/enroll") {
        enrollCalls += 1;
        if (enrollCalls === 1) return Promise.reject(new ApiError(401, { detail: "step-up" }));
        return Promise.resolve({ host_id: "h", token: "T2", command: "enroll/T2/bundle ok", expires_at: "x" });
      }
      if (path === "/auth/mfa/verify") return Promise.resolve(undefined);
      return Promise.resolve({});
    });
    wrap(<Deploy />);
    fireEvent.click(await screen.findByRole("tab", { name: /pull/i }));
    fireEvent.change(screen.getByPlaceholderText("nas-1"), { target: { value: "h" } });
    fireEvent.click(screen.getByRole("button", { name: /generate command/i }));

    // The MFA step-up form appears after the 401.
    const code = await screen.findByLabelText(/totp code/i);
    fireEvent.change(code, { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: /verify & continue/i }));

    await waitFor(() => expect(screen.getByText(/enroll\/T2\/bundle/)).toBeInTheDocument());
    expect(apiPost).toHaveBeenCalledWith("/auth/mfa/verify", { code: "123456" });
    expect(enrollCalls).toBe(2); // retried after verify
  });

  it("clears a pending step-up when switching modes (round-3 P2)", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("admin")) : Promise.resolve({}),
    );
    apiPost.mockImplementation((path: string) =>
      path === "/deployment/enroll"
        ? Promise.reject(new ApiError(401, { detail: "step-up" }))
        : Promise.resolve({}),
    );
    wrap(<Deploy />);
    fireEvent.click(await screen.findByRole("tab", { name: /pull/i }));
    fireEvent.change(screen.getByPlaceholderText("nas-1"), { target: { value: "h" } });
    fireEvent.click(screen.getByRole("button", { name: /generate command/i }));
    await screen.findByLabelText(/totp code/i); // MFA form is up

    fireEvent.click(screen.getByRole("tab", { name: /push/i })); // switch mode
    expect(screen.queryByLabelText(/totp code/i)).not.toBeInTheDocument(); // cleared
  });

  it("sends an added rclone remote target in the enrol request (ADR-029)", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("admin")) : Promise.resolve({}),
    );
    apiPost.mockImplementation((path: string) =>
      path === "/deployment/enroll"
        ? Promise.resolve({ host_id: "cloud-1", token: "T", command: "enroll/T/bundle", expires_at: "x" })
        : Promise.resolve({}),
    );
    wrap(<Deploy />);
    fireEvent.click(await screen.findByRole("tab", { name: /pull/i }));
    fireEvent.change(screen.getByPlaceholderText("nas-1"), { target: { value: "cloud-1" } });
    // Add a remote target and fill the rclone remote name + path.
    fireEvent.click(screen.getByRole("button", { name: /add remote target/i }));
    fireEvent.change(screen.getByPlaceholderText(/remote name/i), { target: { value: "gdrive" } });
    fireEvent.change(screen.getByPlaceholderText(/remote path/i), { target: { value: "/Backups" } });
    fireEvent.click(screen.getByRole("button", { name: /generate command/i }));

    await waitFor(() =>
      expect(apiPost).toHaveBeenCalledWith(
        "/deployment/enroll",
        expect.objectContaining({
          host_id: "cloud-1",
          remote_targets: [{ protocol: "rclone", host: "gdrive", remote_path: "/Backups" }],
        }),
      ),
    );
  });

  it("blocks password deploy without a pinned host key (round-3 needsPin)", async () => {
    apiGet.mockImplementation((path: string) =>
      path === "/auth/me" ? Promise.resolve(meWith("admin")) : Promise.resolve({}),
    );
    wrap(<Deploy />);
    await screen.findByRole("tab", { name: /push/i }); // push is the default mode
    // Switch the auth method to password.
    fireEvent.change(screen.getByDisplayValue(/ssh key/i), { target: { value: "password" } });
    fireEvent.change(screen.getByPlaceholderText("203.0.113.20"), { target: { value: "10.0.0.9" } });
    fireEvent.change(screen.getByPlaceholderText("nas-1"), { target: { value: "h" } });
    const deployBtn = screen.getByRole("button", { name: /deploy this host/i });
    expect(deployBtn).toBeDisabled(); // needsPin → disabled until a key is pinned
  });
});
