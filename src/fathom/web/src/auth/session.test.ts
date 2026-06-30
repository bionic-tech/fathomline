// Session helpers (frontend ADD §5/§12): login/whoami proxy the client; logout revokes the server
// session and clears ALL client storage — even if the revoke call fails (finally), so nothing
// sensitive survives a logout.

import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../api/client", () => ({ apiGet, apiPost }));

const { login, whoami, logout, clearAllClientStorage } = await import("./session");

afterEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
});

describe("session helpers", () => {
  it("login posts credentials to /auth/login", async () => {
    apiPost.mockResolvedValue(undefined);
    await login({ username: "alice", password: "pw" });
    expect(apiPost).toHaveBeenCalledWith("/auth/login", { username: "alice", password: "pw" });
  });

  it("whoami gets /auth/me", async () => {
    apiGet.mockResolvedValue({ subject: "alice" });
    expect(await whoami()).toEqual({ subject: "alice" });
    expect(apiGet).toHaveBeenCalledWith("/auth/me");
  });

  it("logout revokes the server session and clears client storage", async () => {
    apiPost.mockResolvedValue(undefined);
    localStorage.setItem("k", "v");
    sessionStorage.setItem("s", "v");
    await logout();
    expect(apiPost).toHaveBeenCalledWith("/auth/logout");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("logout STILL clears storage when the revoke call fails", async () => {
    apiPost.mockRejectedValue(new Error("network down"));
    localStorage.setItem("k", "v");
    await expect(logout()).rejects.toThrow("network down");
    expect(localStorage.length).toBe(0); // cleared in the finally block
  });

  it("clearAllClientStorage wipes both stores", () => {
    localStorage.setItem("a", "1");
    sessionStorage.setItem("b", "2");
    clearAllClientStorage();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
