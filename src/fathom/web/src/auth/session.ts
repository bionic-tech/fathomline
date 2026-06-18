// In-memory session helpers (frontend ADD §5/§12).
//
// No token or content ever touches localStorage/sessionStorage — the session lives in the
// server-side store behind an httpOnly Secure cookie, and the only client state is the
// whoami() principal, held in memory by TanStack Query. logout() revokes the server session
// and *clears all client storage* (frontend ADD §12: clear all storage on logout) so nothing
// sensitive survives a logout, defeating a later same-browser session.

import { apiGet, apiPost } from "../api/client";
import type { MeResponse } from "../api/types";

export interface LoginCredentials {
  username: string;
  password: string;
}

/** Local-mode login: mints the httpOnly session cookie server-side (no token returned). */
export async function login(creds: LoginCredentials): Promise<void> {
  await apiPost<void>("/auth/login", creds);
}

/** Fetch the authenticated principal + effective grants/scopes (drives scope-aware render). */
export async function whoami(): Promise<MeResponse> {
  // /auth/me is a GET on the server (returns 200 when authed, 401 when not). The query layer
  // (useWhoAmI) is the real read path; this helper mirrors it for callers/tests.
  return apiGet<MeResponse>("/auth/me");
}

/** Revoke the server session and clear ALL client storage (frontend ADD §12). */
export async function logout(): Promise<void> {
  try {
    await apiPost<void>("/auth/logout");
  } finally {
    clearAllClientStorage();
  }
}

/** Wipe every client-side store so no sensitive data survives logout (frontend ADD §12). */
export function clearAllClientStorage(): void {
  try {
    localStorage.clear();
    sessionStorage.clear();
  } catch {
    // Storage may be unavailable (private mode / SSR) — nothing to clear, fail silently.
  }
}
