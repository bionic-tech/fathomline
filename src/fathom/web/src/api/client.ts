// Typed same-origin fetch client for /api/v1 (frontend ADD §7, API ADD §2/§3/§5).
//
// - Same-origin only: the SPA is served by the api container, so requests are relative
//   ("/api/v1/…") and the httpOnly session cookie rides along automatically. No token is ever
//   read from or written to localStorage (frontend ADD §12 — in-memory + httpOnly session).
// - RFC 9457 problem+json: non-2xx responses are surfaced as a sanitised ApiError (the server
//   already strips internal paths/IPs/stack traces, API ADD §3). The client never renders a
//   stack trace (frontend ADD §11).
// - 429 backoff: honours Retry-After (API ADD §5) with a bounded number of retries.

export const API_BASE = "/api/v1";

/** A sanitised RFC 9457 problem surfaced to the UI (no internal detail). */
export interface ProblemDetail {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly problem: ProblemDetail;
  constructor(status: number, problem: ProblemDetail) {
    super(problem.title ?? problem.detail ?? `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }
}

const MAX_RETRIES = 3;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function parseProblem(res: Response): Promise<ProblemDetail> {
  try {
    const body = (await res.json()) as ProblemDetail;
    return { status: res.status, ...body };
  } catch {
    return { status: res.status, title: res.statusText };
  }
}

/** Build a query string from a record, dropping null/undefined values. */
export function toQuery(params: Record<string, string | number | boolean | undefined | null>): string {
  const usp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) usp.set(key, String(value));
  }
  const q = usp.toString();
  return q ? `?${q}` : "";
}

/** GET a typed JSON resource, with RFC9457 errors and 429 Retry-After backoff. */
export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  let attempt = 0;
  for (;;) {
    const res = await fetch(`${API_BASE}${path}`, {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      signal,
    });
    if (res.status === 429 && attempt < MAX_RETRIES) {
      const retryAfter = Number(res.headers.get("Retry-After") ?? "1");
      await sleep(Math.min(Number.isFinite(retryAfter) ? retryAfter : 1, 30) * 1000);
      attempt += 1;
      continue;
    }
    if (!res.ok) throw new ApiError(res.status, await parseProblem(res));
    return (await res.json()) as T;
  }
}

/** POST JSON (login/logout/MFA); 204 returns void. Same RFC9457 + cookie semantics. */
export async function apiPost<T>(path: string, body?: unknown): Promise<T | void> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new ApiError(res.status, await parseProblem(res));
  if (res.status === 204) return;
  return (await res.json()) as T;
}

/** PUT a resource (idempotent set, e.g. an agent config override); 204 returns void. */
export async function apiPut<T>(path: string, body?: unknown): Promise<T | void> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new ApiError(res.status, await parseProblem(res));
  if (res.status === 204) return;
  return (await res.json()) as T;
}

/** DELETE a resource (e.g. revoke a role assignment); 204 returns void. */
export async function apiDelete(path: string): Promise<void> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "DELETE",
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  });
  if (!res.ok) throw new ApiError(res.status, await parseProblem(res));
}
