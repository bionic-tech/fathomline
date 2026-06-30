// Typed fetch client: query-string building, RFC9457 ApiError mapping, 429 Retry-After backoff,
// and the 204→void contract. fetch is mocked; Retry-After is "0" so retries don't actually sleep.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiDelete, apiGet, apiPost, toQuery } from "./client";

interface FakeInit {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  jsonThrows?: boolean;
}

function res({ status = 200, body = {}, headers = {}, jsonThrows = false }: FakeInit): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: `status-${status}`,
    headers: new Headers(headers),
    json: async () => {
      if (jsonThrows) throw new Error("not json");
      return body;
    },
  } as unknown as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockReset();
});

describe("toQuery", () => {
  it("encodes set values and drops null/undefined", () => {
    expect(toQuery({ a: 1, b: "x y", c: null, d: undefined, e: false })).toBe("?a=1&b=x+y&e=false");
  });
  it("returns an empty string when nothing is set", () => {
    expect(toQuery({ a: null, b: undefined })).toBe("");
  });
});

describe("apiGet", () => {
  it("returns parsed JSON on 200", async () => {
    fetchMock.mockResolvedValueOnce(res({ body: [{ id: 1 }] }));
    expect(await apiGet("/x")).toEqual([{ id: 1 }]);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/x", expect.objectContaining({ method: "GET" }));
  });

  it("throws a sanitised ApiError on non-2xx", async () => {
    fetchMock.mockResolvedValueOnce(res({ status: 404, body: { detail: "unknown volume" } }));
    await expect(apiGet("/x")).rejects.toMatchObject({
      status: 404,
      problem: { detail: "unknown volume" },
    });
  });

  it("retries on 429 honouring Retry-After then succeeds", async () => {
    fetchMock
      .mockResolvedValueOnce(res({ status: 429, headers: { "Retry-After": "0" } }))
      .mockResolvedValueOnce(res({ body: { ok: true } }));
    expect(await apiGet("/x")).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("gives up after the retry budget and throws the 429", async () => {
    fetchMock.mockResolvedValue(res({ status: 429, headers: { "Retry-After": "0" } }));
    await expect(apiGet("/x")).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(4); // initial + 3 retries
  });

  it("falls back to statusText when the error body is not JSON", async () => {
    fetchMock.mockResolvedValueOnce(res({ status: 500, jsonThrows: true }));
    await expect(apiGet("/x")).rejects.toMatchObject({ status: 500, problem: { title: "status-500" } });
  });
});

describe("apiPost / apiDelete", () => {
  it("returns void on 204 and JSON otherwise", async () => {
    fetchMock.mockResolvedValueOnce(res({ status: 204 }));
    expect(await apiPost("/x", { a: 1 })).toBeUndefined();
    fetchMock.mockResolvedValueOnce(res({ body: { id: 9 } }));
    expect(await apiPost("/x")).toEqual({ id: 9 });
  });

  it("serialises the body and sets JSON content-type", async () => {
    fetchMock.mockResolvedValueOnce(res({ status: 204 }));
    await apiPost("/x", { a: 1 });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/x",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ a: 1 }) }),
    );
  });

  it("apiPost surfaces an ApiError on failure", async () => {
    fetchMock.mockResolvedValueOnce(res({ status: 403, body: { title: "forbidden" } }));
    await expect(apiPost("/x")).rejects.toMatchObject({ status: 403 });
  });

  it("apiDelete resolves on 204 and throws on error", async () => {
    fetchMock.mockResolvedValueOnce(res({ status: 204 }));
    await expect(apiDelete("/x")).resolves.toBeUndefined();
    fetchMock.mockResolvedValueOnce(res({ status: 409, body: { detail: "last admin" } }));
    await expect(apiDelete("/x")).rejects.toMatchObject({ status: 409 });
  });
});
