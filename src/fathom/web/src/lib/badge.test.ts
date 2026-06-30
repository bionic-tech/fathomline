// semanticBadgeClass: one status/result token → one semantic colour class, so colour means the
// same thing everywhere. Red is reserved for genuine failures; idle/unknown is neutral.

import { describe, expect, it } from "vitest";

import { semanticBadgeClass } from "./badge";

describe("semanticBadgeClass", () => {
  it("maps success-family tokens to success", () => {
    for (const v of ["ok", "granted", "completed", "online", "healthy"]) {
      expect(semanticBadgeClass(v)).toBe("fathom-badge-success");
    }
  });

  it("maps info / warning / danger families to their classes", () => {
    expect(semanticBadgeClass("built")).toBe("fathom-badge-info");
    expect(semanticBadgeClass("pending")).toBe("fathom-badge-warning");
    expect(semanticBadgeClass("partial")).toBe("fathom-badge-warning");
    expect(semanticBadgeClass("failed")).toBe("fathom-badge-danger");
    expect(semanticBadgeClass("denied")).toBe("fathom-badge-danger");
  });

  it("is case- and whitespace-insensitive", () => {
    expect(semanticBadgeClass("  GRANTED ")).toBe("fathom-badge-success");
  });

  it("falls back to neutral for idle / unknown / empty / null", () => {
    expect(semanticBadgeClass("idle")).toBe("fathom-badge-neutral");
    expect(semanticBadgeClass("something-unknown")).toBe("fathom-badge-neutral");
    expect(semanticBadgeClass("")).toBe("fathom-badge-neutral");
    expect(semanticBadgeClass(null)).toBe("fathom-badge-neutral");
    expect(semanticBadgeClass(undefined)).toBe("fathom-badge-neutral");
  });
});
