import { describe, expect, it } from "vitest";

import { basename, formatBytes, formatBytesExact } from "./format";

describe("format", () => {
  it("formats sub-KB as bytes", () => {
    expect(formatBytes(512)).toBe("512 B");
  });
  it("formats KB/MB/GB/TB with familiar unit labels", () => {
    expect(formatBytes(1536)).toBe("1.50 KB");
    expect(formatBytes(1024 * 1024)).toBe("1.00 MB");
    expect(formatBytes(1024 ** 3)).toBe("1.00 GB");
    expect(formatBytes(1024 ** 4)).toBe("1.00 TB");
    expect(formatBytes(1024 ** 5)).toBe("1.00 PB");
  });
  it("guards negatives/NaN", () => {
    expect(formatBytes(-1)).toBe("—");
    expect(formatBytes(Number.NaN)).toBe("—");
  });
  it("formats exact bytes with separators", () => {
    expect(formatBytesExact(1500000)).toContain("B");
  });
  it("computes basename of a materialised path", () => {
    expect(basename("/mnt/pool/movies/")).toBe("movies");
    expect(basename("/mnt/pool")).toBe("pool");
  });
});
