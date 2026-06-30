// volumeLabel: prefer a synthetic volume's human display_name, else its mountpoint.

import { describe, expect, it } from "vitest";

import { volumeLabel } from "./types";

describe("volumeLabel", () => {
  it("prefers a set display_name", () => {
    expect(volumeLabel({ mountpoint: "/synthetic/x", display_name: "Cloud archive" })).toBe(
      "Cloud archive",
    );
  });

  it("falls back to the mountpoint when display_name is null or omitted", () => {
    expect(volumeLabel({ mountpoint: "/mnt/pool", display_name: null })).toBe("/mnt/pool");
    expect(volumeLabel({ mountpoint: "/mnt/pool" })).toBe("/mnt/pool");
  });
});
