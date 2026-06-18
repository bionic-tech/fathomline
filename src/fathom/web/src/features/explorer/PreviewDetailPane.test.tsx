// PreviewDetailPane — metadata view + the on-demand sandboxed preview (ADR-014). apiGet is mocked.

import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiGet } = vi.hoisted(() => ({ apiGet: vi.fn() }));
vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet };
});

import { ApiError } from "../../api/client";
import type { TreeChildOut } from "../../api/types";
import { PreviewDetailPane } from "./PreviewDetailPane";

afterEach(() => {
  vi.clearAllMocks();
});

function fileEntry(over: Partial<TreeChildOut> = {}): TreeChildOut {
  return {
    entry_id: 7,
    path: "/data/a.png",
    name: "a.png",
    is_dir: false,
    is_symlink: false,
    size_logical: 10,
    size_on_disk: 10,
    subtree_size_logical: 10,
    subtree_size_on_disk: 10,
    file_count: 0,
    mtime: 1_700_000_000,
    uid: 0,
    gid: 0,
    inode: 42,
    flags: {},
    content_hash: null,
    ...over,
  };
}

describe("PreviewDetailPane", () => {
  it("shows metadata and offers an on-demand preview for a file", () => {
    render(<PreviewDetailPane entry={fileEntry()} />);
    expect(screen.getByText("a.png")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /generate preview/i })).toBeInTheDocument();
  });

  it("renders the image artifact returned by the preview endpoint", async () => {
    apiGet.mockResolvedValue({
      entry_id: 7,
      type: "image",
      cache_hit: false,
      sandbox_job_id: "j",
      artifacts: [{ kind: "thumbnail", media_type: "image/webp", data_b64: "QUJD", meta: {} }],
    });
    render(<PreviewDetailPane entry={fileEntry()} />);
    fireEvent.click(screen.getByRole("button", { name: /generate preview/i }));
    const img = await screen.findByRole("img", { name: /thumbnail/i });
    expect(img).toHaveAttribute("src", "data:image/webp;base64,QUJD");
    expect(apiGet).toHaveBeenCalledWith("/preview/7");
  });

  it("shows a friendly message when the type is unsupported (415)", async () => {
    apiGet.mockRejectedValue(new ApiError(415, { status: 415, title: "unsupported" }));
    render(<PreviewDetailPane entry={fileEntry()} />);
    fireEvent.click(screen.getByRole("button", { name: /generate preview/i }));
    expect(await screen.findByText(/isn't supported for this file type/i)).toBeInTheDocument();
  });

  it("shows a friendly message when preview is disabled on the server (503)", async () => {
    apiGet.mockRejectedValue(new ApiError(503, { status: 503, title: "off" }));
    render(<PreviewDetailPane entry={fileEntry()} />);
    fireEvent.click(screen.getByRole("button", { name: /generate preview/i }));
    expect(await screen.findByText(/isn't enabled on this server/i)).toBeInTheDocument();
  });

  it("offers no preview for a directory", () => {
    render(<PreviewDetailPane entry={fileEntry({ is_dir: true })} />);
    expect(
      screen.queryByRole("button", { name: /generate preview/i }),
    ).not.toBeInTheDocument();
  });
});
