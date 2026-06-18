import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../../api/client";
import type { BrowseResult } from "../../api/types";
import { DirTree } from "./DirTree";

function renderWith(node: ReactNode): ReturnType<typeof render> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

const RESULT: BrowseResult = {
  request_id: "r1",
  path: "/scan/data",
  truncated: false,
  error: null,
  entries: [
    {
      name: "docker",
      path: "/scan/data/docker",
      is_dir: true,
      is_symlink: false,
      size: 4096,
      mtime: 1,
      subtree_size: 10_000_000,
      subtree_file_count: 42,
      subtree_truncated: false,
    },
    {
      name: "notes.txt",
      path: "/scan/data/notes.txt",
      is_dir: false,
      is_symlink: false,
      size: 5,
      mtime: 1,
      subtree_size: null,
      subtree_file_count: null,
      subtree_truncated: false,
    },
  ],
};

describe("DirTree", () => {
  it("lazily lists directories (not files) on expand, with subtree size + count", async () => {
    const browse = vi.fn().mockResolvedValue(RESULT);
    renderWith(
      <DirTree
        roots={[{ path: "/scan/data", label: "/scan/data" }]}
        browse={browse}
        onInclude={vi.fn()}
        onExclude={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /scan\/data/i }));
    // the directory child appears with its bounded subtree rollup; the file child does NOT
    await waitFor(() => expect(screen.getByRole("button", { name: /docker/i })).toBeInTheDocument());
    expect(screen.getByText(/42 files/)).toBeInTheDocument();
    expect(screen.queryByText(/notes\.txt/)).not.toBeInTheDocument();
    expect(browse).toHaveBeenCalledWith("/scan/data");
  });

  it("fires onInclude / onExclude with the folder path", async () => {
    const onInclude = vi.fn();
    const onExclude = vi.fn();
    renderWith(
      <DirTree
        roots={[{ path: "/scan/data", label: "/scan/data" }]}
        browse={vi.fn().mockResolvedValue(RESULT)}
        onInclude={onInclude}
        onExclude={onExclude}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /scan\/data/i }));
    await waitFor(() => screen.getByRole("button", { name: /docker/i }));
    fireEvent.click(screen.getAllByRole("button", { name: /\+ scan/i })[0]);
    fireEvent.click(screen.getAllByRole("button", { name: /− exclude/i })[0]);
    expect(onInclude).toHaveBeenCalledWith("/scan/data");
    expect(onExclude).toHaveBeenCalledWith("/scan/data");
  });

  it("surfaces a step-up MFA prompt on a 401 from browse", async () => {
    const browse = vi.fn().mockRejectedValue(new ApiError(401, { detail: "step-up MFA required" }));
    renderWith(
      <DirTree
        roots={[{ path: "/scan/data", label: "/scan/data" }]}
        browse={browse}
        onInclude={vi.fn()}
        onExclude={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /scan\/data/i }));
    await waitFor(() => expect(screen.getByText(/step-up mfa required/i)).toBeInTheDocument());
    expect(screen.getByPlaceholderText(/6-digit code/i)).toBeInTheDocument();
  });
});
