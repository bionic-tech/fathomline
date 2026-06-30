// Breadcrumbs: a trail from the volume mountpoint to the current path; every segment except the
// last navigates (re-roots) to that ancestor; the last is the non-clickable current page.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

describe("Breadcrumbs", () => {
  it("renders the trail with the leaf as the current (non-button) page", async () => {
    const { Breadcrumbs } = await import("./Breadcrumbs");
    render(<Breadcrumbs mount="/mnt/pool" path="/mnt/pool/movies/2024" onNavigate={vi.fn()} />);
    // The leaf segment is the current page, not a button.
    const current = screen.getByText("2024");
    expect(current).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("button", { name: "2024" })).not.toBeInTheDocument();
    // Ancestors are navigable buttons.
    expect(screen.getByRole("button", { name: "movies" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "/mnt/pool" })).toBeInTheDocument();
  });

  it("navigates to the clicked ancestor's full path", async () => {
    const { Breadcrumbs } = await import("./Breadcrumbs");
    const onNavigate = vi.fn();
    render(<Breadcrumbs mount="/mnt/pool" path="/mnt/pool/movies/2024" onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole("button", { name: "movies" }));
    expect(onNavigate).toHaveBeenCalledWith("/mnt/pool/movies");
  });

  it("handles a path that equals the mount (root only)", async () => {
    const { Breadcrumbs } = await import("./Breadcrumbs");
    render(<Breadcrumbs mount="/mnt/pool" path="/mnt/pool" onNavigate={vi.fn()} />);
    expect(screen.getByText("/mnt/pool")).toHaveAttribute("aria-current", "page");
  });
});
