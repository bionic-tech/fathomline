// Tabs (WAI-ARIA tabs pattern): tablist + one visible panel, lazy panel mount, arrow-key roving.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Tabs, type TabDef } from "./Tabs";

const TABS: TabDef[] = [
  { id: "a", label: "Alpha", content: <p>alpha-body</p> },
  { id: "b", label: "Beta", content: <p>beta-body</p> },
  { id: "c", label: "Gamma", content: <p>gamma-body</p> },
];

describe("Tabs", () => {
  it("renders the first tab active and only mounts the active panel", () => {
    render(<Tabs tabs={TABS} ariaLabel="Sections" />);
    expect(screen.getByRole("tab", { name: "Alpha" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("alpha-body")).toBeInTheDocument();
    // Inactive panels are lazy — their content is not in the DOM.
    expect(screen.queryByText("beta-body")).not.toBeInTheDocument();
  });

  it("switches panel on click", () => {
    render(<Tabs tabs={TABS} ariaLabel="Sections" />);
    fireEvent.click(screen.getByRole("tab", { name: "Beta" }));
    expect(screen.getByRole("tab", { name: "Beta" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("beta-body")).toBeInTheDocument();
    expect(screen.queryByText("alpha-body")).not.toBeInTheDocument();
  });

  it("honours initialId", () => {
    render(<Tabs tabs={TABS} ariaLabel="Sections" initialId="c" />);
    expect(screen.getByText("gamma-body")).toBeInTheDocument();
  });

  it("roves with ArrowRight (wrapping) and End (the handler is on each tab)", () => {
    render(<Tabs tabs={TABS} ariaLabel="Sections" />);
    fireEvent.keyDown(screen.getByRole("tab", { name: "Alpha" }), { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Beta" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(screen.getByRole("tab", { name: "Beta" }), { key: "End" });
    expect(screen.getByRole("tab", { name: "Gamma" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(screen.getByRole("tab", { name: "Gamma" }), { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Alpha" })).toHaveAttribute("aria-selected", "true"); // wrap
  });

  it("renders nothing for an empty tab set", () => {
    const { container } = render(<Tabs tabs={[]} ariaLabel="Sections" />);
    expect(container.querySelector("[role=tablist]")).toBeNull();
  });
});
