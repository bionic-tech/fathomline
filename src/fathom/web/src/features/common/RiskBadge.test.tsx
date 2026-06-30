// RiskBadge: a colored caution label for risky paths (OS/service/config); renders nothing for
// ordinary user data so it only ever draws attention where a delete/dedup deserves care.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RiskBadge } from "./RiskBadge";

describe("RiskBadge", () => {
  it("labels an OS path", () => {
    render(<RiskBadge path="/etc/passwd" />);
    const badge = screen.getByText("OS");
    expect(badge).toHaveClass("fathom-badge-risk-os");
    expect(badge).toHaveAttribute("title"); // the caution text
  });

  it("labels service data", () => {
    render(<RiskBadge path="/mnt/docker_data/db" />);
    expect(screen.getByText("Service data")).toBeInTheDocument();
  });

  it("renders nothing for ordinary user data", () => {
    const { container } = render(
      <RiskBadge path="/mnt/pool/photos/2024/img.jpg" name="img.jpg" />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
