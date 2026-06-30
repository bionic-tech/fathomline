// Placeholder: a titled stand-in for surfaces delivered by a dependent component.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Placeholder } from "./Placeholder";

describe("Placeholder", () => {
  it("renders the title as a heading and the dependent-surface note", () => {
    render(<Placeholder title="Duplicates" />);
    expect(screen.getByRole("heading", { name: "Duplicates" })).toBeInTheDocument();
    expect(screen.getByText(/delivered by a dependent component/i)).toBeInTheDocument();
  });
});
