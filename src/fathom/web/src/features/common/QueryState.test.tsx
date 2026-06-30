// QueryState: shared loading / error / empty / ready rendering. 403 and 404 from a not-yet-deployed
// endpoint render as calm copy (never a crash); other errors fall back to a generic message.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { QueryState } from "./QueryState";
import { ApiError } from "../../api/client";

const READY = <p>ready-content</p>;

describe("QueryState", () => {
  it("shows a loading status", () => {
    render(
      <QueryState isLoading isError={false} error={null}>
        {READY}
      </QueryState>,
    );
    expect(screen.getByRole("status")).toHaveTextContent(/loading/i);
  });

  it("maps a 403 to a calm no-access message", () => {
    render(
      <QueryState isLoading={false} isError error={new ApiError(403, {})}>
        {READY}
      </QueryState>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/do not have access/i);
  });

  it("maps a 404 to a not-available-yet message", () => {
    render(
      <QueryState isLoading={false} isError error={new ApiError(404, {})}>
        {READY}
      </QueryState>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/not available on this deployment/i);
  });

  it("falls back to a generic message for a non-ApiError", () => {
    render(
      <QueryState isLoading={false} isError error={new Error("boom")}>
        {READY}
      </QueryState>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/something went wrong/i);
  });

  it("shows the empty label when isEmpty", () => {
    render(
      <QueryState isLoading={false} isError={false} error={null} isEmpty emptyLabel="No rows.">
        <p>ready-content</p>
      </QueryState>,
    );
    expect(screen.getByText("No rows.")).toBeInTheDocument();
    expect(screen.queryByText("ready-content")).not.toBeInTheDocument();
  });

  it("renders children when ready", () => {
    render(
      <QueryState isLoading={false} isError={false} error={null}>
        <p>ready-content</p>
      </QueryState>,
    );
    expect(screen.getByText("ready-content")).toBeInTheDocument();
  });
});
