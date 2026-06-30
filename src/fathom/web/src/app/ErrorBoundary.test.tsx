// ErrorBoundary (frontend ADD §11): a render error is caught and shown as a sanitised alert; a
// healthy subtree renders untouched.

import { render, screen } from "@testing-library/react";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { ErrorBoundary } from "./ErrorBoundary";

function Boom(): JSX.Element {
  throw new Error("kaboom-internal-detail");
}

describe("ErrorBoundary", () => {
  // React logs the caught error to console.error; silence it so the test output stays clean.
  beforeAll(() => vi.spyOn(console, "error").mockImplementation(() => {}));
  afterAll(() => vi.restoreAllMocks());

  it("renders children when nothing throws", () => {
    render(
      <ErrorBoundary>
        <p>healthy</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("healthy")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("catches a render error and shows the sanitised fallback alert", () => {
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/something went wrong/i);
    expect(alert).toHaveTextContent(/could not be displayed/i);
  });
});
