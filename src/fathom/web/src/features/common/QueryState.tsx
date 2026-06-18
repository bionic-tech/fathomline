// Shared loading / error / empty rendering for the data-driven feature pages. Errors are
// surfaced from the sanitised ApiError only — never a stack trace or internal path (frontend
// ADD §11). A 403/404 from a not-yet-deployed read endpoint is rendered as a calm "unavailable"
// state rather than a crash, so a partially-provisioned backend still renders the shell.

import type { ReactNode } from "react";

import { ApiError } from "../../api/client";

export interface QueryStateProps {
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  isEmpty?: boolean;
  emptyLabel?: string;
  children: ReactNode;
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return "You do not have access to this data.";
    if (error.status === 404) return "This surface is not available on this deployment yet.";
    return error.problem.title ?? error.problem.detail ?? `Request failed (${error.status}).`;
  }
  return "Something went wrong loading this data.";
}

export function QueryState({
  isLoading,
  isError,
  error,
  isEmpty = false,
  emptyLabel = "Nothing to show.",
  children,
}: QueryStateProps): JSX.Element {
  if (isLoading) {
    return (
      <p role="status" className="fathom-muted">
        Loading…
      </p>
    );
  }
  if (isError) {
    return (
      <p role="alert" className="fathom-inline-error">
        {messageFor(error)}
      </p>
    );
  }
  if (isEmpty) {
    return <p className="fathom-muted">{emptyLabel}</p>;
  }
  return <>{children}</>;
}
