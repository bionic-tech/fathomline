// Error boundary (frontend ADD §11): hides stack traces in production (DEV-guarded), shows a
// sanitised message only. No internal paths/IPs/stack traces ever reach the rendered UI.

import { Component, type ErrorInfo, type ReactNode } from "react";

import { devError, IS_DEV } from "../lib/csp";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    devError("render error", error, info);
  }

  render(): ReactNode {
    if (this.state.error !== null) {
      return (
        <div role="alert" className="fathom-error">
          <h1>Something went wrong</h1>
          <p>The view could not be displayed. Please retry.</p>
          {IS_DEV ? <pre>{this.state.error.message}</pre> : null}
        </div>
      );
    }
    return this.props.children;
  }
}
