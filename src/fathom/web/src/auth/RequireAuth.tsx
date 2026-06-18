// Auth guard (frontend ADD §5). Wraps every protected route: it runs the whoami query
// (GET /api/v1/auth/me) and gates rendering on the result.
//
//   - loading            -> a spinner (never the unauthenticated app chrome)
//   - 401 / not authed   -> redirect to /login
//   - any other error    -> redirect to /login too (no session we can trust)
//   - authenticated      -> render the protected children (AppShell + routes)
//
// The session lives entirely in the httpOnly cookie; this guard holds no token, only the
// in-memory whoami principal cached by TanStack Query.

import { Navigate, Outlet } from "react-router-dom";

import { ApiError } from "../api/client";
import { useWhoAmI } from "../api/queries";

export function RequireAuth(): JSX.Element {
  const me = useWhoAmI();

  if (me.isLoading) {
    return (
      <div className="fathom-loading" role="status" aria-live="polite">
        <span className="fathom-spinner" aria-hidden="true" />
        <span>Loading…</span>
      </div>
    );
  }

  // A 401 (or any failure to read the principal) means we are not authenticated.
  if (me.isError) {
    const status = me.error instanceof ApiError ? me.error.status : undefined;
    if (status === undefined || status === 401 || (status >= 400 && status < 500)) {
      return <Navigate to="/login" replace />;
    }
    // 5xx etc. — bubble to the error boundary rather than masquerading as logged-out.
    throw me.error;
  }

  if (!me.data) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
