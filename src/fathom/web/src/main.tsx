// SPA bootstrap (frontend ADD §3/§5/§6): QueryClientProvider + Router. No tokens/content in
// browser storage (frontend ADD §12) — the session is the httpOnly cookie; client state is
// in-memory TanStack Query + Zustand.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";

import { ApiError } from "./api/client";
import { ErrorBoundary } from "./app/ErrorBoundary";
import { routes } from "./app/routes";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Bounded retry with backoff; never spin on a 4xx (RFC9457 problem, frontend ADD §11).
      // A 401 means "not authenticated" — surface it immediately so the auth guard can redirect
      // to /login instead of retry-spamming the API with credentials it doesn't have.
      retry: (failureCount, error) => {
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
        return failureCount < 2;
      },
      refetchOnWindowFocus: false,
    },
  },
});

const router = createBrowserRouter(routes);

const rootEl = document.getElementById("root");
if (rootEl !== null) {
  createRoot(rootEl).render(
    <StrictMode>
      <ErrorBoundary>
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </ErrorBoundary>
    </StrictMode>,
  );
}
