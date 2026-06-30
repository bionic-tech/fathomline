// Route table with route-level code splitting (frontend ADD §6/§10). Lazy imports keep the
// initial bundle small; each surface loads on navigation.

import { lazy, Suspense } from "react";
import { Navigate, type RouteObject } from "react-router-dom";

import { RequireAuth } from "../auth/RequireAuth";
import { AppShell } from "./AppShell";

const Dashboard = lazy(() =>
  import("../features/dashboard/Dashboard").then((m) => ({ default: m.Dashboard })),
);
const Explorer = lazy(() =>
  import("../features/explorer/Explorer").then((m) => ({ default: m.Explorer })),
);
const Largest = lazy(() =>
  import("../features/largest/Largest").then((m) => ({ default: m.Largest })),
);
const Changes = lazy(() =>
  import("../features/changes/Changes").then((m) => ({ default: m.Changes })),
);
const Search = lazy(() =>
  import("../features/search/Search").then((m) => ({ default: m.Search })),
);
const Organize = lazy(() =>
  import("../features/organize/Organize").then((m) => ({ default: m.Organize })),
);
const GettingStarted = lazy(() =>
  import("../features/onboarding/GettingStarted").then((m) => ({ default: m.GettingStarted })),
);
const Duplicates = lazy(() =>
  import("../features/duplicates/Duplicates").then((m) => ({ default: m.Duplicates })),
);
const Reconcile = lazy(() =>
  import("../features/reconcile/Reconcile").then((m) => ({ default: m.Reconcile })),
);
const Scans = lazy(() =>
  import("../features/scans/Scans").then((m) => ({ default: m.Scans })),
);
const Agents = lazy(() =>
  import("../features/agents/Agents").then((m) => ({ default: m.Agents })),
);
const Deploy = lazy(() =>
  import("../features/deploy/Deploy").then((m) => ({ default: m.Deploy })),
);
const Audit = lazy(() =>
  import("../features/audit/Audit").then((m) => ({ default: m.Audit })),
);
const Settings = lazy(() =>
  import("../features/settings/Settings").then((m) => ({ default: m.Settings })),
);
const LoginPage = lazy(() =>
  import("../auth/LoginPage").then((m) => ({ default: m.LoginPage })),
);
// First-run setup wizard (Build P4): an estate-wide modal that overlays the whole authenticated app
// on first run. Code-split (it renders null whenever it shouldn't show) and mounted ALONGSIDE the
// AppShell layout — not inside it — so the shell stays a pure layout component.
const SetupWizardModal = lazy(() =>
  import("../features/onboarding/SetupWizardModal").then((m) => ({
    default: m.SetupWizardModal,
  })),
);

function withSuspense(node: JSX.Element): JSX.Element {
  return <Suspense fallback={<p role="status">Loading…</p>}>{node}</Suspense>;
}

// The authenticated layout: the AppShell chrome (which renders the matched child route in its
// <Outlet/>) plus the first-run setup modal overlaid on top.
function AppLayout(): JSX.Element {
  return (
    <>
      <AppShell />
      <Suspense fallback={null}>
        <SetupWizardModal />
      </Suspense>
    </>
  );
}

export const routes: RouteObject[] = [
  // Public: the only route reachable without a session.
  { path: "/login", element: withSuspense(<LoginPage />) },
  // Protected: the auth guard runs whoami and redirects unauthenticated users to /login
  // before any AppShell chrome or scoped data query renders.
  {
    path: "/",
    element: <RequireAuth />,
    children: [
      {
        path: "/",
        element: <AppLayout />,
        children: [
          { index: true, element: <Navigate to="/dashboard" replace /> },
          { path: "dashboard", element: withSuspense(<Dashboard />) },
          { path: "explore", element: withSuspense(<Explorer />) },
          { path: "search", element: withSuspense(<Search />) },
          { path: "largest", element: withSuspense(<Largest />) },
          { path: "organize", element: withSuspense(<Organize />) },
          { path: "getting-started", element: withSuspense(<GettingStarted />) },
          { path: "changes", element: withSuspense(<Changes />) },
          { path: "duplicates", element: withSuspense(<Duplicates />) },
          { path: "reconcile", element: withSuspense(<Reconcile />) },
          { path: "scans", element: withSuspense(<Scans />) },
          { path: "agents", element: withSuspense(<Agents />) },
          { path: "deploy", element: withSuspense(<Deploy />) },
          { path: "audit", element: withSuspense(<Audit />) },
          { path: "settings", element: withSuspense(<Settings />) },
        ],
      },
    ],
  },
];
