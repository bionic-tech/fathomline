// Notification bell tests (ADR-031): shows the unread badge, opens the panel to list items, and
// dismisses (mark-read) through the API.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

const { NotificationBell } = await import("./NotificationBell");

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(() => vi.clearAllMocks());

it("shows the unread badge and lists notifications on open", async () => {
  apiGet.mockImplementation((path: string) => {
    if (path.startsWith("/notifications/unread-count")) return Promise.resolve({ unread_count: 2 });
    return Promise.resolve({
      unread_count: 2,
      items: [
        {
          id: 1,
          category: "problem",
          severity: "warning",
          title: "Disk 92% full",
          body: "nas-1 / tank",
          source: "capacity",
          created_at: "2026-06-19T10:00:00Z",
          read: false,
        },
      ],
    });
  });

  wrap(<NotificationBell />);
  // Badge shows the unread count.
  expect(await screen.findByText("2")).toBeInTheDocument();
  // Open the panel → the item renders.
  fireEvent.click(screen.getByRole("button", { name: /notifications/i }));
  expect(await screen.findByText("Disk 92% full")).toBeInTheDocument();
});

it("marks a notification read", async () => {
  apiGet.mockImplementation((path: string) => {
    if (path.startsWith("/notifications/unread-count")) return Promise.resolve({ unread_count: 1 });
    return Promise.resolve({
      unread_count: 1,
      items: [
        {
          id: 7,
          category: "activity",
          severity: "info",
          title: "Scan completed",
          body: "",
          source: "scans",
          created_at: "2026-06-19T11:00:00Z",
          read: false,
        },
      ],
    });
  });
  apiPost.mockResolvedValue({ marked: 1 });

  wrap(<NotificationBell />);
  fireEvent.click(await screen.findByRole("button", { name: /notifications/i }));
  fireEvent.click(await screen.findByRole("button", { name: /^mark read$/i }));
  await waitFor(() =>
    expect(apiPost).toHaveBeenCalledWith("/notifications/mark-read", { ids: [7] }),
  );
});

it("marks all read via /notifications/mark-all-read (UC-notifications-4)", async () => {
  apiGet.mockImplementation((path: string) => {
    if (path.startsWith("/notifications/unread-count")) return Promise.resolve({ unread_count: 3 });
    return Promise.resolve({
      unread_count: 3,
      items: [
        {
          id: 1,
          category: "problem",
          severity: "warning",
          title: "Disk 92% full",
          body: "",
          source: "capacity",
          created_at: "2026-06-19T10:00:00Z",
          read: false,
        },
      ],
    });
  });
  apiPost.mockResolvedValue({ marked: 3 });

  wrap(<NotificationBell />);
  fireEvent.click(await screen.findByRole("button", { name: /notifications/i }));
  const markAll = await screen.findByRole("button", { name: /mark all read/i });
  expect(markAll).toBeEnabled();
  fireEvent.click(markAll);
  // The bulk endpoint takes no body (mark every in-scope unread).
  await waitFor(() => expect(apiPost).toHaveBeenCalledWith("/notifications/mark-all-read"));
});

it("shows the caught-up empty state with a hidden badge and disabled bulk action (EC-notifications-4)", async () => {
  apiGet.mockImplementation((path: string) => {
    if (path.startsWith("/notifications/unread-count")) return Promise.resolve({ unread_count: 0 });
    return Promise.resolve({ unread_count: 0, items: [] });
  });

  const { container } = wrap(<NotificationBell />);
  // Zero unread → the bell carries no "…unread" suffix and renders no badge element.
  const bell = await screen.findByRole("button", { name: "Notifications" });
  expect(container.querySelector(".fathom-bell-badge")).toBeNull();

  fireEvent.click(bell);
  expect(await screen.findByText(/caught up/i)).toBeInTheDocument();
  // "Mark all read" is disabled when there is nothing to mark.
  expect(screen.getByRole("button", { name: /mark all read/i })).toBeDisabled();
});

it("shows an error affordance (not the caught-up copy) when the list fetch fails", async () => {
  // The unread-count poll and the list are independent queries. If only the list fails, the badge
  // still shows from the healthy count poll; the panel now distinguishes the failure with its own
  // error alert instead of reading as "caught up". (Previously this asserted the caught-up copy —
  // that silent-degradation behaviour, where a list error was indistinguishable from an empty
  // list, has been flipped.)
  apiGet.mockImplementation((path: string) => {
    if (path.startsWith("/notifications/unread-count")) return Promise.resolve({ unread_count: 2 });
    return Promise.reject(new Error("list 500"));
  });

  wrap(<NotificationBell />);
  expect(await screen.findByText("2")).toBeInTheDocument(); // badge from the still-healthy count poll
  fireEvent.click(screen.getByRole("button", { name: /notifications/i }));
  expect(await screen.findByRole("dialog", { name: /notifications/i })).toBeInTheDocument();
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(/couldn't load notifications/i);
  expect(screen.queryByText(/caught up/i)).not.toBeInTheDocument();
});
