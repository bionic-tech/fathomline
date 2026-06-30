// Notification bell (ADR-031): the in-app channel of the Notification Center. Shows an unread
// badge (cheap 30s poll) and, on open, the scope-filtered list with per-item + bulk "mark read".
// Rendered in the app shell only when notifications are enabled server-side. Read-only: dismissing
// is a benign acknowledgement, never an estate write.

import { useState } from "react";

import {
  useMarkAllNotificationsRead,
  useMarkNotificationsRead,
  useNotifications,
  useUnreadCount,
} from "../../api/queries";
import type { NotificationOut } from "../../api/types";

function severityClass(severity: string): string {
  if (severity === "critical") return "fathom-note-critical";
  if (severity === "warning") return "fathom-note-warning";
  return "fathom-note-info";
}

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export function NotificationBell(): JSX.Element {
  const [open, setOpen] = useState(false);
  const unread = useUnreadCount(true);
  const list = useNotifications(open); // only fetch the list while the panel is open
  const markRead = useMarkNotificationsRead();
  const markAll = useMarkAllNotificationsRead();

  const count = unread.data?.unread_count ?? 0;
  const items: NotificationOut[] = list.data?.items ?? [];

  return (
    <div className="fathom-bell">
      <button
        type="button"
        className="fathom-bell-button"
        aria-label={`Notifications${count > 0 ? `, ${count} unread` : ""}`}
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span aria-hidden="true">🔔</span>
        {count > 0 ? (
          <span className="fathom-bell-badge" aria-hidden="true">
            {count > 99 ? "99+" : count}
          </span>
        ) : null}
      </button>

      {open ? (
        <div className="fathom-bell-panel" role="dialog" aria-label="Notifications">
          <header className="fathom-bell-panel-head">
            <strong>Notifications</strong>
            <button
              type="button"
              onClick={() => markAll.mutate()}
              disabled={markAll.isPending || count === 0}
            >
              Mark all read
            </button>
          </header>

          {list.isLoading ? <p>Loading…</p> : null}
          {!list.isLoading && list.isError ? (
            <p role="alert" className="fathom-inline-error">
              Couldn&apos;t load notifications.
            </p>
          ) : null}
          {!list.isLoading && !list.isError && items.length === 0 ? (
            <p className="fathom-bell-empty">You&apos;re all caught up.</p>
          ) : null}

          <ul className="fathom-bell-list">
            {items.map((n) => (
              <li
                key={n.id}
                className={`fathom-note ${severityClass(n.severity)} ${
                  n.read ? "fathom-note-read" : "fathom-note-unread"
                }`}
              >
                <div className="fathom-note-row">
                  <span className="fathom-note-cat">{n.category}</span>
                  <span className="fathom-note-time">{when(n.created_at)}</span>
                </div>
                <div className="fathom-note-title">{n.title}</div>
                {n.body ? <div className="fathom-note-body">{n.body}</div> : null}
                {!n.read ? (
                  <button
                    type="button"
                    className="fathom-note-dismiss"
                    onClick={() => markRead.mutate([n.id])}
                    disabled={markRead.isPending}
                  >
                    Mark read
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
