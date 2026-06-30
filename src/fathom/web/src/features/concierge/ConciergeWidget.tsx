// Concierge floating widget (ADR-035) — a VS-Code-style docked sidebar instead of a nav page.
// Shown only when the concierge is enabled server-side. On login it shows a floating bottom-right
// icon; if the user has *pinned* it before, it opens docked instead (pin persists in localStorage).
// The current page is passed to the chat as a soft context hint, so a question is read against the
// view you're on while cross-page questions still work.

import { useEffect } from "react";
import { useLocation } from "react-router-dom";

import { useServerConfig } from "../../api/queries";
import { useUiStore } from "../../state/uiStore";
import { ConciergeChat } from "./ConciergeChat";

const PIN_KEY = "fathom.concierge.pinned";

// Map a route path to a short page label used as the concierge's context hint.
function pageLabel(pathname: string): string {
  const seg = pathname.replace(/^\/+/, "").split("/")[0] || "dashboard";
  const labels: Record<string, string> = {
    explore: "explorer",
    "getting-started": "getting started",
  };
  return labels[seg] ?? seg;
}

export function ConciergeWidget(): JSX.Element | null {
  const config = useServerConfig();
  const open = useUiStore((s) => s.conciergeOpen);
  const pinned = useUiStore((s) => s.conciergePinned);
  const setOpen = useUiStore((s) => s.setConciergeOpen);
  const setPinned = useUiStore((s) => s.setConciergePinned);
  const location = useLocation();

  // On first mount, restore the pin preference: pinned → open docked; otherwise just the icon.
  useEffect(() => {
    if (typeof localStorage !== "undefined" && localStorage.getItem(PIN_KEY) === "1") {
      setPinned(true);
      setOpen(true);
    }
  }, [setPinned, setOpen]);

  // Hidden entirely until the server reports the concierge is enabled.
  if (!config.data?.concierge_enabled) return null;

  const togglePin = (): void => {
    const next = !pinned;
    setPinned(next);
    if (typeof localStorage !== "undefined") {
      if (next) localStorage.setItem(PIN_KEY, "1");
      else localStorage.removeItem(PIN_KEY);
    }
    if (next) setOpen(true);
  };

  if (!open) {
    return (
      <button
        type="button"
        className="fathom-cc-fab"
        aria-label="Open concierge"
        title="Ask the concierge"
        onClick={() => setOpen(true)}
      >
        <span aria-hidden="true">💬</span>
      </button>
    );
  }

  return (
    <aside className="fathom-cc-sidebar" aria-label="Concierge">
      <header className="fathom-cc-head">
        <strong>Concierge</strong>
        <div className="fathom-cc-head-actions">
          <button
            type="button"
            className="fathom-btn-mini"
            aria-pressed={pinned}
            title={pinned ? "Unpin (won't reopen on next login)" : "Pin (dock + reopen on login)"}
            onClick={togglePin}
          >
            {pinned ? "📌 Pinned" : "📌 Pin"}
          </button>
          <button
            type="button"
            className="fathom-btn-mini"
            aria-label="Close concierge"
            title="Close"
            onClick={() => setOpen(false)}
          >
            ✕
          </button>
        </div>
      </header>
      <ConciergeChat page={pageLabel(location.pathname)} />
    </aside>
  );
}
