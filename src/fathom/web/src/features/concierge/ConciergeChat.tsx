// Concierge chat (ADR-035) — a conversational, read-only assistant over the catalogue. The server
// classifies each question to ONE closed-enum tool, runs the matching scope-enforcing query, and
// narrates it; the model has no authority and every citation is built server-side. It keeps a
// short client-held conversation history (memory) so follow-ups like "and on host 2?" resolve, and
// sends the current page + scoped volume as soft context. Off-topic questions are refused
// server-side; ambiguous ones get a clarifying question back.

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { ApiError } from "../../api/client";
import { useConciergeAsk, useVolumes } from "../../api/queries";
import type { ConciergeActionOut, ConciergeCitationOut, ConciergeTurn } from "../../api/types";
import { displayPath } from "../../lib/format";
import { useNames } from "../../lib/names";
import { useUiStore } from "../../state/uiStore";

interface ChatMsg {
  role: "user" | "assistant";
  text: string;
  citations?: ConciergeCitationOut[];
  actions?: ConciergeActionOut[];
  tool?: string;
  considered?: number;
  error?: boolean;
}

function gateMessage(e: unknown): string | null {
  if (e instanceof ApiError) {
    if (e.status === 403)
      return (
        "The concierge is turned OFF on this server. It's opt-in because it asks an AI model to " +
        "interpret your question. Enable it in Settings → Configuration → AI concierge (or set " +
        "FATHOM_CONCIERGE_ENABLED), with a reachable model. (Or a volume you named is out of scope.)"
      );
    if (e.status === 504) return "The model took too long. Try a simpler question.";
    if (e.status === 503 || e.status === 502)
      return "The inference model is unavailable — is the configured provider reachable?";
  }
  return null;
}

const EXAMPLES = [
  "Where is budget.xlsx — and was it deleted?",
  "How much free space is left across the fleet?",
  "What's eating my space on this volume?",
  "When will my disks fill up?",
  "How much can I reclaim from duplicates?",
];

const MAX_HISTORY = 12; // turns sent as context (server caps further)

// /command word → forced concierge tool (deterministic; skips the LLM classify).
const FORCED_TOOLS: Record<string, string> = {
  find: "find_file",
  largest: "largest",
  big: "largest",
  duplicates: "reclaimable",
  reclaim: "reclaimable",
  forecast: "forecast",
  fills: "forecast",
  storage: "fleet_storage",
  disks: "fleet_storage",
  hot: "hot_folders",
  search: "semantic_search",
  scanned: "coverage",
  coverage: "coverage",
};

// /go <page> → route. Friendly aliases for the nav targets.
const PAGES: Record<string, string> = {
  dashboard: "/dashboard",
  explorer: "/explore",
  explore: "/explore",
  search: "/search",
  largest: "/largest",
  organize: "/organize",
  changes: "/changes",
  duplicates: "/duplicates",
  reconcile: "/reconcile",
  scans: "/scans",
  agents: "/agents",
  deploy: "/deploy",
  audit: "/audit",
  settings: "/settings",
  "getting-started": "/getting-started",
};

const COMMANDS_HELP =
  "Commands: /find <name>, /largest, /forecast, /duplicates, /storage, /scanned, /hot, " +
  "/search <text>, /go <page>, /scope <volume|all>, /clear, /help. " +
  "You can also just ask in plain language.";

export function ConciergeChat({ page }: { page?: string }): JSX.Element {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const ask = useConciergeAsk();
  const volumes = useVolumes();
  const { hostName } = useNames();
  const selectVolume = useUiStore((s) => s.selectVolume);
  const selectPath = useUiStore((s) => s.selectPath);
  const selectedVolumeId = useUiStore((s) => s.selectedVolumeId);
  const navigate = useNavigate();
  const bodyRef = useRef<HTMLDivElement>(null);

  // Keep the latest message in view as the thread grows / while thinking. (Optional-call: jsdom
  // and some environments don't implement Element.scrollTo.)
  useEffect(() => {
    bodyRef.current?.scrollTo?.({ top: bodyRef.current.scrollHeight });
  }, [messages, ask.isPending]);

  const addBot = (text: string, error = false): void =>
    setMessages((m) => [...m, { role: "assistant", text, error }]);

  // Send to the API. `display` is the user-bubble text (the typed command for /commands); `apiQ`
  // is what the server sees as the question; `forcedTool` skips the LLM classify when set.
  const send = async (apiQ: string, display: string, forcedTool?: string): Promise<void> => {
    const history: ConciergeTurn[] = messages
      .filter((m) => !m.error)
      .slice(-MAX_HISTORY)
      .map((m) => ({ role: m.role, content: m.text }));
    setMessages((m) => [...m, { role: "user", text: display }]);
    try {
      const res = await ask.mutateAsync({
        question: apiQ,
        page,
        ...(selectedVolumeId != null ? { volume_id: selectedVolumeId } : {}),
        ...(history.length ? { history } : {}),
        ...(forcedTool ? { tool: forcedTool } : {}),
      });
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          text: res.answer,
          citations: res.citations,
          actions: res.actions,
          tool: res.tool,
          considered: res.considered,
        },
      ]);
    } catch (e) {
      const msg =
        gateMessage(e) ??
        (e instanceof ApiError
          ? (e.problem.detail ?? e.problem.title ?? "The question failed.")
          : "The question failed.");
      addBot(msg, true);
    }
  };

  // A leading "/" is a command: navigation/scope/help run locally; data commands force a tool.
  const handleSlash = (text: string): void => {
    const [word, ...rest] = text.slice(1).split(/\s+/);
    const cmd = word.toLowerCase();
    const arg = rest.join(" ").trim();
    if (cmd === "help" || cmd === "?") {
      setMessages((m) => [...m, { role: "user", text }]);
      addBot(COMMANDS_HELP);
      return;
    }
    if (cmd === "clear" || cmd === "new") {
      setMessages([]);
      return;
    }
    if (cmd === "go") {
      const route = PAGES[arg.toLowerCase()];
      setMessages((m) => [...m, { role: "user", text }]);
      if (route) {
        navigate(route);
        addBot(`Opened ${arg}.`);
      } else {
        addBot(`Unknown page "${arg}". Try one of: ${Object.keys(PAGES).join(", ")}.`);
      }
      return;
    }
    if (cmd === "scope") {
      setMessages((m) => [...m, { role: "user", text }]);
      if (arg.toLowerCase() === "all" || arg === "") {
        selectVolume(null, null, null);
        addBot("Scope set to all volumes (estate).");
        return;
      }
      const vol = volumes.data?.find(
        (v) =>
          v.mountpoint.toLowerCase().includes(arg.toLowerCase()) ||
          (v.display_name ?? "").toLowerCase().includes(arg.toLowerCase()),
      );
      if (vol) {
        selectVolume(vol.host_id, vol.id, vol.mountpoint);
        addBot(`Scope set to ${vol.mountpoint} (${hostName(vol.host_id)}).`);
      } else {
        addBot(`No volume matching "${arg}".`);
      }
      return;
    }
    const tool = FORCED_TOOLS[cmd];
    if (tool) {
      if (tool === "find_file" && !arg) {
        setMessages((m) => [...m, { role: "user", text }]);
        addBot("Usage: /find <name or path>.");
        return;
      }
      // find_file/semantic_search use the arg as the search text; others ignore it.
      void send(tool === "find_file" || tool === "semantic_search" ? arg : cmd, text, tool);
      return;
    }
    setMessages((m) => [...m, { role: "user", text }]);
    addBot(`Unknown command "/${cmd}". ${COMMANDS_HELP}`);
  };

  const run = (q?: string): void => {
    const text = (q ?? question).trim();
    if (text.length === 0 || ask.isPending) return;
    setQuestion("");
    if (text.startsWith("/")) {
      handleSlash(text);
      return;
    }
    void send(text, text);
  };

  const jumpTo = (c: ConciergeCitationOut): void => {
    if (c.path == null || c.volume_id == null) return;
    const vol = volumes.data?.find((v) => v.id === c.volume_id);
    if (!vol) return;
    selectVolume(vol.host_id, vol.id, vol.mountpoint);
    selectPath(c.path);
    navigate("/explore");
  };

  // A suggested action is NAVIGATION ONLY — it opens a (separately RBAC/MFA-gated) page; the
  // concierge never mutates anything. Set the scope first if the action targets a volume.
  const runAction = (a: ConciergeActionOut): void => {
    if (a.volume_id != null) {
      const vol = volumes.data?.find((v) => v.id === a.volume_id);
      if (vol) selectVolume(vol.host_id, vol.id, vol.mountpoint);
    }
    navigate(a.route);
  };

  return (
    <div className="fathom-cc">
      <div className="fathom-cc-body" aria-live="polite" ref={bodyRef}>
        {messages.length === 0 ? (
          <>
            <p className="fathom-muted">
              Ask about your storage in plain language — find a file (incl. when it was last seen or
              deleted), disk space and types, the biggest consumers, reclaimable duplicates, growth
              forecasts, or what changed. It reads the catalogue only and answers what your account
              can see. You can ask follow-ups.
            </p>
            <p className="fathom-muted fathom-hint">
              Try:{" "}
              {EXAMPLES.map((ex, i) => (
                <span key={ex}>
                  {i > 0 ? " · " : ""}
                  <button type="button" className="fathom-linkbtn" onClick={() => run(ex)}>
                    {ex}
                  </button>
                </span>
              ))}
            </p>
            <p className="fathom-muted fathom-hint">
              Tip: type <code>/help</code> for quick commands (e.g. <code>/largest</code>,{" "}
              <code>/forecast</code>, <code>/go duplicates</code>).
            </p>
          </>
        ) : (
          <>
            <div className="fathom-cc-thread-actions">
              <button
                type="button"
                className="fathom-linkbtn"
                onClick={() => setMessages([])}
                disabled={ask.isPending}
              >
                New conversation
              </button>
            </div>
            {messages.map((m, i) =>
              m.role === "user" ? (
                <div key={i} className="fathom-cc-msg fathom-cc-msg-user">
                  {m.text}
                </div>
              ) : (
                <div
                  key={i}
                  className={`fathom-cc-msg fathom-cc-msg-bot${m.error ? " fathom-cc-msg-error" : ""}`}
                  role={m.error ? "alert" : undefined}
                >
                  <p className="fathom-answer">{m.text}</p>
                  {m.citations && m.citations.length > 0 ? (
                    <>
                      <h3 className="fathom-card-subhead">Based on</h3>
                      <ul className="fathom-citations">
                        {m.citations.map((c, j) => (
                          <li key={`${c.label}-${j}`}>
                            {c.path != null && c.volume_id != null ? (
                              <button
                                type="button"
                                className="fathom-linkbtn"
                                onClick={() => jumpTo(c)}
                              >
                                {displayPath(c.path)}
                              </button>
                            ) : (
                              <span className="fathom-path">{c.label}</span>
                            )}
                            {c.host_id != null ? (
                              <span className="fathom-muted"> · {hostName(c.host_id)}</span>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    </>
                  ) : null}
                  {m.actions && m.actions.length > 0 ? (
                    <div className="fathom-cc-actions">
                      {m.actions.map((a, j) => (
                        <button
                          key={`${a.route}-${j}`}
                          type="button"
                          className="fathom-btn fathom-btn-mini"
                          onClick={() => runAction(a)}
                        >
                          {a.label} →
                        </button>
                      ))}
                    </div>
                  ) : null}
                  {m.tool && !m.error ? (
                    <p className="fathom-muted fathom-hint">
                      {m.considered ?? 0} item(s) · tool <code>{m.tool}</code>
                    </p>
                  ) : null}
                </div>
              ),
            )}
            {ask.isPending ? (
              <div className="fathom-cc-msg fathom-cc-msg-bot fathom-muted">…thinking</div>
            ) : null}
          </>
        )}
      </div>

      <form
        className="fathom-cc-input"
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <label className="sr-only" htmlFor="concierge-q">
          Your question
        </label>
        <input
          id="concierge-q"
          type="text"
          value={question}
          placeholder="Ask about your storage…"
          onChange={(e) => setQuestion(e.target.value)}
        />
        <button
          type="submit"
          className="fathom-btn fathom-btn-primary"
          disabled={ask.isPending || question.trim().length === 0}
        >
          {ask.isPending ? "…" : "Ask"}
        </button>
      </form>
    </div>
  );
}
