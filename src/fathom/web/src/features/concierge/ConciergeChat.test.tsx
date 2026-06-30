// Concierge chat tests (ADR-035): it asks the API (passing the page context hint) and renders the
// grounded answer + citations, and it surfaces the default-OFF gate as a clear, actionable message.
// It also drives the client-side surfaces the server never sees — citation jumps, suggested-action
// navigation, the slash-command DSL (/go, /scope, /find, /clear), conversation memory, and the
// loading/empty states — asserting the REAL store mutations + navigation (useNavigate is spied).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPost };
});

// useNavigate is spied so a citation jump / action / "/go" is observable without a route table.
const navigate = vi.fn();
vi.mock("react-router-dom", async (orig) => ({
  ...(await orig<typeof import("react-router-dom")>()),
  useNavigate: () => navigate,
}));

const { ConciergeChat } = await import("./ConciergeChat");
const { ApiError } = await import("../../api/client");
const { useUiStore } = await import("../../state/uiStore");

// Two volumes on host 1; "data" matches both (multiple-match), "archive" only the second.
const VOLS = [
  {
    id: 2,
    host_id: 1,
    mountpoint: "/scan/data",
    fs_type: "ext4",
    device: "/dev/sda1",
    transport: "sata",
    raid_role: null,
    total: 100,
    used: 40,
    free: 60,
    display_name: null,
  },
  {
    id: 3,
    host_id: 1,
    mountpoint: "/scan/data-archive",
    fs_type: "ext4",
    device: "/dev/sdb1",
    transport: "sata",
    raid_role: null,
    total: 100,
    used: 40,
    free: 60,
    display_name: null,
  },
];
const AGENTS = [{ id: 1, name: "nas-1" }];

const EXAMPLES = [
  "Where is budget.xlsx — and was it deleted?",
  "How much free space is left across the fleet?",
  "What's eating my space on this volume?",
  "When will my disks fill up?",
  "How much can I reclaim from duplicates?",
];

// Mock apiGet per-endpoint (useVolumes + useAgents/useNames both read it).
function routeApi(volumes: unknown = VOLS, agents: unknown = AGENTS): void {
  apiGet.mockImplementation((url: string) => {
    if (url === "/agents") return Promise.resolve(agents);
    if (url === "/volumes") return Promise.resolve(volumes);
    return Promise.resolve([]);
  });
}

// Seeds the query cache so volumes/agents are available SYNCHRONOUSLY (deterministic for the
// commands that read volumes.data on the click, e.g. /scope and citation jumps).
function wrap(node: JSX.Element, seed?: { volumes?: unknown; agents?: unknown }): ReturnType<typeof render> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  if (seed?.volumes !== undefined) client.setQueryData(["volumes"], seed.volumes);
  if (seed?.agents !== undefined) client.setQueryData(["agents"], seed.agents);
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const ask = (): HTMLElement => screen.getByRole("button", { name: /^ask$/i });
const typeQ = (text: string): void => {
  fireEvent.change(screen.getByLabelText(/your question/i), { target: { value: text } });
};

beforeEach(() => {
  useUiStore.setState({
    selectedHostId: null,
    selectedVolumeId: null,
    selectedPath: null,
    selection: new Set(),
  });
});
afterEach(() => vi.clearAllMocks());

it("asks the API with the page context and renders the answer + citation", async () => {
  apiGet.mockResolvedValue([]); // /volumes, /agents (names) → empty is fine
  apiPost.mockResolvedValue({
    answer: "report.pdf was deleted on 2026-06-12.",
    tool: "find_file",
    considered: 1,
    citations: [
      { label: "/mnt/data/report.pdf", path: "/mnt/data/report.pdf", host_id: 1, volume_id: 2 },
    ],
  });

  wrap(<ConciergeChat page="dashboard" />);
  fireEvent.change(screen.getByLabelText(/your question/i), {
    target: { value: "where is report.pdf?" },
  });
  fireEvent.click(screen.getByRole("button", { name: /^ask$/i }));

  expect(await screen.findByText(/was deleted on 2026-06-12/i)).toBeInTheDocument();
  expect(screen.getByText("/mnt/data/report.pdf")).toBeInTheDocument();
  expect(apiPost).toHaveBeenCalledWith("/concierge/ask", {
    question: "where is report.pdf?",
    page: "dashboard",
  });
});

it("shows the enable-it gate message on 403", async () => {
  apiGet.mockResolvedValue([]);
  apiPost.mockRejectedValue(new ApiError(403, { status: 403, detail: "concierge is disabled" }));

  wrap(<ConciergeChat />);
  fireEvent.change(screen.getByLabelText(/your question/i), { target: { value: "anything" } });
  fireEvent.click(screen.getByRole("button", { name: /^ask$/i }));

  expect(await screen.findByText(/turned OFF on this server/i)).toBeInTheDocument();
});

it("handles /help locally without calling the API", async () => {
  apiGet.mockResolvedValue([]);

  wrap(<ConciergeChat page="dashboard" />);
  fireEvent.change(screen.getByLabelText(/your question/i), { target: { value: "/help" } });
  fireEvent.click(screen.getByRole("button", { name: /^ask$/i }));

  expect(await screen.findByText(/Commands:/i)).toBeInTheDocument();
  expect(apiPost).not.toHaveBeenCalled();
});

it("sends a forced tool for a /command (no LLM classify)", async () => {
  apiGet.mockResolvedValue([]);
  apiPost.mockResolvedValue({
    answer: "Biggest items here.",
    tool: "largest",
    considered: 3,
    citations: [],
  });

  wrap(<ConciergeChat page="dashboard" />);
  fireEvent.change(screen.getByLabelText(/your question/i), { target: { value: "/largest" } });
  fireEvent.click(screen.getByRole("button", { name: /^ask$/i }));

  expect(await screen.findByText(/biggest items here/i)).toBeInTheDocument();
  expect(apiPost).toHaveBeenCalledWith(
    "/concierge/ask",
    expect.objectContaining({ tool: "largest" }),
  );
});

// --- citation jump (UC-concierge-1) -------------------------------------------------------

it("jumps to /explore from a citation: sets the volume scope + path", async () => {
  routeApi();
  apiPost.mockResolvedValue({
    answer: "Found it.",
    tool: "find_file",
    considered: 1,
    citations: [
      { label: "report.pdf", path: "/scan/data/report.pdf", host_id: 1, volume_id: 2 },
    ],
  });

  wrap(<ConciergeChat page="dashboard" />, { volumes: VOLS, agents: AGENTS });
  typeQ("where is report.pdf?");
  fireEvent.click(ask());

  // The citation renders as a button labelled with the /scan-stripped display path.
  fireEvent.click(await screen.findByRole("button", { name: "/data/report.pdf" }));

  expect(navigate).toHaveBeenCalledWith("/explore");
  const s = useUiStore.getState();
  expect(s.selectedVolumeId).toBe(2);
  expect(s.selectedHostId).toBe(1);
  expect(s.selectedPath).toBe("/scan/data/report.pdf");
});

// --- suggested-action navigation (UC-concierge-3/4/5/6) -----------------------------------

it.each([["/largest"], ["/duplicates"], ["/scans"], ["/changes"]])(
  "runs a suggested action → sets scope and navigates to %s",
  async (route) => {
    routeApi();
    apiPost.mockResolvedValue({
      answer: "Here you go.",
      tool: "largest",
      considered: 2,
      citations: [],
      actions: [{ label: "Open it", route, volume_id: 2 }],
    });

    wrap(<ConciergeChat page="dashboard" />, { volumes: VOLS, agents: AGENTS });
    typeQ("show me");
    fireEvent.click(ask());

    fireEvent.click(await screen.findByRole("button", { name: /open it/i }));
    expect(navigate).toHaveBeenCalledWith(route);
    expect(useUiStore.getState().selectedVolumeId).toBe(2);
  },
);

// --- slash commands (UC-concierge-11) -----------------------------------------------------

it("/go <page> navigates locally without calling the API", async () => {
  apiGet.mockResolvedValue([]);
  wrap(<ConciergeChat />);
  typeQ("/go explorer");
  fireEvent.click(ask());

  expect(await screen.findByText("Opened explorer.")).toBeInTheDocument();
  expect(navigate).toHaveBeenCalledWith("/explore");
  expect(apiPost).not.toHaveBeenCalled();
});

it("/scope <volume> sets the global scope without calling the API", async () => {
  routeApi();
  wrap(<ConciergeChat />, { volumes: VOLS, agents: AGENTS });
  typeQ("/scope archive");
  fireEvent.click(ask());

  expect(await screen.findByText(/Scope set to \/scan\/data-archive/)).toBeInTheDocument();
  const s = useUiStore.getState();
  expect(s.selectedVolumeId).toBe(3);
  expect(s.selectedHostId).toBe(1);
  expect(apiPost).not.toHaveBeenCalled();
});

it("/scope all resets the scope to the estate", async () => {
  routeApi();
  useUiStore.setState({ selectedHostId: 1, selectedVolumeId: 2, selectedPath: "/scan/data" });
  wrap(<ConciergeChat />, { volumes: VOLS, agents: AGENTS });
  typeQ("/scope all");
  fireEvent.click(ask());

  expect(await screen.findByText(/Scope set to all volumes \(estate\)/)).toBeInTheDocument();
  expect(useUiStore.getState().selectedVolumeId).toBeNull();
});

it("/clear and /new empty the thread back to the intro", async () => {
  apiGet.mockResolvedValue([]);
  wrap(<ConciergeChat />);

  typeQ("/help");
  fireEvent.click(ask());
  expect(await screen.findByText(/Commands:/)).toBeInTheDocument();

  typeQ("/clear");
  fireEvent.click(ask());
  expect(await screen.findByText(/Ask about your storage in plain language/i)).toBeInTheDocument();
  expect(screen.queryByText(/Commands:/)).not.toBeInTheDocument();

  // /new is an alias for /clear.
  typeQ("/help");
  fireEvent.click(ask());
  expect(await screen.findByText(/Commands:/)).toBeInTheDocument();
  typeQ("/new");
  fireEvent.click(ask());
  expect(await screen.findByText(/Ask about your storage in plain language/i)).toBeInTheDocument();
  expect(apiPost).not.toHaveBeenCalled();
});

it("/find <text> forces a find_file tool with the text as the query", async () => {
  apiGet.mockResolvedValue([]);
  apiPost.mockResolvedValue({ answer: "Found files.", tool: "find_file", considered: 2, citations: [] });
  wrap(<ConciergeChat page="dashboard" />);
  typeQ("/find report");
  fireEvent.click(ask());

  expect(await screen.findByText("Found files.")).toBeInTheDocument();
  expect(screen.getByText("/find report")).toBeInTheDocument(); // the typed command is the user bubble
  expect(apiPost).toHaveBeenCalledWith(
    "/concierge/ask",
    expect.objectContaining({ tool: "find_file", question: "report" }),
  );
});

it("/find with no argument shows usage and does not call the API", async () => {
  apiGet.mockResolvedValue([]);
  wrap(<ConciergeChat />);
  typeQ("/find");
  fireEvent.click(ask());

  expect(await screen.findByText("Usage: /find <name or path>.")).toBeInTheDocument();
  expect(apiPost).not.toHaveBeenCalled();
});

// --- scope/command feedback (EC-concierge-25 / EC-concierge-26) ----------------------------

it("/scope with no match reports it (non-alert) and leaves the scope alone", async () => {
  routeApi();
  wrap(<ConciergeChat />, { volumes: VOLS, agents: AGENTS });
  typeQ("/scope zzz");
  fireEvent.click(ask());

  expect(await screen.findByText('No volume matching "zzz".')).toBeInTheDocument();
  expect(screen.queryByRole("alert")).toBeNull(); // it is informational, not an error bubble
  expect(useUiStore.getState().selectedVolumeId).toBeNull();
});

it("/scope with multiple matches selects the first", async () => {
  routeApi();
  wrap(<ConciergeChat />, { volumes: VOLS, agents: AGENTS });
  typeQ("/scope data"); // matches both /scan/data (id 2) and /scan/data-archive (id 3)
  fireEvent.click(ask());

  expect(await screen.findByText(/Scope set to \/scan\/data /)).toBeInTheDocument();
  expect(useUiStore.getState().selectedVolumeId).toBe(2);
});

it("/go <unknown> returns an unknown-page bubble (non-alert), no navigation", async () => {
  apiGet.mockResolvedValue([]);
  wrap(<ConciergeChat />);
  typeQ("/go nowhere");
  fireEvent.click(ask());

  expect(await screen.findByText(/Unknown page "nowhere"/)).toBeInTheDocument();
  expect(navigate).not.toHaveBeenCalled();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(apiPost).not.toHaveBeenCalled();
});

it("an unknown /command returns an unknown-command bubble (non-alert)", async () => {
  apiGet.mockResolvedValue([]);
  wrap(<ConciergeChat />);
  typeQ("/bogus");
  fireEvent.click(ask());

  expect(await screen.findByText(/Unknown command "\/bogus"/)).toBeInTheDocument();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(apiPost).not.toHaveBeenCalled();
});

// --- stale volume list (EC-concierge-23) --------------------------------------------------

it("with an empty volume list: a citation does NOT navigate; an action navigates WITHOUT scope", async () => {
  routeApi([]); // volumes query resolves to []
  apiPost.mockResolvedValue({
    answer: "Found.",
    tool: "find_file",
    considered: 1,
    citations: [{ label: "report.pdf", path: "/scan/data/report.pdf", host_id: 1, volume_id: 2 }],
    actions: [{ label: "Open largest", route: "/largest", volume_id: 2 }],
  });

  wrap(<ConciergeChat page="dashboard" />, { volumes: [], agents: AGENTS });
  typeQ("where is report.pdf?");
  fireEvent.click(ask());

  // Citation: volume_id 2 is not in the (empty) list → jumpTo bails, no navigation.
  fireEvent.click(await screen.findByRole("button", { name: "/data/report.pdf" }));
  expect(navigate).not.toHaveBeenCalled();
  expect(useUiStore.getState().selectedVolumeId).toBeNull();

  // Action: still navigates (route is server-fixed) but cannot set a scope it can't resolve.
  fireEvent.click(screen.getByRole("button", { name: /open largest/i }));
  expect(navigate).toHaveBeenCalledWith("/largest");
  expect(useUiStore.getState().selectedVolumeId).toBeNull();
});

// --- loading state ------------------------------------------------------------------------

it("shows the …thinking bubble and disables Ask while the request is in flight", async () => {
  apiGet.mockResolvedValue([]);
  apiPost.mockReturnValue(new Promise(() => {})); // never resolves → stays pending
  wrap(<ConciergeChat />);
  typeQ("anything");
  fireEvent.click(ask());

  expect(await screen.findByText("…thinking")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "…" })).toBeDisabled(); // the submit button while pending
});

// --- empty state --------------------------------------------------------------------------

it("empty state: intro paragraph + 5 clickable examples + a /help tip", async () => {
  apiGet.mockResolvedValue([]);
  wrap(<ConciergeChat />);

  expect(screen.getByText(/Ask about your storage in plain language/i)).toBeInTheDocument();
  expect(screen.getByText(/Tip:/)).toBeInTheDocument();
  for (const ex of EXAMPLES) {
    expect(screen.getByRole("button", { name: ex })).toBeInTheDocument();
  }
});

it("clicking an example sends it verbatim as a question", async () => {
  apiGet.mockResolvedValue([]);
  apiPost.mockResolvedValue({ answer: "ok", tool: "largest", considered: 1, citations: [] });
  wrap(<ConciergeChat page="dashboard" />);

  fireEvent.click(screen.getByRole("button", { name: EXAMPLES[0] }));
  await waitFor(() =>
    expect(apiPost).toHaveBeenCalledWith(
      "/concierge/ask",
      expect.objectContaining({ question: EXAMPLES[0] }),
    ),
  );
});

it("renders the zero-result footer for a clarify/other answer", async () => {
  apiGet.mockResolvedValue([]);
  apiPost.mockResolvedValue({ answer: "Could you clarify?", tool: "clarify", considered: 0, citations: [] });
  wrap(<ConciergeChat />);
  typeQ("huh");
  fireEvent.click(ask());

  expect(await screen.findByText("Could you clarify?")).toBeInTheDocument();
  expect(screen.getByText(/0 item\(s\)/)).toBeInTheDocument();
  expect(screen.getByText("clarify")).toBeInTheDocument();
});

// --- follow-up memory (UC-concierge-10) ---------------------------------------------------

it("sends prior turns as history on a follow-up", async () => {
  apiGet.mockResolvedValue([]);
  apiPost
    .mockResolvedValueOnce({ answer: "a1", tool: "largest", considered: 1, citations: [] })
    .mockResolvedValue({ answer: "a2", tool: "largest", considered: 1, citations: [] });
  wrap(<ConciergeChat page="dashboard" />);

  typeQ("q1");
  fireEvent.click(ask());
  expect(await screen.findByText("a1")).toBeInTheDocument();

  typeQ("q2");
  fireEvent.click(ask());
  await waitFor(() => expect(apiPost).toHaveBeenCalledTimes(2));
  expect(apiPost).toHaveBeenNthCalledWith(
    2,
    "/concierge/ask",
    expect.objectContaining({
      question: "q2",
      history: [
        { role: "user", content: "q1" },
        { role: "assistant", content: "a1" },
      ],
    }),
  );
});

it("excludes error bubbles from the history of a follow-up", async () => {
  apiGet.mockResolvedValue([]);
  apiPost
    .mockRejectedValueOnce(new ApiError(500, { status: 500, detail: "boom" }))
    .mockResolvedValue({ answer: "a2", tool: "largest", considered: 1, citations: [] });
  wrap(<ConciergeChat page="dashboard" />);

  typeQ("q1");
  fireEvent.click(ask());
  expect(await screen.findByText(/boom/)).toBeInTheDocument();

  typeQ("q2");
  fireEvent.click(ask());
  await waitFor(() => expect(apiPost).toHaveBeenCalledTimes(2));
  // Only the (non-error) user turn survives — the error reply is NOT replayed to the model.
  expect(apiPost).toHaveBeenNthCalledWith(
    2,
    "/concierge/ask",
    expect.objectContaining({ question: "q2", history: [{ role: "user", content: "q1" }] }),
  );
});
