// RuntimeSettings (ADR-038): the admin runtime-config editor. One tab per present category (+ a
// Named secrets tab), each listing its applicable settings, plus the notification channel test
// tucked into the Notifications tab. Covers the loading/error/ready states + tab routing, the
// non-secret save / reset / restart-badge surface, the secret + step-up-MFA surface (masked input,
// Reveal, named secrets), provider-aware value rendering (select vs combobox), the relevant/advanced
// filtering, and the channel test. The non-admin ServerConfig fallback is reached through the parent
// Settings page (the manage_settings gate lives there), so that one case renders <Settings/>.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ServerConfigOut, SettingOut, SettingsListOut } from "../../api/types";

const { apiGet, apiPost, apiPut, apiDelete } = vi.hoisted(() => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
  apiPut: vi.fn(),
  apiDelete: vi.fn(),
}));
vi.mock("../../api/client", () => ({
  apiGet,
  apiPost,
  apiPut,
  apiDelete,
  ApiError: class ApiError extends Error {},
}));

const { RuntimeSettings } = await import("./RuntimeSettings");
const { Settings } = await import("./Settings");

function setting(over: Partial<SettingOut>): SettingOut {
  return {
    key: "k",
    category: "general",
    type: "str",
    editable: true,
    is_secret: false,
    restart_required: false,
    help: "",
    overridden: false,
    is_set: true,
    value: "v",
    label: "Label",
    options: null,
    suggestions: null,
    relevant: true,
    relevant_hint: null,
    advanced: false,
    ...over,
  };
}

function listing(settings: SettingOut[], named_secrets: string[] = []): SettingsListOut {
  return { settings, named_secrets, version: 1 };
}

const DATA = {
  settings: [
    setting({ key: "ui_theme", category: "general", label: "UI theme", value: "dark" }),
    setting({ key: "inference_model", category: "inference", label: "Inference model", value: "llama3" }),
  ],
  named_secrets: [],
};

function renderWith(node: JSX.Element): ReturnType<typeof render> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function wrap(): void {
  renderWith(<RuntimeSettings />);
}

afterEach(() => vi.clearAllMocks());

describe("RuntimeSettings", () => {
  it("renders a tab per category plus a Named secrets tab, general active first", async () => {
    apiGet.mockResolvedValue(DATA);
    wrap();
    expect(await screen.findByRole("tab", { name: /general & ui/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /llm inference/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /named secrets/i })).toBeInTheDocument();
    // General is first → its setting label is visible.
    expect(screen.getByText("UI theme")).toBeInTheDocument();
  });

  it("switches to the inference tab on click", async () => {
    apiGet.mockResolvedValue(DATA);
    wrap();
    fireEvent.click(await screen.findByRole("tab", { name: /llm inference/i }));
    expect(screen.getByText("Inference model")).toBeInTheDocument();
    // The cohesion banner explains the model is shared + how to override per-feature (P1).
    const note = screen.getByRole("note");
    expect(note).toHaveTextContent(/shared by every AI feature/i);
    expect(note).toHaveTextContent(/override/i);
  });

  it("shows the loading state while settings load", () => {
    apiGet.mockReturnValue(new Promise(() => {})); // never resolves
    wrap();
    expect(screen.getByRole("status")).toHaveTextContent(/loading/i);
  });

  it("shows an error state when settings fail to load", async () => {
    apiGet.mockRejectedValue(new Error("boom"));
    wrap();
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});

// --- save / reset / restart (UC-settings-1/2/3) -------------------------------------------
describe("RuntimeSettings — save / reset / restart", () => {
  it("saves a non-secret setting via PUT /settings/<key> with the edited value", async () => {
    apiGet.mockResolvedValue(
      listing([setting({ key: "ui_theme", category: "general", label: "UI theme", value: "dark" })]),
    );
    wrap();
    const input = await screen.findByLabelText("ui_theme");
    fireEvent.change(input, { target: { value: "light" } });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() =>
      expect(apiPut).toHaveBeenCalledWith("/settings/ui_theme", { value: "light" }),
    );
  });

  it("shows the 'overridden' badge + Reset, and Reset clears the override via DELETE", async () => {
    apiGet.mockResolvedValue(
      listing([setting({ key: "ui_theme", category: "general", label: "UI theme", overridden: true })]),
    );
    wrap();
    // Scoped by title so it isn't confused with any other badge.
    expect(await screen.findByTitle(/in-app override is set/i)).toHaveTextContent("overridden");
    fireEvent.click(screen.getByRole("button", { name: /reset/i }));
    await waitFor(() => expect(apiDelete).toHaveBeenCalledWith("/settings/ui_theme"));
  });

  it("flags a restart-required setting with the restart badge", async () => {
    apiGet.mockResolvedValue(
      listing([
        setting({ key: "auth_session_ttl", category: "general", label: "Session TTL", restart_required: true }),
      ]),
    );
    wrap();
    // The header paragraph also renders a (title-less) "restart" badge, so match by the row's title.
    expect(await screen.findByTitle(/needs a restart to fully apply/i)).toHaveTextContent("restart");
  });
});

// --- secrets + step-up MFA (UC-settings-4/5, EC-settings-3) --------------------------------
describe("RuntimeSettings — secrets & step-up MFA", () => {
  const secret = (over: Partial<SettingOut>): SettingOut =>
    setting({
      key: "inference_anthropic_key",
      category: "general",
      label: "Anthropic API key",
      is_secret: true,
      value: null,
      ...over,
    });

  it("renders a masked password input and a Reveal button when the secret is set", async () => {
    apiGet.mockResolvedValue(listing([secret({ is_set: true })]));
    wrap();
    const input = await screen.findByLabelText("inference_anthropic_key value");
    expect(input).toHaveAttribute("type", "password");
    expect(input.getAttribute("placeholder")).toMatch(/\(set\)/);
    expect(screen.getByRole("button", { name: /reveal/i })).toBeInTheDocument();
  });

  it("hides Reveal (and marks the field unset) when the secret is not set", async () => {
    apiGet.mockResolvedValue(listing([secret({ is_set: false })]));
    wrap();
    await screen.findByLabelText("inference_anthropic_key value");
    expect(screen.queryByRole("button", { name: /reveal/i })).not.toBeInTheDocument();
    expect(screen.getByPlaceholderText("(unset)")).toBeInTheDocument();
  });

  it("reveals the plaintext inline on Reveal", async () => {
    apiGet.mockResolvedValue(listing([secret({ is_set: true })]));
    apiPost.mockResolvedValue({ key: "inference_anthropic_key", value: "sk-live-abc123" });
    wrap();
    fireEvent.click(await screen.findByRole("button", { name: /reveal/i }));
    expect(await screen.findByText("sk-live-abc123")).toBeInTheDocument();
    expect(apiPost).toHaveBeenCalledWith("/settings/inference_anthropic_key/reveal");
  });

  it("surfaces 'fresh MFA required' when a reveal is rejected", async () => {
    apiGet.mockResolvedValue(listing([secret({ is_set: true })]));
    apiPost.mockRejectedValue(new Error("forbidden"));
    wrap();
    fireEvent.click(await screen.findByRole("button", { name: /reveal/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/fresh MFA required/i);
  });

  it("adds, reveals, and deletes a free-form named secret", async () => {
    apiGet.mockResolvedValue(
      listing([setting({ key: "ui_theme", category: "general", label: "UI theme" })], ["ANTHROPIC_KEY"]),
    );
    wrap();
    fireEvent.click(await screen.findByRole("tab", { name: /named secrets/i }));

    // Existing reference is listed.
    expect(screen.getByText("ANTHROPIC_KEY")).toBeInTheDocument();

    // Reveal it (POST /settings/<ref>/reveal → shown inline).
    apiPost.mockResolvedValue({ key: "ANTHROPIC_KEY", value: "sk-secret" });
    fireEvent.click(screen.getByRole("button", { name: /reveal/i }));
    expect(await screen.findByText("sk-secret")).toBeInTheDocument();
    expect(apiPost).toHaveBeenCalledWith("/settings/ANTHROPIC_KEY/reveal");

    // Delete it (DELETE /settings/secrets/<ref>).
    fireEvent.click(screen.getByRole("button", { name: /delete/i }));
    await waitFor(() => expect(apiDelete).toHaveBeenCalledWith("/settings/secrets/ANTHROPIC_KEY"));

    // Add a new one (PUT /settings/secrets).
    fireEvent.change(screen.getByLabelText(/reference name/i), { target: { value: "NEW_KEY" } });
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "topsecret" } });
    fireEvent.click(screen.getByRole("button", { name: /add secret/i }));
    await waitFor(() =>
      expect(apiPut).toHaveBeenCalledWith("/settings/secrets", { ref: "NEW_KEY", value: "topsecret" }),
    );
  });
});

// --- provider-aware rendering + relevant/advanced filtering (UC-settings-10) ---------------
describe("RuntimeSettings — provider-aware rendering", () => {
  it("renders inference_model as a strict <select> for a closed option set (anthropic)", async () => {
    apiGet.mockResolvedValue(
      listing([
        setting({
          key: "inference_model",
          category: "inference",
          label: "Inference model",
          value: "claude-3-5-sonnet",
          options: ["claude-3-5-sonnet", "claude-3-opus"],
        }),
      ]),
    );
    wrap();
    const el = await screen.findByLabelText("inference_model");
    expect(el.tagName).toBe("SELECT");
    expect(screen.getByRole("option", { name: "claude-3-opus" })).toBeInTheDocument();
  });

  it("renders inference_model as a free-text input + datalist for an open set (ollama)", async () => {
    apiGet.mockResolvedValue(
      listing([
        setting({
          key: "inference_model",
          category: "inference",
          label: "Inference model",
          value: "llama3",
          options: null,
          suggestions: ["llama3", "mistral"],
        }),
      ]),
    );
    const { container } = renderWith(<RuntimeSettings />);
    const el = await screen.findByLabelText("inference_model");
    expect(el.tagName).toBe("INPUT");
    expect(el).toHaveAttribute("list", "inference_model-suggestions");
    expect(container.querySelector("datalist#inference_model-suggestions")).not.toBeNull();
  });

  it("hides settings the server marks not-relevant", async () => {
    apiGet.mockResolvedValue(
      listing([
        setting({ key: "inference_ollama_url", category: "inference", label: "Ollama URL", relevant: false }),
        setting({ key: "inference_model", category: "inference", label: "Inference model" }),
      ]),
    );
    wrap();
    expect(await screen.findByText("Inference model")).toBeInTheDocument();
    expect(screen.queryByText("Ollama URL")).not.toBeInTheDocument();
  });

  it("tucks advanced settings behind an 'Advanced (n)' disclosure", async () => {
    apiGet.mockResolvedValue(
      listing([
        setting({ key: "inference_model", category: "inference", label: "Inference model" }),
        setting({
          key: "inference_anthropic_key_ref",
          category: "inference",
          label: "Key reference",
          advanced: true,
        }),
      ]),
    );
    const { container } = renderWith(<RuntimeSettings />);
    await screen.findByText("Inference model");
    const details = container.querySelector("details.fathom-advanced");
    expect(details).not.toBeNull();
    expect(within(details as HTMLElement).getByText("Advanced (1)")).toBeInTheDocument();
    expect(within(details as HTMLElement).getByText("Key reference")).toBeInTheDocument();
  });
});

// --- notification channel test (UC-settings-11, UC-notifications-8) ------------------------
describe("RuntimeSettings — notification channel test", () => {
  function notifData(): SettingsListOut {
    return listing([
      setting({
        key: "notifications_enabled",
        category: "notifications",
        label: "Notifications enabled",
        type: "bool",
        value: "true",
      }),
    ]);
  }

  it("sends a channel test and renders per-channel ok/failed", async () => {
    apiGet.mockResolvedValue(notifData());
    apiPost.mockResolvedValue({
      results: [
        { channel: "email", ok: true, detail: "queued" },
        { channel: "chat", ok: false, detail: "401 from webhook" },
      ],
    });
    wrap();
    fireEvent.click(await screen.findByRole("tab", { name: /notifications/i }));
    fireEvent.click(screen.getByRole("button", { name: /send test notification/i }));
    expect(await screen.findByText("email")).toBeInTheDocument();
    expect(screen.getByText("chat")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(apiPost).toHaveBeenCalledWith("/notifications/test");
  });

  it("shows 'No channels enabled.' when the test returns no results", async () => {
    apiGet.mockResolvedValue(notifData());
    apiPost.mockResolvedValue({ results: [] });
    wrap();
    fireEvent.click(await screen.findByRole("tab", { name: /notifications/i }));
    fireEvent.click(screen.getByRole("button", { name: /send test notification/i }));
    expect(await screen.findByText("No channels enabled.")).toBeInTheDocument();
  });
});

// --- ServerConfig non-admin fallback (UC-settings-8, EC-settings-2) ------------------------
// The manage_settings gate lives in the parent Settings page (config tab → RuntimeSettings for an
// admin, the read-only ServerConfig grid otherwise), so the fallback is exercised through <Settings/>.
describe("Settings → Configuration tab (ServerConfig gating)", () => {
  const ME_AUDITOR = {
    subject: "auditor1",
    source: "local",
    display_name: "Aud Itor",
    groups: [],
    grants: [{ role: "auditor", scope_kind: "global", host_id: null, volume_id: null }],
    mfa_fresh: false,
    mfa_enrolled: false,
  };
  const CFG: ServerConfigOut = {
    organize_enabled: true,
    inference_provider: "ollama",
    inference_model: "llama3",
    inference_ollama_url: "http://nas-1:7869",
    organize_model: null,
    inference_allow_egress: false,
    inference_timeout_seconds: 60,
    remediation_enabled: false,
    remediation_blast_cap: 100,
    preview_enabled: true,
    change_log_retention_days: 90,
    concierge_enabled: false,
    concierge_model: null,
    concierge_embeddings_enabled: false,
    scan_coordinator_enabled: false,
    notifications_enabled: true,
    onboarding_completed: true,
  };

  it("shows the read-only ServerConfig grid (not the editable panel) for a manage_settings-less principal", async () => {
    apiGet.mockImplementation((url: string) => {
      if (url.startsWith("/auth/me")) return Promise.resolve(ME_AUDITOR);
      if (url.startsWith("/config")) return Promise.resolve(CFG);
      return Promise.resolve([]);
    });
    renderWith(<Settings />);

    fireEvent.click(await screen.findByRole("tab", { name: /configuration/i }));

    expect(await screen.findByText("Server configuration")).toBeInTheDocument();
    expect(screen.getByText("Organize (AI) enabled")).toBeInTheDocument();
    // The on/off badges render (organize=on, egress/remediation=off).
    expect(screen.getAllByText("on").length).toBeGreaterThan(0);
    expect(screen.getAllByText("off").length).toBeGreaterThan(0);
    // The editable RuntimeSettings panel is NOT offered to a non-manage_settings principal.
    expect(screen.queryByRole("heading", { name: /^runtime settings$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /named secrets/i })).not.toBeInTheDocument();
  });
});
