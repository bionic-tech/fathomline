// Getting Started wizard tests (ADR-037): renders per-host suitability, and one-click applies the
// recommended settings — local by default, cloud when the preference is switched.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";

import { ApiError } from "../../api/client";

const { apiGet, apiPut } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPut: vi.fn() }));

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, apiGet, apiPut };
});

const { GettingStarted } = await import("./GettingStarted");

const SUITABILITY = {
  egress_allowed: false,
  hosts: [
    {
      host_id: 1,
      name: "nas-1",
      facts_known: true,
      facts: { ram_bytes: 68719476736, gpu_vram_bytes: 17179869184 },
      options: [
        { key: "local_chat_small", label: "Local chat — small", rating: "green", reason: "fits" },
        { key: "local_chat_large", label: "Local chat — large", rating: "green", reason: "VRAM" },
        { key: "cloud_chat", label: "Cloud chat", rating: "green", reason: "any hw" },
        { key: "semantic_embeddings", label: "Semantic search", rating: "green", reason: "ram" },
      ],
      recommendation: "Use an 8B local model for chat.",
      recommended_chat_provider: "ollama",
      recommended_chat_model: "llama3.1:8b",
      recommended_embedder: "ollama",
      recommended_embedding_dim: 768,
    },
  ],
};

function wrap(node: JSX.Element) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => vi.clearAllMocks());

it("renders host suitability and applies the local recommendation", async () => {
  apiGet.mockResolvedValue(SUITABILITY);
  apiPut.mockResolvedValue({ key: "x", overridden: true, restart_required: false, version: 1 });

  wrap(<GettingStarted />);
  // The host card + its green large-model assessment render.
  expect(await screen.findByText("nas-1")).toBeInTheDocument();
  expect(screen.getByText(/Model → llama3.1:8b/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /apply recommended settings/i }));
  await waitFor(() =>
    expect(apiPut).toHaveBeenCalledWith("/settings/inference_provider", { value: "ollama" }),
  );
  expect(apiPut).toHaveBeenCalledWith("/settings/inference_model", { value: "llama3.1:8b" });
  expect(apiPut).toHaveBeenCalledWith("/settings/concierge_enabled", { value: true });
});

it("switching to cloud plans Anthropic + egress", async () => {
  apiGet.mockResolvedValue(SUITABILITY);
  apiPut.mockResolvedValue({ key: "x", overridden: true, restart_required: false, version: 1 });

  wrap(<GettingStarted />);
  await screen.findByText("nas-1");
  fireEvent.click(screen.getByRole("radio", { name: /cloud/i }));
  expect(screen.getByText(/Chat provider → Anthropic/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /apply recommended settings/i }));
  await waitFor(() =>
    expect(apiPut).toHaveBeenCalledWith("/settings/inference_provider", { value: "anthropic" }),
  );
  expect(apiPut).toHaveBeenCalledWith("/settings/inference_allow_egress", { value: true });
});

// A facts-known host whose best local option is the small model: local_chat_large is red, so the
// "best" host (the only known one) lacks a green large local and the plan falls back to 3b.
const SMALL_MODEL_SUITABILITY = {
  egress_allowed: false,
  hosts: [
    {
      host_id: 3,
      name: "tank",
      facts_known: true,
      facts: { ram_bytes: 17179869184, gpu_vram_bytes: 0 },
      options: [
        { key: "local_chat_small", label: "Local chat — small", rating: "green", reason: "fits" },
        { key: "local_chat_large", label: "Local chat — large", rating: "red", reason: "no VRAM" },
        { key: "cloud_chat", label: "Cloud chat", rating: "green", reason: "any hw" },
      ],
      recommendation: "Use a 3B local model for chat.",
      recommended_chat_provider: "ollama",
      recommended_chat_model: "llama3.2:3b",
      recommended_embedder: "ollama",
      recommended_embedding_dim: 768,
    },
  ],
};

// A host the agent has not reported hardware for yet: facts_known=false → "deploy to assess".
const UNKNOWN_HOST_SUITABILITY = {
  egress_allowed: false,
  hosts: [
    {
      host_id: 7,
      name: "node-1",
      facts_known: false,
      facts: null,
      options: [
        { key: "local_chat_small", label: "Local chat — small", rating: "amber", reason: "RAM?" },
        { key: "local_chat_large", label: "Local chat — large", rating: "amber", reason: "VRAM?" },
      ],
      recommendation: "Deploy or upgrade the agent to assess this host.",
      recommended_chat_provider: "ollama",
      recommended_chat_model: null,
      recommended_embedder: "ollama",
      recommended_embedding_dim: null,
    },
  ],
};

it("shows an empty state with a deploy link when no hosts are known (EC-onboarding-1)", async () => {
  apiGet.mockResolvedValue({ egress_allowed: false, hosts: [] });

  wrap(<GettingStarted />);
  expect(await screen.findByText(/No hosts yet\./)).toBeInTheDocument();
  // The empty state offers a way to bootstrap the estate from Deploy.
  expect(screen.getByRole("link", { name: /deploy an agent/i })).toHaveAttribute("href", "/deploy");
});

it("renders a calm access-denied state on a 403 (EC-onboarding-6)", async () => {
  apiGet.mockRejectedValue(new ApiError(403, { status: 403, title: "Forbidden" }));

  wrap(<GettingStarted />);
  // QueryState maps the sanitised 403 to its standard access copy (no stack trace).
  expect(await screen.findByText("You do not have access to this data.")).toBeInTheDocument();
  // No host card was rendered.
  expect(screen.queryByText("nas-1")).not.toBeInTheDocument();
});

it("renders an unavailable state on a 404 (EC-onboarding-8)", async () => {
  apiGet.mockRejectedValue(new ApiError(404, { status: 404, title: "Not Found" }));

  wrap(<GettingStarted />);
  expect(
    await screen.findByText(/not available on this deployment yet/i),
  ).toBeInTheDocument();
});

it("surfaces an apply error and stops mid-loop when a PUT fails (EC-onboarding-10)", async () => {
  apiGet.mockResolvedValue(SUITABILITY);
  apiPut
    .mockResolvedValueOnce({ key: "inference_provider", overridden: true, restart_required: false, version: 1 })
    .mockRejectedValueOnce(new ApiError(422, { status: 422, detail: "Model not installed." }));

  wrap(<GettingStarted />);
  await screen.findByText("nas-1");

  fireEvent.click(screen.getByRole("button", { name: /apply recommended settings/i }));

  // The sanitised problem detail surfaces as an alert; no success status is shown.
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent("Model not installed.");
  expect(screen.queryByRole("status")).not.toBeInTheDocument();

  // The first setting was issued, but the loop aborted before the later ones.
  expect(apiPut).toHaveBeenCalledWith("/settings/inference_provider", { value: "ollama" });
  expect(apiPut).not.toHaveBeenCalledWith("/settings/concierge_enabled", { value: true });
});

it("renders a facts-unknown host with a deploy link and amber pills (EC-onboarding-2)", async () => {
  apiGet.mockResolvedValue(UNKNOWN_HOST_SUITABILITY);

  wrap(<GettingStarted />);
  expect(await screen.findByText("node-1")).toBeInTheDocument();
  expect(screen.getByText(/Hardware not reported yet/)).toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: /deploy or upgrade the agent/i }),
  ).toHaveAttribute("href", "/deploy");

  // The option is rendered as an amber (warning) pill carrying the ⚠️ icon.
  const largePill = screen.getByText("VRAM?").closest("li");
  expect(largePill).toHaveClass("fathom-note-warning");
  expect(largePill).toHaveTextContent("⚠️");
});

it("plans the small local model when no host can run the large one (UC-onboarding-4)", async () => {
  apiGet.mockResolvedValue(SMALL_MODEL_SUITABILITY);
  apiPut.mockResolvedValue({ key: "x", overridden: true, restart_required: false, version: 1 });

  wrap(<GettingStarted />);
  await screen.findByText("tank");
  // best host lacks a green local_chat_large → the plan falls back to the 3b model.
  expect(screen.getByText(/Model → llama3.2:3b/)).toBeInTheDocument();
  expect(screen.queryByText(/Model → llama3.1:8b/)).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /apply recommended settings/i }));
  await waitFor(() =>
    expect(apiPut).toHaveBeenCalledWith("/settings/inference_model", { value: "llama3.2:3b" }),
  );
});
