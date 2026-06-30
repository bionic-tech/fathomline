// Getting Started wizard (ADR-037): the newcomer-friendly path that does the thinking. It asks
// local-vs-cloud up front, shows each host's AI-option suitability as traffic-lights with a "best
// for you" pick (from the suitability engine), and one-click applies the recommended AI settings
// (live, via the settings store). It never replaces the manual Deploy / Settings screens — it links
// to them. Hosts without an agent show as "deploy to assess" with a link to Deploy.

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { ApiError } from "../../api/client";
import { useSetSetting, useSuitability } from "../../api/queries";
import type { HostSuitabilityOut, OptionAssessmentOut, SuitabilityRating } from "../../api/types";
import { QueryState } from "../common/QueryState";

type Preference = "local" | "cloud";

const RATING_ICON: Record<SuitabilityRating, string> = { green: "✅", amber: "⚠️", red: "❌" };

function ratingClass(r: SuitabilityRating): string {
  return r === "green"
    ? "fathom-note-info"
    : r === "amber"
      ? "fathom-note-warning"
      : "fathom-note-critical";
}

function hasGreenLargeLocal(host: HostSuitabilityOut): boolean {
  return host.options.some((o) => o.key === "local_chat_large" && o.rating === "green");
}

/** The settings the wizard applies, derived from the preference + the best host's capability. */
function plannedSettings(
  preference: Preference,
  best: HostSuitabilityOut | null,
): { key: string; value: unknown; label: string }[] {
  if (preference === "cloud") {
    return [
      { key: "inference_provider", value: "anthropic", label: "Chat provider → Anthropic (cloud)" },
      { key: "inference_model", value: "claude-haiku-4-5", label: "Model → Claude Haiku" },
      { key: "inference_allow_egress", value: true, label: "Allow cloud egress → on" },
      { key: "concierge_enabled", value: true, label: "AI concierge → on" },
    ];
  }
  const model = best && hasGreenLargeLocal(best) ? "llama3.1:8b" : "llama3.2:3b";
  return [
    { key: "inference_provider", value: "ollama", label: "Chat provider → Ollama (local)" },
    { key: "inference_model", value: model, label: `Model → ${model}` },
    { key: "concierge_enabled", value: true, label: "AI concierge → on" },
  ];
}

function OptionPill({ option }: { option: OptionAssessmentOut }): JSX.Element {
  return (
    <li className={`fathom-note ${ratingClass(option.rating)}`}>
      <div className="fathom-note-title">
        {RATING_ICON[option.rating]} {option.label}
      </div>
      <div className="fathom-note-body">{option.reason}</div>
    </li>
  );
}

function HostCard({ host }: { host: HostSuitabilityOut }): JSX.Element {
  return (
    <section className="fathom-card" aria-label={`Suitability for ${host.name}`}>
      <h3 className="fathom-card-title">{host.name}</h3>
      {host.facts_known ? null : (
        <p className="fathom-muted">
          Hardware not reported yet — <Link to="/deploy">deploy or upgrade the agent</Link> so this
          host can be assessed.
        </p>
      )}
      <ul className="fathom-bell-list">
        {host.options.map((o) => (
          <OptionPill key={o.key} option={o} />
        ))}
      </ul>
      <p className="fathom-muted">Best for this host: {host.recommendation}</p>
    </section>
  );
}

export function GettingStarted(): JSX.Element {
  const suitability = useSuitability();
  const setSetting = useSetSetting();
  const [preference, setPreference] = useState<Preference>("local");
  const [applied, setApplied] = useState<string[] | null>(null);
  const [applyError, setApplyError] = useState<string | null>(null);

  const hosts = suitability.data?.hosts ?? [];
  // The "best" host = the one that can run the most capable local model (for the local plan).
  const best = useMemo<HostSuitabilityOut | null>(() => {
    const known = (suitability.data?.hosts ?? []).filter((h) => h.facts_known);
    return known.find(hasGreenLargeLocal) ?? known[0] ?? null;
  }, [suitability.data]);

  const planned = plannedSettings(preference, best);

  async function applyPlan(): Promise<void> {
    setApplyError(null);
    try {
      for (const s of planned) {
        await setSetting.mutateAsync({ key: s.key, value: s.value });
      }
      setApplied(planned.map((s) => s.label));
    } catch (e) {
      setApplyError(
        e instanceof ApiError ? (e.problem.detail ?? "Failed to apply settings.") : "Failed.",
      );
    }
  }

  return (
    <div className="fathom-page">
      <h1>Getting Started</h1>
      <p className="fathom-muted">
        This guided path sets up the AI features for your estate. It checks what each host can run,
        recommends settings, and applies them for you. You can change anything later under{" "}
        <Link to="/settings">Settings</Link>, or skip this and configure manually.
      </p>

      <section className="fathom-card" aria-label="Local or cloud">
        <h2 className="fathom-card-title">1 · Local or cloud?</h2>
        <p className="fathom-muted">
          Local keeps everything on your hardware (no data leaves the host) but needs enough RAM/GPU.
          Cloud runs on any hardware but sends prompts to a provider and needs an API key.
        </p>
        <label className="fathom-field">
          <input
            type="radio"
            name="pref"
            checked={preference === "local"}
            onChange={() => setPreference("local")}
          />{" "}
          Local (Ollama on my hardware)
        </label>
        <label className="fathom-field">
          <input
            type="radio"
            name="pref"
            checked={preference === "cloud"}
            onChange={() => setPreference("cloud")}
          />{" "}
          Cloud (Anthropic/OpenAI — requires egress + an API key)
        </label>
      </section>

      <section className="fathom-card" aria-label="Suitability">
        <h2 className="fathom-card-title">2 · What your hosts can run</h2>
        <QueryState
          isLoading={suitability.isLoading}
          isError={suitability.isError}
          error={suitability.error}
        >
          {hosts.length === 0 ? (
            <p className="fathom-muted">
              No hosts yet. <Link to="/deploy">Deploy an agent</Link> to a host, then return here.
            </p>
          ) : (
            hosts.map((h) => <HostCard key={h.host_id} host={h} />)
          )}
        </QueryState>
      </section>

      <section className="fathom-card" aria-label="Apply recommendation">
        <h2 className="fathom-card-title">3 · Apply recommended settings</h2>
        <ul className="fathom-assignment-list">
          {planned.map((s) => (
            <li key={s.key}>{s.label}</li>
          ))}
        </ul>
        {preference === "cloud" ? (
          <p className="fathom-muted">
            After applying, add your API key under <Link to="/settings">Settings</Link>: set{" "}
            <code>inference_anthropic_key_ref</code> and store the key under Named secrets.
          </p>
        ) : null}
        <button
          type="button"
          className="fathom-btn fathom-btn-primary"
          disabled={setSetting.isPending}
          onClick={() => void applyPlan()}
        >
          Apply recommended settings
        </button>
        {applied ? (
          <p role="status" className="fathom-muted">
            Applied: {applied.join("; ")}. Try it on the <Link to="/concierge">Concierge</Link>.
          </p>
        ) : null}
        {applyError ? (
          <span role="alert" className="fathom-inline-error">
            {applyError}
          </span>
        ) : null}
      </section>
    </div>
  );
}
