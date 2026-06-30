// Runtime settings store (ADR-038): the admin-only panel to edit the in-app, persistent,
// live-reloaded configuration. Non-secret settings edit in place (a change is live on the next
// request); secret settings + free-form named secrets are masked, set/cleared, and revealed through
// the step-up-MFA-gated routes. The server is authoritative — it validates every value, gates every
// route on MANAGE_SETTINGS, and re-checks fresh MFA on the secret routes — so this is a UX layer.

import { useState } from "react";

import { ApiError } from "../../api/client";
import {
  useClearSecret,
  useClearSetting,
  useRevealSecret,
  useSetSecret,
  useSetSetting,
  useSettings,
  useTestNotificationChannels,
} from "../../api/queries";
import type { NotifyChannelResult, SettingOut } from "../../api/types";
import { QueryState } from "../common/QueryState";
import { Tabs, type TabDef } from "../common/Tabs";

const CATEGORY_LABELS: Record<string, string> = {
  general: "General & UI",
  auth: "Authentication",
  ingest: "Ingest",
  inference: "LLM inference",
  organize: "Organize (AI)",
  concierge: "AI concierge",
  remediation: "Remediation",
  preview: "Preview sandbox",
  scan_coordinator: "Scan coordinator",
  notifications: "Notifications",
  retention: "Retention",
};

// Tab order (most operators reach for the AI + notification knobs first; infra/auth last).
const CATEGORY_ORDER = [
  "general",
  "inference",
  "concierge",
  "organize",
  "notifications",
  "scan_coordinator",
  "remediation",
  "preview",
  "retention",
  "ingest",
  "auth",
];

function errText(err: unknown, fallback: string): string {
  return err instanceof ApiError ? (err.problem.detail ?? fallback) : fallback;
}

function SettingRow({ setting }: { setting: SettingOut }): JSX.Element {
  const set = useSetSetting();
  const clear = useClearSetting();
  const reveal = useRevealSecret();
  const [draft, setDraft] = useState<string>(
    setting.is_secret ? "" : String(setting.value ?? ""),
  );
  const [revealed, setRevealed] = useState<string | null>(null);

  const onSave = (): void => {
    let value: unknown = draft;
    if (setting.type === "bool") value = draft === "true";
    else if (setting.type === "int") value = Number.parseInt(draft, 10);
    else if (setting.type === "float") value = Number.parseFloat(draft);
    set.mutate({ key: setting.key, value });
  };

  return (
    <tr>
      <td>
        <div className="fathom-setting-label">{setting.label}</div>
        {setting.restart_required ? (
          <span className="fathom-badge fathom-badge-warn" title="Persisted, but needs a restart to fully apply">
            restart
          </span>
        ) : null}
        {setting.overridden ? (
          <span className="fathom-badge fathom-badge-role" title="An in-app override is set">
            overridden
          </span>
        ) : null}
        <div className="fathom-muted fathom-help">{setting.help}</div>
        <code className="fathom-setting-key">{setting.key}</code>
      </td>
      <td>
        {setting.is_secret ? (
          <div className="fathom-form-inline">
            <input
              type="password"
              aria-label={`${setting.key} value`}
              placeholder={setting.is_set ? "•••••• (set)" : "(unset)"}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            {revealed != null ? <code className="fathom-revealed">{revealed}</code> : null}
          </div>
        ) : setting.options ? (
          // Strict dropdown. Keep the current value selectable even if it's outside the closed set
          // (e.g. an env-seeded model that predates the provider switch) so it's never silently lost.
          <select aria-label={setting.key} value={draft} onChange={(e) => setDraft(e.target.value)}>
            {(setting.options.includes(draft) ? setting.options : [draft, ...setting.options]).map(
              (opt) => (
                <option key={opt} value={opt}>
                  {opt === "" ? "(unset)" : opt}
                </option>
              ),
            )}
          </select>
        ) : setting.suggestions && setting.suggestions.length > 0 ? (
          // Combobox: free text with suggested values (e.g. Ollama model tags, or a per-feature
          // model override where blank = use the inference model).
          <>
            <input
              type="text"
              aria-label={setting.key}
              list={`${setting.key}-suggestions`}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            <datalist id={`${setting.key}-suggestions`}>
              {setting.suggestions.map((opt) => (
                <option key={opt} value={opt} />
              ))}
            </datalist>
          </>
        ) : setting.type === "bool" ? (
          <select aria-label={setting.key} value={draft} onChange={(e) => setDraft(e.target.value)}>
            <option value="true">on</option>
            <option value="false">off</option>
          </select>
        ) : (
          <input
            type={setting.type === "int" || setting.type === "float" ? "number" : "text"}
            aria-label={setting.key}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
          />
        )}
      </td>
      <td className="fathom-actions">
        <button
          type="button"
          className="fathom-btn fathom-btn-primary"
          disabled={set.isPending || (setting.is_secret && draft === "")}
          onClick={onSave}
        >
          Save
        </button>
        {setting.is_secret && setting.is_set ? (
          <button
            type="button"
            className="fathom-btn"
            disabled={reveal.isPending}
            onClick={() =>
              reveal.mutate(setting.key, { onSuccess: (d) => setRevealed(d.value) })
            }
          >
            Reveal
          </button>
        ) : null}
        {setting.overridden ? (
          <button
            type="button"
            className="fathom-btn fathom-btn-danger"
            disabled={clear.isPending}
            onClick={() => clear.mutate(setting.key)}
          >
            Reset
          </button>
        ) : null}
        {set.isError ? (
          <span role="alert" className="fathom-inline-error">
            {errText(set.error, "Save failed.")}
          </span>
        ) : null}
        {reveal.isError ? (
          <span role="alert" className="fathom-inline-error">
            {errText(reveal.error, "Reveal failed (fresh MFA required).")}
          </span>
        ) : null}
      </td>
    </tr>
  );
}

function NamedSecrets({ refs }: { refs: string[] }): JSX.Element {
  const setSecret = useSetSecret();
  const clearSecret = useClearSecret();
  const reveal = useRevealSecret();
  const [ref, setRef] = useState("");
  const [value, setValue] = useState("");
  const [revealed, setRevealed] = useState<Record<string, string>>({});

  const onAdd = (e: React.FormEvent): void => {
    e.preventDefault();
    setSecret.mutate({ ref, value }, { onSuccess: () => { setRef(""); setValue(""); } });
  };

  return (
    <section aria-label="Named secrets" className="fathom-card">
      <h3 className="fathom-card-title">Named secrets</h3>
      <p className="fathom-muted">
        Credentials the secret backend resolves by reference (e.g. an LLM API key whose name you put
        in <code>inference_anthropic_key_ref</code>). Encrypted at rest; revealing requires fresh
        step-up MFA.
      </p>
      {refs.length === 0 ? (
        <p className="fathom-muted">No named secrets stored in-app.</p>
      ) : (
        <ul className="fathom-assignment-list">
          {refs.map((r) => (
            <li key={r}>
              <code>{r}</code>
              {revealed[r] != null ? <code className="fathom-revealed">{revealed[r]}</code> : null}
              <button
                type="button"
                className="fathom-btn"
                disabled={reveal.isPending}
                onClick={() =>
                  reveal.mutate(r, {
                    onSuccess: (d) => setRevealed((cur) => ({ ...cur, [r]: d.value })),
                  })
                }
              >
                Reveal
              </button>
              <button
                type="button"
                className="fathom-btn fathom-btn-danger"
                disabled={clearSecret.isPending}
                onClick={() => clearSecret.mutate(r)}
              >
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
      <form className="fathom-form fathom-form-inline" onSubmit={onAdd} aria-label="Add named secret">
        <label className="fathom-field">
          Reference name
          <input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="ANTHROPIC_KEY" />
        </label>
        <label className="fathom-field">
          Value
          <input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="secret value"
          />
        </label>
        <button
          type="submit"
          className="fathom-btn fathom-btn-primary"
          disabled={setSecret.isPending || ref === "" || value === ""}
        >
          Add secret
        </button>
        {setSecret.isError ? (
          <span role="alert" className="fathom-inline-error">
            {errText(setSecret.error, "Add failed (fresh MFA required).")}
          </span>
        ) : null}
      </form>
    </section>
  );
}

function TestChannels(): JSX.Element {
  const test = useTestNotificationChannels();
  const results: NotifyChannelResult[] = test.data?.results ?? [];
  return (
    <section aria-label="Notification channel test" className="fathom-card">
      <h3 className="fathom-card-title">Notification channels</h3>
      <p className="fathom-muted">
        Configure the Email/Chat channels above (the password / webhook value goes under Named
        secrets), then send a test to verify connectivity. The test ignores the category/severity
        policy and contacts only channels you have enabled.
      </p>
      <button
        type="button"
        className="fathom-btn fathom-btn-primary"
        disabled={test.isPending}
        onClick={() => test.mutate()}
      >
        Send test notification
      </button>
      {test.data && results.length === 0 ? (
        <p className="fathom-muted">No channels enabled.</p>
      ) : null}
      {results.length > 0 ? (
        <ul className="fathom-assignment-list">
          {results.map((r) => (
            <li key={r.channel}>
              <code>{r.channel}</code>{" "}
              <span className={r.ok ? "fathom-badge fathom-badge-role" : "fathom-badge fathom-badge-warn"}>
                {r.ok ? "ok" : "failed"}
              </span>{" "}
              <span className="fathom-muted">{r.detail}</span>
            </li>
          ))}
        </ul>
      ) : null}
      {test.isError ? (
        <span role="alert" className="fathom-inline-error">
          {errText(test.error, "Test failed.")}
        </span>
      ) : null}
    </section>
  );
}

function SettingsTable({ items }: { items: SettingOut[] }): JSX.Element {
  return (
    <table className="fathom-table">
      <caption className="sr-only">settings</caption>
      <thead>
        <tr>
          <th scope="col">Setting</th>
          <th scope="col">Value</th>
          <th scope="col">Actions</th>
        </tr>
      </thead>
      <tbody>
        {items.map((s) => (
          <SettingRow key={s.key} setting={s} />
        ))}
      </tbody>
    </table>
  );
}

// Common settings render directly; "advanced" ones (e.g. external-secret-backend *references* —
// rarely needed now the key can be entered directly) collapse behind a disclosure so the panel
// stays uncluttered. Settings that don't currently apply (e.g. the Ollama URL while the provider is
// Anthropic) are hidden entirely — the server marks them with relevant=false.
function CategoryTable({ items }: { items: SettingOut[] }): JSX.Element {
  const applicable = items.filter((s) => s.relevant);
  const common = applicable.filter((s) => !s.advanced);
  const advanced = applicable.filter((s) => s.advanced);
  return (
    <>
      <SettingsTable items={common} />
      {advanced.length > 0 ? (
        <details className="fathom-advanced">
          <summary>Advanced ({advanced.length})</summary>
          <SettingsTable items={advanced} />
        </details>
      ) : null}
    </>
  );
}

export function RuntimeSettings(): JSX.Element {
  const settings = useSettings();
  const byCategory = new Map<string, SettingOut[]>();
  for (const s of settings.data?.settings ?? []) {
    const list = byCategory.get(s.category) ?? [];
    list.push(s);
    byCategory.set(s.category, list);
  }

  // One tab per present category (in CATEGORY_ORDER; any unknown trailing), the channel test
  // tucked into Notifications, plus a Secrets tab.
  const presentCats = [
    ...CATEGORY_ORDER.filter((c) => byCategory.has(c)),
    ...[...byCategory.keys()].filter((c) => !CATEGORY_ORDER.includes(c)),
  ];
  const tabs: TabDef[] = presentCats.map((cat) => ({
    id: cat,
    label: CATEGORY_LABELS[cat] ?? cat,
    content: (
      <>
        {cat === "inference" ? (
          <p className="fathom-note fathom-note-info" role="note">
            The inference model here is shared by every AI feature (Organize, Concierge, file
            suggestions). Switching the provider resets it to that provider&apos;s default, so you
            never call one provider with another&apos;s model. To use a different model for one
            specific feature, set that feature&apos;s own model override in the advanced rows below.
          </p>
        ) : null}
        <CategoryTable items={byCategory.get(cat) ?? []} />
        {cat === "notifications" ? <TestChannels /> : null}
      </>
    ),
  }));
  if (settings.data) {
    tabs.push({
      id: "secrets",
      label: "Named secrets",
      content: <NamedSecrets refs={settings.data.named_secrets} />,
    });
  }

  return (
    <section aria-label="Runtime settings" className="fathom-card">
      <h2 className="fathom-card-title">Runtime settings</h2>
      <p className="fathom-muted">
        Edit configuration in-app — a change is live on the next request (no restart), unless flagged{" "}
        <span className="fathom-badge fathom-badge-warn">restart</span>. The environment seeds the
        defaults; an in-app value wins. Secrets are encrypted at rest.
      </p>
      <QueryState isLoading={settings.isLoading} isError={settings.isError} error={settings.error}>
        {settings.data ? <Tabs tabs={tabs} ariaLabel="Runtime settings sections" /> : null}
      </QueryState>
    </section>
  );
}
