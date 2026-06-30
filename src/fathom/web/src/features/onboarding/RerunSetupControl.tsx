// Re-run setup control (Build P4): an admin-only button (rendered under Settings) that re-arms the
// first-run setup wizard by clearing the estate-wide onboarding_completed flag. The wizard then
// auto-shows again on the next admin login. Writing the flag goes through the same settings-store
// PUT used everywhere else (the server re-enforces MANAGE_SETTINGS).

import { ApiError } from "../../api/client";
import { useServerConfig, useSetSetting, useWhoAmI } from "../../api/queries";
import { principalHas } from "../../auth/rbac";
import { ONBOARDING_SETTING_KEY, onboardingCompleted } from "./onboardingFlag";

export function RerunSetupControl(): JSX.Element | null {
  const me = useWhoAmI();
  const serverConfig = useServerConfig();
  const setSetting = useSetSetting();

  // Admin-only — the server also enforces MANAGE_SETTINGS on the write.
  if (!principalHas(me.data, "manage_settings")) return null;

  const completed = onboardingCompleted(serverConfig.data);
  const rearmed = setSetting.isSuccess && !completed;

  return (
    <section aria-label="Setup wizard" className="fathom-card">
      <h2 className="fathom-card-title">Setup wizard</h2>
      <p className="fathom-muted">
        {completed
          ? "The first-run setup wizard has been completed for this estate. Re-run it to walk through the AI setup again — it appears on the next login for any admin."
          : "The first-run setup wizard is armed and will appear on the next admin login."}
      </p>
      <button
        type="button"
        className="fathom-btn"
        disabled={setSetting.isPending || !completed}
        onClick={() => setSetting.mutate({ key: ONBOARDING_SETTING_KEY, value: false })}
      >
        {setSetting.isPending ? "Working…" : "Run setup wizard again"}
      </button>
      {setSetting.isError ? (
        <span role="alert" className="fathom-inline-error">
          {setSetting.error instanceof ApiError
            ? (setSetting.error.problem.detail ?? "Could not re-arm the setup wizard.")
            : "Could not re-arm the setup wizard."}
        </span>
      ) : null}
      {rearmed ? (
        <span role="status" className="fathom-inline-ok">
          Setup wizard re-armed — it will show on the next admin login.
        </span>
      ) : null}
    </section>
  );
}
