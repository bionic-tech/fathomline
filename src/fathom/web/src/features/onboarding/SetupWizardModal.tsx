// First-run setup wizard (Build P4): the very first admin to open a fresh estate is greeted with the
// Getting Started wizard as a floating MODAL — no hunting for it in the nav. It auto-shows until ANY
// admin completes it once, recorded as a single estate-wide flag (onboarding_completed) in the
// settings store. After completion the modal never auto-opens again and the standalone "Getting
// Started" nav link is hidden; an admin can re-arm it from Settings. Non-admins never see it (only an
// admin holds manage_settings, the capability needed to apply the recommended settings).

import { useState } from "react";

import { useServerConfig, useSetSetting, useWhoAmI } from "../../api/queries";
import { principalHas } from "../../auth/rbac";
import { GettingStarted } from "./GettingStarted";
import { ONBOARDING_SETTING_KEY, onboardingCompleted } from "./onboardingFlag";

export function SetupWizardModal(): JSX.Element | null {
  const me = useWhoAmI();
  const serverConfig = useServerConfig();
  const setSetting = useSetSetting();
  // Session-local "skip": closes the modal WITHOUT recording completion, so it returns on the next
  // login. Only "Finish" writes the estate-wide flag and stops it auto-showing for good.
  const [dismissed, setDismissed] = useState(false);

  const isAdmin = principalHas(me.data, "manage_settings");
  const completed = onboardingCompleted(serverConfig.data);
  // Auto-show only once config has loaded (no flash before we know), the estate hasn't onboarded,
  // and the viewer is an admin who can actually apply the recommended settings.
  const open = serverConfig.isSuccess && !completed && isAdmin && !dismissed;
  if (!open) return null;

  async function finish(): Promise<void> {
    try {
      await setSetting.mutateAsync({ key: ONBOARDING_SETTING_KEY, value: true });
    } finally {
      // Close at once; the server-config refetch the mutation triggers also reports completed=true,
      // so it never auto-shows again even after this session-local flag is forgotten.
      setDismissed(true);
    }
  }

  return (
    <div className="fathom-modal-backdrop" role="presentation">
      <div className="fathom-modal" role="dialog" aria-modal="true" aria-label="First-run setup">
        <header className="fathom-modal-head">
          <h2>Welcome — let&apos;s set up Fathom</h2>
        </header>
        <p className="fathom-muted">
          A one-time guided setup for your estate&apos;s AI features. Finish it now, or skip and
          return any time — admins can re-run it from Settings.
        </p>

        <GettingStarted />

        <footer className="fathom-modal-foot">
          <button type="button" className="fathom-btn" onClick={() => setDismissed(true)}>
            Skip for now
          </button>
          <button
            type="button"
            className="fathom-btn fathom-btn-primary"
            disabled={setSetting.isPending}
            onClick={() => void finish()}
          >
            {setSetting.isPending ? "Finishing…" : "Finish setup"}
          </button>
        </footer>
      </div>
    </div>
  );
}
