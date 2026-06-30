// onboarding_completed (Build P4) is a server-config flag that is not in the shared ServerConfigOut
// type yet — the parent will add it to api/types.ts. Until then we read it through a local cast so
// this feature compiles against the not-yet-extended shared type. Centralised here so the first-run
// modal, the nav-link gate (AppShell) and the re-run control all read it the same way.

import type { ServerConfigOut } from "../../api/types";

/** The settings-store key for the estate-wide first-run flag. */
export const ONBOARDING_SETTING_KEY = "onboarding_completed";

/** Whether the first-run setup wizard has been completed for this estate. */
export function onboardingCompleted(cfg: ServerConfigOut | undefined): boolean {
  return Boolean((cfg as { onboarding_completed?: boolean } | undefined)?.onboarding_completed);
}
