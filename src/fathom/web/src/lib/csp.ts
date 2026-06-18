// Client-side CSP / DEV guards (frontend ADD §12).
//
// The authoritative Content-Security-Policy is the response *header* sent by the api
// container's SecurityHeadersMiddleware (no unsafe-inline / no unsafe-eval). This module only
// holds the DEV-guard helpers the rest of the SPA uses so no console output and no source maps
// leak in production, and so the build never introduces an inline-script/eval requirement.

export const IS_DEV: boolean = import.meta.env.DEV;

/** DEV-only console.* — silent in production (frontend ADD §12: all console gated to DEV). */
export const devLog: (...args: unknown[]) => void = IS_DEV
  ? // eslint-disable-next-line no-console
    (...args: unknown[]) => console.log("[fathom]", ...args)
  : () => {};

/** DEV-only console.error — silent in production. */
export const devError: (...args: unknown[]) => void = IS_DEV
  ? // eslint-disable-next-line no-console
    (...args: unknown[]) => console.error("[fathom]", ...args)
  : () => {};
