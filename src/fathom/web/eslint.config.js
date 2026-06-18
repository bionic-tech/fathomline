// Flat ESLint config for the SPA (frontend ADD §3). typescript-eslint provides the parser +
// recommended TS rules; the strict typecheck (tsc) remains the primary gate. console.* is
// forbidden so all logging goes through the DEV-guarded helpers in lib/csp.ts (frontend ADD
// §12: console gated to DEV).
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", "src/api/generated/"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "no-console": "error",
    },
  },
);
