/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Built to dist/ and COPYed into the api image (ADR-012 supply chain); served same-origin
// under / by the FastAPI api container with SPA history fallback (frontend ADD §15). In dev
// the SPA runs on Vite and proxies /api → the api container so it is same-origin there too.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "dist",
    // No source maps in production (frontend ADD §12: source maps off in prod).
    sourcemap: false,
    // Hashed, content-addressed asset filenames under /assets so the strict CSP can pin them
    // and the api container can serve them immutably.
    assetsDir: "assets",
  },
  server: {
    proxy: {
      "/api": {
        target: process.env.FATHOM_API_PROXY ?? "http://localhost:8088",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // Vitest owns the component/unit tests under src/; Playwright owns tests/e2e/ (its own
    // runner) — exclude it here so `vitest run` does not try to resolve @playwright/test.
    include: ["src/**/*.test.{ts,tsx}"],
    exclude: ["tests/e2e/**", "node_modules/**", "dist/**"],
  },
});
