// Playwright E2E skeleton (frontend ADD §14). Runs against a built SPA served by the api
// container (same-origin). These are the risky-flow acceptance checks; they are skeletons here
// (skipped until the E2E harness + seeded fixture estate are wired in CI) so the contract is
// captured without a flaky live dependency.
//
// Run:  npx playwright test   (after `npm run build` and bringing up the api with FATHOM_WEB_DIST)

import { expect, test } from "@playwright/test";

const BASE = process.env.FATHOM_E2E_BASE ?? "http://localhost:8088";

test.describe("dashboard + explorer", () => {
  test.skip(true, "enable once the E2E harness + seeded estate fixture land in CI");

  test("dashboard loads volume usage + estate treemap", async ({ page }) => {
    await page.goto(`${BASE}/dashboard`);
    await expect(page.getByRole("heading", { name: /estate dashboard/i })).toBeVisible();
    // The volume usage chart renders with its a11y data-table alternative.
    await expect(page.getByRole("table", { name: /volume capacity/i })).toBeAttached();
  });

  test("explorer drill-down lazy-loads children without a full-tree load", async ({ page }) => {
    await page.goto(`${BASE}/explore`);
    await expect(page.getByRole("navigation", { name: /directory tree/i })).toBeVisible();
  });

  test("out-of-scope hosts are never rendered (scope-aware)", async ({ page }) => {
    await page.goto(`${BASE}/dashboard`);
    await expect(page.getByText("out-of-scope-host")).toHaveCount(0);
  });

  test("logout clears client storage", async ({ page }) => {
    await page.goto(`${BASE}/dashboard`);
    await page.getByRole("button", { name: /sign out/i }).click();
    const localStorageLength = await page.evaluate(() => window.localStorage.length);
    expect(localStorageLength).toBe(0);
  });
});
