// Capture a screenshot of every Fathom SPA page against the local dev server, as visual proof the
// pages render with real data. Needs Playwright + its chromium:
//   npx playwright install chromium
//   node scripts/localdev/screenshot.mjs
// Output: /tmp/fathom-shots/*.png . Playwright ships CommonJS, so it is default-imported.
import playwright from "playwright";
import { mkdirSync } from "node:fs";

const { chromium } = playwright;

const BASE = process.env.FATHOM_LOCAL_API || "http://127.0.0.1:8099";
const USER = "admin";
const PASS = process.env.FATHOM_LOCAL_ADMIN_PASS || "localdev-admin-pw";
const OUT = "/tmp/fathom-shots";
mkdirSync(OUT, { recursive: true });

const PAGES = [
  ["dashboard", "/dashboard"],
  ["explorer", "/explore"],
  ["duplicates", "/duplicates"],
  ["scans", "/scans"],
  ["agents", "/agents"],
  ["audit", "/audit"],
  ["settings", "/settings"],
];

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

await page.goto(`${BASE}/login`, { waitUntil: "networkidle" });
await page.fill('input[name="username"]', USER);
await page.fill('input[name="password"]', PASS);
await page.click('button[type="submit"]');
await page.waitForURL(/dashboard|\/$/, { timeout: 10000 }).catch(() => {});
await page.waitForTimeout(1500);

for (const [name, path] of PAGES) {
  await page.goto(`${BASE}${path}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1800); // let charts/queries settle
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });
  console.log(`shot: ${name}`);
}

await browser.close();
console.log(`done -> ${OUT}`);
