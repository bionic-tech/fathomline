// Use-case "story" screenshots for the E2E harness (Phase E). Unlike the per-page screenshot.mjs,
// this drives real flows in ONE SPA session (in-app navigation preserves the in-memory volume/path
// store) so each shot tells a story against the deterministic synthetic corpus:
//   * dashboard       — the estate at a glance (totals + growth)
//   * explorer        — drill into /data/downloads
//   * largest-files   — biggest FILES under /data/downloads, server-ranked
//   * duplicates      — estate-wide duplicate groups, expanded, incl. the cross-mount "mount alias"
//                       false-positive (ADR-032) and its 0-reclaimable highlight
//   * ai-organize     — the local-model reorganisation proposal (group-by-type)
//   * reconcile / agents / scans / changes / audit / search
//
// It ALSO asserts the rendered UI content (not just captures it): each story checks the page shows
// the expected values from the synthetic corpus (largest file, by-type organize proposal, the
// "mount alias" badge, the seeded hosts, search hits), so a UI that renders wrong/empty data against
// a correct backend FAILS (exit 1) instead of merely looking off in a screenshot. Output:
// $E2E_OUT/shots/*.png + $E2E_OUT/ui-report.json. Exits 0 if Playwright is absent (graceful skip).
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// playwright is installed under src/fathom/web/node_modules; ESM resolves bare specifiers from the
// module's own dir (not cwd), so require it by absolute path so this runs from anywhere.
const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const pwPath = process.env.E2E_PLAYWRIGHT || resolve(here, "../../src/fathom/web/node_modules/playwright");
let chromium;
try {
  chromium = require(pwPath).chromium;
} catch (e) {
  // Playwright/chromium not installed: skip UI verification gracefully (exit 0, NOT a failure) so a
  // non-zero exit unambiguously means a real UI-assertion failure for run_e2e.sh.
  console.log(`playwright unavailable — skipping UI verification + screenshots: ${String(e).split("\n")[0]}`);
  process.exit(0);
}
const BASE = process.env.FATHOM_LOCAL_API || "http://127.0.0.1:8097";
const USER = "admin";
const PASS = process.env.FATHOM_LOCAL_ADMIN_PASS || "localdev-admin-pw";
const OUT = (process.env.E2E_OUT || "/tmp/fathom-e2e") + "/shots";
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1480, height: 1000 } });
const log = (m) => console.log(m);

// ---- UI-content assertions (the gap screenshots alone miss) ------------------------------------
// Each story asserts the RENDERED page actually shows the expected values from the synthetic corpus,
// so a UI that displays wrong/empty data against a correct backend FAILS here (not just looks off in
// a screenshot). Failures are collected and the process exits non-zero so run_e2e.sh treats a UI
// regression as a real failure.
const checks = [];
function record(name, ok, detail) {
  checks.push({ name, ok, detail });
  log(`  [${ok ? "PASS" : "FAIL"}] ui:${name} — ${detail}`);
}
async function expectText(name, ...needles) {
  let body = "";
  try {
    body = await page.locator("body").innerText({ timeout: 5000 });
  } catch {
    /* fall through to fail */
  }
  const missing = needles.filter((n) => !body.includes(n));
  record(name, missing.length === 0, missing.length ? `missing: ${missing.join(", ")}` : `found: ${needles.join(", ")}`);
}

async function shot(name) {
  await page.waitForTimeout(900);
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });
  log(`  shot: ${name}`);
}
async function story(name, fn) {
  try {
    await fn();
    await shot(name);
  } catch (e) {
    log(`  !! story ${name} failed: ${String(e).split("\n")[0]}`);
    try { await shot(`${name}-error`); } catch { /* ignore */ }
  }
}
async function nav(href) {
  await page.click(`a[href="${href}"]`).catch(async () => { await page.goto(`${BASE}${href}`); });
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(700);
}

// ---- login -------------------------------------------------------------------------------------
await page.goto(`${BASE}/login`, { waitUntil: "networkidle" });
await page.fill('input[name="username"]', USER);
await page.fill('input[name="password"]', PASS);
await page.click('button[type="submit"]');
await page.waitForURL(/dashboard|\/$/, { timeout: 12000 }).catch(() => {});
await page.waitForTimeout(1500);

// ---- volume picker helper (top-bar <select>) --------------------------------------------------
async function selectVolume(match) {
  const sel = page.locator("header select, nav select, select").first();
  const labels = await sel.locator("option").allTextContents();
  const idx = labels.findIndex(match);
  if (idx >= 0) await sel.selectOption({ index: idx });
  await page.waitForTimeout(900);
}
// default scope: /data
await selectVolume((t) => t.includes("/data") && !t.includes("/nfsmnt")).catch((e) =>
  log(`  (volume select skipped: ${String(e).split("\n")[0]})`),
);

// ---- stories -----------------------------------------------------------------------------------
await story("01-dashboard", async () => {
  await nav("/dashboard");
  await expectText("dashboard-loaded", "Dashboard");
});

await story("02-explorer-downloads", async () => {
  await nav("/explore");
  await page.getByText("downloads", { exact: true }).first().click().catch(() => {});
  await page.waitForTimeout(900);
  await expectText("explorer-downloads-listing", "movie.mkv"); // the folder's files render
});

// After drilling into downloads above, Largest ranks the biggest FILES in that folder.
await story("03-largest-files", async () => {
  await nav("/largest");
  // switch the "kind" toggle to files if present, else default view is fine
  await page.getByRole("button", { name: /file/i }).first().click().catch(() => {});
  await page.waitForTimeout(700);
  await expectText("largest-shows-biggest-file", "movie.mkv"); // 7MB = biggest under downloads
});

await story("04-ai-organize", async () => {
  await nav("/organize");
  await page.getByRole("button", { name: /suggest reorgani/i }).click().catch(async () => {
    await page.getByRole("button", { name: /suggest/i }).first().click().catch(() => {});
  });
  await page.waitForTimeout(2500); // wait for the (mock) model proposal to render
  // the proposal must render the by-type grouping: movie.mkv -> videos/, song.mp3 -> audio/
  await expectText("organize-proposal", "movie.mkv", "videos", "audio");
});

await story("05-duplicates-and-mount-alias", async () => {
  await nav("/duplicates");
  // expand every group row so members (and the "mount alias" badge) render
  const expanders = page.locator('button[aria-expanded]');
  const n = await expanders.count().catch(() => 0);
  for (let i = 0; i < n; i++) {
    await expanders.nth(i).click().catch(() => {});
    await page.waitForTimeout(400);
  }
  await page.waitForTimeout(800);
  // estate-wide dups render with a suggested keeper + the cross-host a.jpg group, and members show
  // HOST NAMES (not numeric ids) so you can tell which host each copy lives on (UI review fix).
  await expectText("duplicates-render", "Duplicates", "suggested", "a.jpg", "nas-1", "tiger-1");
});

// The cross-mount alias group lives on /raid (native) + /nfsmnt (NFS view); the duplicates page is
// volume-scoped, so switch scope to /nfsmnt to surface the "mount alias" false-positive highlight.
await story("05b-cross-mount-alias", async () => {
  await selectVolume((t) => t.includes("/nfsmnt"));
  await nav("/duplicates");
  const expanders = page.locator('button[aria-expanded]');
  const n = await expanders.count().catch(() => 0);
  for (let i = 0; i < n; i++) { await expanders.nth(i).click().catch(() => {}); await page.waitForTimeout(400); }
  await page.waitForTimeout(800);
  // the headline ADR-032 assertion: the NFS view is flagged "mount alias" on the movie.bin group
  await expectText("cross-mount-alias-badge", "mount alias", "movie.bin");
});
await selectVolume((t) => t.includes("/data") && !t.includes("/nfsmnt")).catch(() => {});

await story("06-reconcile", async () => { await nav("/reconcile"); });
await story("07-agents", async () => {
  await nav("/agents");
  await expectText("agents-list", "nas-1", "tiger-1"); // both seeded hosts present
});
await story("08-scans", async () => { await nav("/scans"); });
await story("09-changes", async () => { await nav("/changes"); });
await story("10-audit", async () => { await nav("/audit"); });
await story("11-search-movie", async () => {
  await nav("/search");
  await page.fill('input[type="search"], input[type="text"], input', "movie").catch(() => {});
  await page.keyboard.press("Enter").catch(() => {});
  await page.waitForTimeout(1200);
  await expectText("search-movie-results", "movie.bin", "movie.mkv"); // 3 hits across hosts
});

await browser.close();

// ---- write UI report + exit non-zero on any UI-assertion failure ------------------------------
const { writeFileSync } = await import("node:fs");
const passed = checks.filter((c) => c.ok).length;
const failed = checks.filter((c) => !c.ok);
writeFileSync((process.env.E2E_OUT || "/tmp/fathom-e2e") + "/ui-report.json",
  JSON.stringify({ passed, total: checks.length, ok: failed.length === 0, checks }, null, 2));
log(`\nUI assertions: ${passed}/${checks.length} passed; screenshots -> ${OUT}`);
if (failed.length) {
  log(`UI FAILURES: ${failed.map((c) => c.name).join(", ")}`);
  process.exit(1);
}
log("done.");
