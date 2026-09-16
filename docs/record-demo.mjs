/* Records the console being used, for the animation in the README.
 *
 * Usage, from the repository root:
 *   node docs/record-demo.mjs [consoleUrl] [targetUrl]
 *
 * Needs playwright (npm i playwright), a console running, and a target worth
 * showing. The demo target is built by docs/make-demo-target.py: a folder of
 * harmless files that carries the shapes DirSift looks for, so the recording
 * never points at anyone's real server.
 *
 * Playwright draws no cursor, so every click is announced by flashing a ring on
 * the element first. The scan in the recording is real, at the fastest delay the
 * tool allows.
 */

import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const BASE = process.argv[2] || "http://127.0.0.1:8000";
const TARGET = process.argv[3] || "http://127.0.0.1:8765/";
const OUT = "docs/demo-recording";
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1280, height: 800 },
  recordVideo: { dir: OUT, size: { width: 1280, height: 800 } },
  deviceScaleFactor: 1,
});
const page = await context.newPage();

async function spotlight(selector) {
  const target = page.locator(selector).first();
  await target.scrollIntoViewIfNeeded();
  await target.evaluate((element) => {
    const previous = element.style.boxShadow;
    element.style.boxShadow = "0 0 0 3px #56c7f2";
    window.setTimeout(() => { element.style.boxShadow = previous; }, 700);
  });
  await page.waitForTimeout(650);
}

async function act(selector, action) {
  await spotlight(selector);
  await action();
  await page.waitForTimeout(600);
}

await page.goto(BASE + "/", { waitUntil: "networkidle" });
await page.waitForTimeout(1200);

// Fill the scan form the way a person would, one field at a time.
await spotlight("#url");
await page.click("#url");
await page.type("#url", TARGET, { delay: 45 });
await page.waitForTimeout(400);
await act("#delay", async () => { await page.fill("#delay", "0.2"); });
await act('input[name="allow_private"]', async () => {
  await page.check('input[name="allow_private"]');
});
await act('form[action="/scan"] button[type="submit"]', async () => {
  await page.click('form[action="/scan"] button[type="submit"]');
});

// The job page polls; the console redirects itself when the walk finishes.
await page.waitForURL(/\/runs\//, { timeout: 120000 });
await page.waitForTimeout(1500);

// Read the top of the triage page, then the cards under it.
await page.evaluate(() => window.scrollTo({ top: 0 }));
await page.waitForTimeout(1200);
await page.evaluate(() => window.scrollBy({ top: 420, behavior: "smooth" }));
await page.waitForTimeout(1600);

// Open the file that drives the rest.
const driver = '[data-listing] button:has-text("install.bat")';
await page.evaluate(() => window.scrollBy({ top: 520, behavior: "smooth" }));
await page.waitForTimeout(900);
await act(driver, async () => { await page.click(driver); });
await page.waitForTimeout(1600);

// The evidence, then the bytes, then what it is linked to.
await act("#tab-hex", async () => { await page.click("#tab-hex"); });
await page.waitForTimeout(1500);
await act("#tab-links", async () => { await page.click("#tab-links"); });
await page.waitForTimeout(1800);

// Pick two files and turn them into a rule.
const boxes = await page.$$('[data-listing] input[type="checkbox"]');
if (boxes.length > 7) {
  await boxes[5].check();
  await page.waitForTimeout(350);
  await boxes[6].check();
  await page.waitForTimeout(500);
}
await act('[data-listing] button[type="submit"]', async () => {
  await page.click('[data-listing] button[type="submit"]');
});
await page.waitForTimeout(2600);

await context.close();
await browser.close();
console.log("video written under", OUT);
