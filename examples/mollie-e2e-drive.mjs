#!/usr/bin/env node
// Canonical copy: attesso repository, scripts/mollie-e2e-drive.mjs.
// Unattended driver for scripts/mollie-e2e.mjs: watches the harness output for
// the two browser handoffs and plays them with Playwright — the passkey
// approval (virtual CTAP2 authenticator, same recipe as
// verify-browser-lifecycle.mjs) and the Mollie test checkout (iDEAL for the
// paid phase, card + documented magic amount for the failed phase).
//
// Rehearsal rig, not a product.
//
// Usage:
//   MOLLIE_API_KEY=test_... MOLLIE_WEBHOOK_URL=https://.../mollie-webhook \
//     node scripts/mollie-e2e-drive.mjs [--runs N] [--headed]
//
// Run from a directory holding attesso-quickstart.json (the harness reads it
// from the working directory), with an `open` shim early on PATH so the
// harness does not open real browser windows.
//
// Playwright resolves from this repo root; set MOLLIE_DRIVE_PLAYWRIGHT_HOME
// to a directory with node_modules/playwright when running from a worktree
// that has no install (for example the main checkout).
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HARNESS = resolve(__dirname, 'mollie-e2e.mjs');

const platformAuthenticator = {
  protocol: 'ctap2',
  ctap2Version: 'ctap2_1',
  transport: 'internal',
  hasResidentKey: true,
  hasUserVerification: true,
  automaticPresenceSimulation: true,
  isUserVerified: true,
};

const require = createRequire(import.meta.url);
const playwrightRoots = [process.env.MOLLIE_DRIVE_PLAYWRIGHT_HOME, resolve(__dirname, '..'), process.cwd()]
  .filter((entry) => typeof entry === 'string' && entry !== '');
let playwright;
for (const root of playwrightRoots) {
  try {
    playwright = await import(require.resolve('playwright', { paths: [root] }));
    break;
  } catch {
    // Try the next root.
  }
}
if (playwright === undefined) {
  throw new Error('playwright not found; run pnpm install or set MOLLIE_DRIVE_PLAYWRIGHT_HOME');
}
const chromium = playwright.chromium ?? playwright.default.chromium;

function parseArguments(argv) {
  const options = { runs: 1, headed: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--headed') {
      options.headed = true;
    } else if (argument === '--runs') {
      const value = argv[index + 1];
      if (value === undefined || !/^[0-9]+$/.test(value) || Number(value) < 1) {
        throw new Error('--runs requires a positive integer');
      }
      options.runs = Number(value);
      index += 1;
    } else {
      throw new Error('unknown argument: ' + argument);
    }
  }
  return options;
}

function stamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

// -- browser walks -----------------------------------------------------------

async function driveApproval(browser, approvalURL, log) {
  log(`[drive] approval: opening ${approvalURL.slice(0, 96)}...`);
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: platformAuthenticator });
    await page.goto(approvalURL, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await page.getByRole('heading', { name: 'Review this mandate' }).waitFor({ timeout: 20_000 });
    await page.getByRole('button', { name: 'Approve with passkey' }).click();
    await page.getByRole('heading', { name: 'Mandate approved' }).waitFor({ timeout: 30_000 });
    log('[drive] approval: passkey ceremony complete, "Mandate approved".');
    await Promise.all([
      page.waitForURL((url) => url.pathname === '/approved', { timeout: 15_000 }),
      page.getByRole('button', { name: /^Return to / }).click(),
    ]);
    log('[drive] approval: returned to the harness listener.');
  } finally {
    await context.close().catch(() => {});
  }
}

async function dumpStructure(page, log) {
  for (const frame of page.frames()) {
    try {
      const info = await frame.evaluate(() => ({
        buttons: Array.from(document.querySelectorAll('button')).map((el) => ({
          text: (el.textContent || '').trim().slice(0, 60),
          disabled: el.disabled,
        })),
        radios: Array.from(document.querySelectorAll('input[type=radio]')).map((el) => el.value),
      }));
      log(`[drive]   frame ${frame.url().slice(0, 90)} buttons=${JSON.stringify(info.buttons)} radios=${JSON.stringify(info.radios)}`);
    } catch {
      // Cross-origin frames that cannot evaluate are skipped.
    }
  }
}

// The test-mode status screen (four labels: Open/Paid/Failed/Expired +
// Continue) is shared by both methods. The radios are wrapped in labels that
// swallow check()/coordinate clicks, so select by label text and gate on the
// input state; a Continue without a selected status leaves the payment open.
async function selectStatus(page, outcome, log) {
  const radio = page.locator(`input[type=radio][value=${outcome}]`).first();
  try {
    await radio.waitFor({ state: 'attached', timeout: 20_000 });
  } catch (error) {
    await dumpStructure(page, log);
    throw error;
  }
  const labelText = outcome.charAt(0).toUpperCase() + outcome.slice(1);
  for (let attempt = 0; attempt < 3 && !(await radio.isChecked()); attempt += 1) {
    await page.getByText(labelText, { exact: true }).first().click({ timeout: 10_000 }).catch(() => {});
    if (!(await radio.isChecked())) await page.waitForTimeout(500);
  }
  if (!(await radio.isChecked())) {
    await dumpStructure(page, log);
    throw new Error(`could not select ${outcome} on the status screen`);
  }
  await page.locator('button', { hasText: /continue/i }).first().click({ timeout: 15_000 });
  log(`[drive] checkout: selected ${outcome} + Continue.`);
  await page.waitForTimeout(2_500);
}

async function driveCheckoutPaid(browser, paymentURL, log) {
  log(`[drive] checkout (paid, iDEAL): ${paymentURL.slice(0, 96)}`);
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(paymentURL, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await page.locator('button', { hasText: /iDEAL/i }).first().click({ timeout: 15_000 });
    await page.waitForTimeout(1_500);
    const issuer = page.locator('button', { hasText: /^ING$/ }).first();
    if (await issuer.count()) {
      await issuer.click();
    } else {
      const buttons = page.locator('button');
      const total = await buttons.count();
      for (let index = 0; index < total; index += 1) {
        const label = ((await buttons.nth(index).textContent()) ?? '').trim();
        if (label !== '' && !label.startsWith('‹')) {
          await buttons.nth(index).click();
          break;
        }
      }
    }
    await page.waitForTimeout(1_500);
    await selectStatus(page, 'paid', log);
  } finally {
    await context.close().catch(() => {});
  }
}

async function driveCheckoutFailed(browser, paymentURL, log) {
  log(`[drive] checkout (failed, card + magic amount): ${paymentURL.slice(0, 96)}`);
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(paymentURL, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    let cardFrame;
    for (let attempt = 0; attempt < 20 && cardFrame === undefined; attempt += 1) {
      cardFrame = page.frames().find((frame) => frame.url().includes('/components/card/'));
      if (cardFrame === undefined) await page.waitForTimeout(500);
    }
    if (cardFrame === undefined) {
      await dumpStructure(page, log);
      throw new Error('card component frame not found');
    }
    const fill = async (selector, value) => {
      const field = cardFrame.locator(selector).first();
      await field.waitFor({ timeout: 15_000 });
      await field.click();
      await field.pressSequentially(value, { delay: 40 });
    };
    await fill('#cardNumber', '4111111111111111');
    await fill('#cardExpiryDate', '1230');
    await fill('#cardCvv', '123');
    await fill('#cardHolder', 'Douwe Kramer');
    await cardFrame.locator('button', { hasText: /pay with card/i }).first().click({ timeout: 15_000 });
    log('[drive] checkout: card submitted.');
    await selectStatus(page, 'failed', log);
  } finally {
    await context.close().catch(() => {});
  }
}

// -- harness driver ----------------------------------------------------------

function runOnce({ headed, logPath, browser }) {
  return new Promise((resolveRun) => {
    const harness = spawn(process.execPath, [HARNESS], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const log = (line) => {
      process.stdout.write(line + '\n');
      appendFileSync(logPath, line + '\n');
    };
    let tail = '';
    let chain = Promise.resolve();
    let driveFailure = null;
    let closed = false;
    let currentPhase = 0;

    const onLine = (line) => {
      if (line.startsWith('APPROVAL_URL=')) {
        const url = line.slice('APPROVAL_URL='.length).trim();
        chain = chain.then(() => driveApproval(browser, url, log));
      } else if (line.startsWith('PAYMENT_URL=')) {
        const url = line.slice('PAYMENT_URL='.length).trim();
        const paid = currentPhase === 1;
        chain = chain.then(() =>
          paid ? driveCheckoutPaid(browser, url, log) : driveCheckoutFailed(browser, url, log),
        );
      } else if (/^=== Phase \d:/.test(line)) {
        currentPhase = Number(line.match(/^=== Phase (\d):/)[1]);
      }
    };

    const consume = (chunk, isError) => {
      tail += chunk.toString();
      const lines = tail.split('\n');
      tail = lines.pop() ?? '';
      for (const line of lines) {
        if (isError) {
          log('[harness:stderr] ' + line);
        } else {
          log(line);
          onLine(line);
        }
      }
    };
    harness.stdout.on('data', (chunk) => consume(chunk, false));
    harness.stderr.on('data', (chunk) => consume(chunk, true));

    chain.catch((error) => {
      driveFailure = error;
      log(`[drive] FAILED: ${error.message}`);
      harness.kill('SIGTERM');
    });

    harness.on('close', (code) => {
      if (closed) return;
      closed = true;
      chain.finally(() => {
        if (tail !== '') log(tail);
        resolveRun({ code: code ?? 1, driveFailure });
      });
    });
  });
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const browser = await chromium.launch({ headless: !options.headed });
  const results = [];
  try {
    for (let run = 1; run <= options.runs; run += 1) {
      const logPath = resolve(process.cwd(), `autodrive-run-${stamp()}.log`);
      process.stdout.write(`\n===== autodrive run ${run}/${options.runs} (log: ${logPath}) =====\n`);
      const result = await runOnce({ headed: options.headed, logPath, browser });
      let summary = null;
      try {
        summary = JSON.parse(readFileSync(resolve(process.cwd(), 'mollie-run-summary.json'), 'utf8'));
        writeFileSync(resolve(process.cwd(), `mollie-run-summary-${summary.runID}.json`), JSON.stringify(summary, null, 2) + '\n');
      } catch {
        // The first run writes the summary; a missing file means the run died early.
      }
      results.push({ run, code: result.code, runID: summary?.runID ?? null, driveFailure: result.driveFailure?.message ?? null });
      process.stdout.write(`autodrive run ${run}: exit=${result.code} runID=${summary?.runID ?? 'none'}\n`);
      if (result.code !== 0) break;
    }
  } finally {
    await browser.close();
  }
  process.stdout.write('\n===== autodrive results =====\n' + JSON.stringify(results, null, 2) + '\n');
  if (results.some((entry) => entry.code !== 0)) process.exitCode = 1;
}

await main();
