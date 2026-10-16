#!/usr/bin/env node
// Canonical copy: attesso repository, scripts/mollie-e2e.mjs.
// Attesso x Mollie rehearsal harness. Plays the INTEGRATOR for one full loop:
// create a test Mandate, approve it with a passkey, one over-cap DENY, one
// in-cap ALLOW, create a Mollie test payment bound to the ALLOW, settle on
// Mollie's finality (webhook triggered fetch when a public URL is given,
// otherwise polling), then either commit (paid) or cancel (failed), and
// verify the signed evidence locally. A second phase proves the cancel path
// on a failed payment.
//
// Rehearsal tooling, not a product: Attesso never calls executor APIs. This
// script exists to prove the wiring against Mollie's test mode end to end.
// Adapted from docs/public-v1/examples/quickstart.mjs (same state file, same
// one-crypto-step identity assertion, no dependencies, Node.js 20+).
//
// Mollie notes:
//   - The API key must be a test key (`test_...`); refusals otherwise.
//   - `webhookUrl` is validated for reachability at payment creation: a
//     loopback URL is rejected (observed 422); pass a public URL via
//     MOLLIE_WEBHOOK_URL (a tunnel in local development). Without it the
//     harness omits webhookUrl and settles by polling.
//   - Mollie posts only `id=<tr_...>` to the webhook; the receiver fetches
//     the payment and decides. Respond 200 immediately, then process.
//
//   - Phase 2's failure route is card-only: pin `method: creditcard` at
//     creation and use a documented magic amount (EUR 1007.00 ->
//     insufficient_funds), then select Failed on the test-mode status
//     screen. A payment created without a fixed method bounced non-paid
//     selections back to method selection and stayed open (observed
//     2026-10-15).
//
// Usage:
//   MOLLIE_API_KEY=test_... node scripts/mollie-e2e.mjs [--port N] [--help]
//   MOLLIE_API_KEY=test_... MOLLIE_WEBHOOK_URL=https://.../mollie-webhook \
//     node scripts/mollie-e2e.mjs
// Run from a directory holding attesso-quickstart.json (create it with
// quickstart.mjs first: it carries the test API key, the registered identity
// key, and the return port).

import { spawn } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { resolve } from 'node:path';

const ATTESSO_API_ORIGIN = 'https://api-staging.attesso.com';
const MOLLIE_API_ORIGIN = 'https://api.mollie.com/v2';
const TEST_AUDIENCE = 'urn:attesso:approval:test:v1';
const ASSERTION_LIFETIME_SECONDS = 300;
const SUBJECT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const STATE_FILE = 'attesso-quickstart.json';
const DEFAULT_PORT = 43117;
const IDENTITY_KID = 'quickstart-1';
const IDENTITY_ISSUER = 'https://quickstart.local';

const MANDATE_ACTION = 'purchase.execute';
const PHASE_ONE_MANDATE_MAX_AMOUNT = 25000; // minor units: EUR 250.00
const PHASE_TWO_MANDATE_MAX_AMOUNT = 150000; // minor units: EUR 1500.00, clears the card failure-test amount
const DEMO_DENY_AMOUNT = 32000; // minor units: EUR 320.00, deliberately above the cap
const PHASE_ONE_ALLOW_AMOUNT = 18900; // minor units: EUR 189.00, within the cap
// Documented card failure-test amount: EUR 1007.00 -> insufficient_funds.
const PHASE_TWO_ALLOW_AMOUNT = 100700;
const EXECUTION_WINDOW_SECONDS = 900; // the rehearsal drives a hosted checkout in between
const POLL_INTERVAL_MS = 2000;
const MANDATE_WAIT_MS = 10 * 60 * 1000;
const PAYMENT_WAIT_MS = 15 * 60 * 1000;
const WEBHOOK_GRACE_MS = 30 * 1000; // after final status, wait this long for a webhook receipt
const RETURN_GRACE_MS = 5 * 1000;

const USAGE = `Attesso x Mollie rehearsal harness (rehearsal tooling, not a product).

Usage:
  MOLLIE_API_KEY=test_... node scripts/mollie-e2e.mjs [--port N]
  MOLLIE_API_KEY=test_... MOLLIE_WEBHOOK_URL=https://<public>/mollie-webhook node scripts/mollie-e2e.mjs

What it runs (test plane only; activity is free):
  Phase 1: Mandate create -> passkey approval -> over-cap DENY -> in-cap
  ALLOW -> Mollie test payment (paid) -> commit -> evidence verified.
  Phase 2: same loop; the payment is pinned to card with the documented
  magic amount (EUR 1007.00) and driven to failed on the status screen ->
  cancel -> evidence verified.
  Every Mandate and Authorization create is replayed under the same
  idempotency key first; the replay must return the same resource.

Environment:
  MOLLIE_API_KEY       required; Mollie test-mode API key (test_...).
  MOLLIE_WEBHOOK_URL   optional; publicly reachable URL Mollie posts to.
                       Without it, finality settles by polling.

Run from a directory holding ${STATE_FILE} (create it via quickstart.mjs).`;

// The loopback server while it is still listening; the entry point finally
// closes it so a mid-flow failure can never keep the process alive.
let activeServer = null;

// Set in runMollie; never logged, never written to disk.
let MOLLIE_KEY = '';

// Timestamped forensic log; every observed request/response lands in the run log.
function trace(tag, message) {
  process.stdout.write(`  [${tag}] ${new Date().toISOString()} ${message}\n`);
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function jsonSegment(value) {
  return base64url(JSON.stringify(value));
}

function generateIdentityKey({ kid, issuer }) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  privateJwk.kid = kid;
  privateJwk.iss = issuer;
  return { privateJwk, publicJwk: publicIdentityJwk(privateJwk) };
}

function publicIdentityJwk(privateJwk) {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: privateJwk.x,
    y: privateJwk.y,
    use: 'sig',
    alg: 'ES256',
    kid: privateJwk.kid,
  };
}

function signIdentityAssertion(privateJwk, subject, audience) {
  if (audience !== TEST_AUDIENCE) {
    throw new Error('this harness signs for the test audience only');
  }
  if (typeof subject !== 'string' || !SUBJECT_PATTERN.test(subject)) {
    throw new Error('subject_reference must match ' + SUBJECT_PATTERN + ': ' + subject);
  }
  if (!privateJwk.d || !privateJwk.kid || !privateJwk.iss) {
    throw new Error('identity key must carry d, kid and iss');
  }
  const now = Math.floor(Date.now() / 1000);
  const protectedHeader = { typ: 'attesso-identity+jwt', alg: 'ES256', kid: privateJwk.kid };
  const claims = {
    iss: privateJwk.iss,
    sub: subject,
    aud: audience,
    iat: now,
    exp: now + ASSERTION_LIFETIME_SECONDS,
    jti: randomUUID(),
  };
  const signingInput = jsonSegment(protectedHeader) + '.' + jsonSegment(claims);
  const signature = sign('sha256', Buffer.from(signingInput, 'utf8'), {
    key: createPrivateKey({ key: privateJwk, format: 'jwk' }),
    dsaEncoding: 'ieee-p1363',
  });
  return { assertion: signingInput + '.' + base64url(signature) };
}

// -- terminal input ----------------------------------------------------------

const stdinState = { buffer: '', lines: [], waiters: [], raw: false, started: false };
let swallowNewline = false;

function deliverLine(line) {
  const waiter = stdinState.waiters.shift();
  if (waiter) {
    waiter(line);
    return;
  }
  stdinState.lines.push(line);
}

function feedStdin(text) {
  for (const character of text) {
    if (stdinState.raw && character === '\u0003') {
      process.exit(130);
    }
    if (stdinState.raw && (character === '\u007f' || character === '\b')) {
      stdinState.buffer = stdinState.buffer.slice(0, -1);
      continue;
    }
    if (character === '\r') {
      const line = stdinState.buffer;
      stdinState.buffer = '';
      swallowNewline = true;
      deliverLine(line);
      continue;
    }
    if (character === '\n') {
      if (swallowNewline) {
        swallowNewline = false;
        continue;
      }
      const line = stdinState.buffer;
      stdinState.buffer = '';
      deliverLine(line);
      continue;
    }
    stdinState.buffer += character;
  }
}

function startStdin() {
  if (stdinState.started) {
    return;
  }
  stdinState.started = true;
  if (process.stdin.isTTY === true) {
    process.stdin.setRawMode(true);
    stdinState.raw = true;
  }
  process.stdin.resume();
  process.stdin.on('data', (chunk) => feedStdin(chunk.toString('utf8')));
  process.stdin.on('end', () => {
    while (stdinState.waiters.length > 0) {
      stdinState.waiters.shift()(null);
    }
  });
  process.stdin.on('error', () => {});
}

function stopStdin() {
  if (!stdinState.started) {
    return;
  }
  if (stdinState.raw) {
    try {
      process.stdin.setRawMode(false);
    } catch {
      // The terminal is gone; nothing to restore.
    }
  }
  process.stdin.pause();
  process.stdin.destroy();
}

function nextLine() {
  if (stdinState.lines.length > 0) {
    return Promise.resolve(stdinState.lines.shift());
  }
  return new Promise((resolveLine) => stdinState.waiters.push(resolveLine));
}

async function promptForLine(prompt) {
  process.stdout.write(prompt);
  startStdin();
  const line = await nextLine();
  if (stdinState.raw) {
    process.stdout.write('\n');
  }
  return line;
}

// -- local state -------------------------------------------------------------

function statePath() {
  return resolve(process.cwd(), STATE_FILE);
}

function loadState() {
  const path = statePath();
  if (!existsSync(path)) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`could not read ${STATE_FILE}; delete it and run quickstart.mjs again`);
  }
  if (!parsed.identity || !parsed.identity.d || !parsed.identity.kid || !parsed.identity.iss) {
    throw new Error(`${STATE_FILE} is missing the identity key; delete it and run quickstart.mjs again`);
  }
  return parsed;
}

async function loadStateOrPrompt() {
  const existing = loadState();
  if (existing) {
    return existing;
  }
  const environmentKey =
    typeof process.env.ATTESSO_API_KEY === 'string' ? process.env.ATTESSO_API_KEY.trim() : '';
  const apiKey =
    environmentKey !== ''
      ? environmentKey
      : ((await promptForLine('Paste your att_test_ API key (Dashboard -> Test): ')) ?? '');
  if (!apiKey.startsWith('att_test_')) {
    throw new Error('that is not an att_test_ key; this harness runs on the test plane only');
  }
  const { privateJwk } = generateIdentityKey({ kid: IDENTITY_KID, issuer: IDENTITY_ISSUER });
  const state = { apiKey, port: DEFAULT_PORT, identity: privateJwk };
  const path = statePath();
  writeFileSync(path, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
  chmodSync(path, 0o600);
  process.stdout.write(`Created ${STATE_FILE} (test key + identity key, chmod 600).\n`);
  return state;
}

// -- Attesso API -------------------------------------------------------------

function returnOrigin(state) {
  return `http://127.0.0.1:${state.port}`;
}

async function apiRequest(state, { method, path, idempotencyKey, body }) {
  let response;
  try {
    response = await fetch(new URL(path, ATTESSO_API_ORIGIN + '/'), {
      method,
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${state.apiKey}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(idempotencyKey === undefined ? {} : { 'Idempotency-Key': idempotencyKey }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    const cause = error && error.cause && error.cause.message ? error.cause.message : error.message;
    throw new Error(`could not reach ${ATTESSO_API_ORIGIN} (${cause})`);
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    // Keep payload null; status still describes the failure.
  }
  if (body !== undefined) {
    trace('attesso', `${method} ${path} request: ${JSON.stringify(body)}`);
  }
  trace('attesso', `${method} ${path} -> HTTP ${response.status}`);
  if (payload !== null) {
    trace('attesso', `${method} ${path} response: ${JSON.stringify(payload)}`);
  }
  return { status: response.status, payload };
}

function describeFailure(result) {
  const code = result.payload && typeof result.payload.code === 'string' ? result.payload.code : '';
  return code === '' ? `HTTP ${result.status}` : `${code}`;
}

function euroAmount(minorUnits) {
  return 'EUR ' + (minorUnits / 100).toFixed(2);
}

function mollieValue(minorUnits) {
  return (minorUnits / 100).toFixed(2);
}

function sleep(milliseconds) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds));
}

// -- the combined loopback server: approval return + Mollie webhook ----------

// One server serves both legs: GET /approved is the registered approval
// return origin; POST /mollie-webhook is what Mollie calls when a payment
// changes state. Webhook receipts are recorded (id + timestamp) and the
// settle loop reads them as delivery evidence.
function startServer(state) {
  return new Promise((resolveListen, rejectListen) => {
    const control = { resolveApproved: null, webhookReceipts: [] };
    control.approvedPromise = new Promise((resolveReturn) => {
      control.resolveApproved = resolveReturn;
    });
    const server = createServer((request, response) => {
      const url = new URL(request.url, returnOrigin(state));
      if (request.method === 'GET' && url.pathname === '/approved') {
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        response.end(
          '<!doctype html><meta charset="utf-8"><title>Attesso Mollie rehearsal</title>' +
            '<p>Approval received. Return to the terminal; it continues on its own.</p>',
        );
        control.resolveApproved({ state: url.searchParams.get('state') });
        return;
      }
      if (request.method === 'POST' && url.pathname === '/mollie-webhook') {
        let body = '';
        request.on('data', (chunk) => {
          body += chunk;
          if (body.length > 4096) {
            request.destroy();
          }
        });
        request.on('end', () => {
          // Mollie's rule: respond 200 immediately, then process.
          response.writeHead(200, { 'Content-Type': 'text/plain' });
          response.end('OK');
          const id = new URLSearchParams(body).get('id') || '';
          const receipt = { id, at: new Date().toISOString() };
          control.webhookReceipts.push(receipt);
          process.stdout.write(`  [mollie-webhook] Mollie delivered id=${id} at ${receipt.at}\n`);
          trace('webhook', `raw body=${JSON.stringify(body)} content-type=${request.headers['content-type'] ?? ''}`);
        });
        return;
      }
      response.writeHead(404, { 'Content-Type': 'text/plain' });
      response.end('Not found');
    });
    server.on('error', rejectListen);
    server.listen(state.port, '127.0.0.1', () => resolveListen({ server, control }));
  });
}

function openInBrowser(url, env) {
  const command =
    process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try {
    spawn(command, args, { detached: true, stdio: 'ignore', env }).unref();
  } catch {
    // The printed URL remains the way in.
  }
}

// -- approval flow -----------------------------------------------------------

async function waitForMandateActive(state, mandateID) {
  const deadline = Date.now() + MANDATE_WAIT_MS;
  let lastName = '';
  for (;;) {
    const result = await apiRequest(state, { method: 'GET', path: `/v1/mandates/${mandateID}` });
    if (result.status !== 200 || typeof result.payload?.state !== 'string') {
      throw new Error(`mandate read failed: ${describeFailure(result)}`);
    }
    if (result.payload.state !== lastName) {
      lastName = result.payload.state;
      process.stdout.write(`  Mandate state: ${lastName}\n`);
    }
    if (lastName === 'ACTIVE') {
      return result.payload;
    }
    if (lastName !== 'PENDING_APPROVAL' && lastName !== 'SCHEDULED') {
      throw new Error(`the Mandate ended as ${lastName}`);
    }
    if (Date.now() > deadline) {
      throw new Error('timed out waiting for the approval');
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

// Same provisioning body the quickstart uses; the rig workspace already has
// trust registered, so this only fires on a fresh workspace.
function approvalTrustBody(identity, origin) {
  return {
    identity_issuer: identity.iss,
    approval_return_origin: origin,
    identity_public_jwks: [publicIdentityJwk(identity)],
  };
}

async function provisionTestTrust(state) {
  const result = await apiRequest(state, {
    method: 'PUT',
    path: '/v1/approval-trust',
    body: approvalTrustBody(state.identity, returnOrigin(state)),
  });
  if (result.status === 200) {
    process.stdout.write('\nTest approval trust provisioned for this workspace.\n');
    return true;
  }
  if (result.status === 409 && result.payload?.code === 'APPROVAL_TRUST_ALREADY_REGISTERED') {
    process.stdout.write('\nThis workspace already has different approval trust registered.\n');
    return false;
  }
  throw new Error(`provisioning test approval trust failed: ${describeFailure(result)}`);
}

// Creates the Mandate, opens the hosted approval page, and waits for ACTIVE
// through the server-side read (the redirect is never the proof).
// The `open` PATH shim in the rig records the approval URL.
async function createAndApproveMandate(state, { runID, subject, externalReference, maxAmount, openEnv }) {
  const idempotencyKey = `mollie.${runID}.mandate.create`;
  const body = {
    subject_reference: subject,
    external_reference: externalReference,
    policy: {
      version: '1',
      action: MANDATE_ACTION,
      constraints: [
        { path: 'payment.currency', operator: 'eq', value: 'EUR' },
        { path: 'payment.amount', operator: 'max', value: maxAmount },
      ],
    },
    approval_deadline: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    valid_from: new Date(Date.now() - 60 * 1000).toISOString(),
    valid_until: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
  };
  const mandate = await apiRequest(state, { method: 'POST', path: '/v1/mandates', idempotencyKey, body });
  if (mandate.status !== 201 || typeof mandate.payload?.id !== 'string') {
    throw new Error(`mandate creation failed: ${describeFailure(mandate)}`);
  }
  const mandateID = mandate.payload.id;
  // Idempotency contract: the identical create replayed under the same key
  // returns the same Mandate, not a second one.
  const replay = await apiRequest(state, { method: 'POST', path: '/v1/mandates', idempotencyKey, body });
  if ((replay.status !== 200 && replay.status !== 201) || replay.payload?.id !== mandateID) {
    throw new Error(`the mandate create replay broke idempotency: ${describeFailure(replay)}`);
  }
  trace('idempotency', `mandate create replayed: same id ${mandateID}, HTTP ${replay.status}.`);
  process.stdout.write(
    `\nMandate created: ${MANDATE_ACTION}, cap ${euroAmount(maxAmount)} (${mandateID}, PENDING_APPROVAL).\n`,
  );

  for (let attempt = 1; ; attempt += 1) {
    const { assertion } = signIdentityAssertion(state.identity, subject, TEST_AUDIENCE);
    const session = await apiRequest(state, {
      method: 'POST',
      path: `/v1/mandates/${mandateID}/approval-sessions`,
      idempotencyKey: `mollie.${runID}.approval.create.${attempt}`,
      body: {
        identity_assertion: assertion,
        return_url: `${returnOrigin(state)}/approved`,
        return_state: `mollie_${runID}`,
      },
    });
    if (session.status === 201 || session.status === 200) {
      const approvalURL = session.payload?.approval_url;
      if (typeof approvalURL !== 'string' || approvalURL === '') {
        throw new Error('the approval session did not include an approval_url');
      }
      process.stdout.write(`\nApproval session: OPEN (${session.payload.id}).\n`);
      process.stdout.write(`\nAPPROVAL_URL=${approvalURL}\n`);
      openInBrowser(approvalURL, openEnv);
      await waitForMandateActive(state, mandateID);
      process.stdout.write('Mandate is ACTIVE. (The redirect is not proof; this server-side read is.)\n');
      return mandateID;
    }
    if (session.payload?.code === 'APPROVAL_NOT_CONFIGURED' && attempt === 1) {
      if (await provisionTestTrust(state)) {
        continue;
      }
    }
    throw new Error(`the approval session was rejected: ${describeFailure(session)}`);
  }
}

// -- authorizations ----------------------------------------------------------

const COMMITMENT_DOMAIN = 'attesso:authorization:commitment:v1\n';

function deriveCommitment(opening) {
  return (
    'sha256:' +
    createHash('sha256')
      .update(Buffer.concat([Buffer.from(COMMITMENT_DOMAIN), Buffer.from(opening, 'hex')]))
      .digest('hex')
  );
}

function newCommitmentPair() {
  const opening = randomBytes(32).toString('hex');
  return { opening, commitment: deriveCommitment(opening) };
}

async function createAuthorization(state, mandateID, runID, label, amount) {
  const pair = newCommitmentPair();
  const idempotencyKey = `mollie.${runID}.authorization.${label}`;
  const body = {
    external_reference: `candidate_${label}_${runID}`,
    proposed_action: {
      action: MANDATE_ACTION,
      attributes: {},
      payment: { amount, currency: 'EUR' },
    },
    execution_window_seconds: EXECUTION_WINDOW_SECONDS,
    commitment: pair.commitment,
  };
  const result = await apiRequest(state, {
    method: 'POST',
    path: `/v1/mandates/${mandateID}/authorizations`,
    idempotencyKey,
    body,
  });
  // Idempotency contract: the identical authorization replayed under the same
  // key returns the same decision and never double-reserves.
  const replay = await apiRequest(state, {
    method: 'POST',
    path: `/v1/mandates/${mandateID}/authorizations`,
    idempotencyKey,
    body,
  });
  if ((replay.status !== 200 && replay.status !== 201) || replay.payload?.id !== result.payload?.id) {
    throw new Error(`the authorization replay broke idempotency: ${describeFailure(replay)}`);
  }
  trace('idempotency', `authorization ${label} replayed: same id ${result.payload?.id}, HTTP ${replay.status}.`);
  return { result, opening: pair.opening };
}

// -- Mollie ------------------------------------------------------------------

async function mollieRequest({ method, path, body, idempotencyKey }) {
  let response;
  try {
    response = await fetch(new URL(path, MOLLIE_API_ORIGIN + '/'), {
      method,
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${MOLLIE_KEY}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(idempotencyKey === undefined ? {} : { 'Idempotency-Key': idempotencyKey }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new Error(`could not reach Mollie (${error.message})`);
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    // Keep payload null; status still describes the failure.
  }
  if (body !== undefined) {
    trace('mollie', `${method} ${path} request: ${JSON.stringify(body)}`);
  }
  trace('mollie', `${method} ${path} -> HTTP ${response.status}`);
  if (payload !== null) {
    trace('mollie', `${method} ${path} response: ${JSON.stringify(payload)}`);
  }
  return { status: response.status, payload };
}

const FINAL_PAYMENT_STATES = new Set(['paid', 'authorized', 'failed', 'expired', 'canceled']);

// Settles on Mollie finality. Polling always runs (a webhook-augmented poll in
// the real-world sense: whichever signal lands first, the status fetch
// decides). Webhook receipts are logged as delivery evidence; without a
// public webhook URL this is a plain poll.
async function settlePayment(paymentID, control, webhookEnabled) {
  const deadline = Date.now() + PAYMENT_WAIT_MS;
  let lastName = '';
  let lastStatus = '';
  for (;;) {
    const result = await mollieRequest({ method: 'GET', path: `payments/${paymentID}` });
    if (result.status !== 200) {
      throw new Error(`payment read failed: HTTP ${result.status}`);
    }
    lastStatus = result.payload.status;
    if (lastStatus !== lastName) {
      lastName = lastStatus;
      process.stdout.write(`  Payment status: ${lastStatus}\n`);
    }
    trace(
      'poll',
      `${paymentID} status=${lastStatus} isCancelable=${result.payload.isCancelable ?? ''} expiresAt=${result.payload.expiresAt ?? ''}`,
    );
    if (FINAL_PAYMENT_STATES.has(lastStatus)) {
      break;
    }
    if (Date.now() > deadline) {
      throw new Error('timed out waiting for the Mollie payment to reach a final status');
    }
    await sleep(POLL_INTERVAL_MS);
  }

  const finalRead = await mollieRequest({ method: 'GET', path: `payments/${paymentID}` });
  trace(
    'settle',
    `${paymentID} final: ${JSON.stringify({
      status: finalRead.payload?.status ?? null,
      failureReason: finalRead.payload?.details?.failureReason ?? null,
      failedAt: finalRead.payload?.failedAt ?? null,
      canceledAt: finalRead.payload?.canceledAt ?? null,
      expiresAt: finalRead.payload?.expiresAt ?? null,
    })}`,
  );

  let webhookDelivered = control.webhookReceipts.some((receipt) => receipt.id === paymentID);
  if (webhookEnabled && !webhookDelivered) {
    // Mollie's delivery is near-instant on change; a short grace separates
    // "arrives a beat late" from "never arrived".
    const graceDeadline = Date.now() + WEBHOOK_GRACE_MS;
    while (Date.now() < graceDeadline && !webhookDelivered) {
      await sleep(1000);
      webhookDelivered = control.webhookReceipts.some((receipt) => receipt.id === paymentID);
    }
  }
  if (!webhookEnabled) {
    process.stdout.write('  Webhook delivery disabled (MOLLIE_WEBHOOK_URL unset); settled via polling.\n');
  } else if (webhookDelivered) {
    process.stdout.write(`  Mollie webhook delivery confirmed for ${paymentID}.\n`);
  } else {
    process.stdout.write('  No Mollie webhook receipt within the grace window; settled via polling. Check the tunnel.\n');
  }
  return { status: lastStatus, webhookDelivered };
}

// -- evidence ----------------------------------------------------------------

async function verifyEvidence(state, mandateID) {
  const result = await apiRequest(state, { method: 'GET', path: `/v1/mandates/${mandateID}/evidence` });
  if (result.status !== 200) {
    throw new Error(`evidence fetch failed: ${describeFailure(result)}`);
  }
  const envelope = result.payload;
  if (
    envelope?.format !== 'attesso.evidence.v1' ||
    typeof envelope.protected !== 'string' ||
    typeof envelope.payload !== 'string' ||
    typeof envelope.signature !== 'string'
  ) {
    throw new Error('the evidence envelope is not in the documented shape');
  }
  let keyID = '';
  try {
    keyID = JSON.parse(Buffer.from(envelope.protected, 'base64url').toString('utf8')).kid;
  } catch {
    // The explicit check below reports the miss.
  }
  if (typeof keyID !== 'string' || keyID === '') {
    throw new Error('the evidence header carries no key id');
  }
  let keySet;
  try {
    const response = await fetch(new URL('/.well-known/jwks.json', ATTESSO_API_ORIGIN));
    keySet = await response.json();
  } catch (error) {
    throw new Error(`could not fetch the public verification keys: ${error.message}`);
  }
  const jwk = Array.isArray(keySet?.keys) ? keySet.keys.find((key) => key?.kid === keyID) : undefined;
  if (!jwk) {
    throw new Error(`no published key matches the evidence key id ${keyID}`);
  }
  const signatureOkay = verify(
    'sha256',
    Buffer.from(envelope.protected + '.' + envelope.payload, 'utf8'),
    { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    Buffer.from(envelope.signature, 'base64url'),
  );
  if (!signatureOkay) {
    throw new Error('the evidence signature did not verify against the published key');
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8'));
  } catch {
    throw new Error('the verified evidence payload is not JSON');
  }
  if (!Array.isArray(payload?.events)) {
    throw new Error('the verified evidence payload carries no events');
  }
  return { keyID, envelope, payload };
}

function saveEvidence(mandateID, envelope) {
  const path = resolve(process.cwd(), `mollie-evidence-${mandateID}.json`);
  writeFileSync(path, JSON.stringify(envelope, null, 2) + '\n');
  return path;
}

// -- phases ------------------------------------------------------------------

// One full loop for one Mandate. `expectation` decides the terminal branch:
// 'commit' requires the payment to end paid/authorized; 'cancel' requires a
// failed/expired/canceled payment and reports definite non-acceptance.
async function runPhase(state, control, { runID, phase, allowAmount, expectation, webhookURL, openEnv }) {
  const label = `p${phase}`;
  const subject = `mollie_${runID}_${label}`;
  process.stdout.write(`\n=== Phase ${phase}: ${expectation} path ===\n`);

  const maxAmount = phase === 1 ? PHASE_ONE_MANDATE_MAX_AMOUNT : PHASE_TWO_MANDATE_MAX_AMOUNT;
  const mandateID = await createAndApproveMandate(state, {
    runID: `${runID}.${label}`,
    subject,
    externalReference: `mollie_${runID}_${label}`,
    maxAmount,
    openEnv,
  });

  if (phase === 1) {
    const { result: denied } = await createAuthorization(state, mandateID, `${runID}.${label}`, 'deny', DEMO_DENY_AMOUNT);
    if (denied.status !== 201 || denied.payload?.decision !== 'DENY' || denied.payload?.can_execute !== false) {
      throw new Error(`over-cap probe expected DENY, got ${denied.payload?.decision}/${describeFailure(denied)}`);
    }
    process.stdout.write(`Over the cap (${euroAmount(DEMO_DENY_AMOUNT)}): DENY. Nothing was reserved.\n`);
  }

  const { result: allowed, opening } = await createAuthorization(state, mandateID, `${runID}.${label}`, 'allow', allowAmount);
  if (allowed.status !== 201 || allowed.payload?.decision !== 'ALLOW' || allowed.payload?.can_execute !== true) {
    throw new Error(`expected ALLOW, got ${allowed.payload?.decision}/${describeFailure(allowed)}`);
  }
  const authorizationID = allowed.payload.id;
  process.stdout.write(
    `Within the cap (${euroAmount(allowAmount)}): ALLOW, execute before ${allowed.payload.execute_before}.\n`,
  );

  // Execute on Mollie: the request is derived from the same immutable
  // proposed action; the idempotency key is our external_action_reference.
  const externalActionReference = `mollie_${runID}-${label}`;
  const payment = await mollieRequest({
    method: 'POST',
    path: 'payments',
    idempotencyKey: externalActionReference,
    body: {
      amount: { currency: 'EUR', value: mollieValue(allowAmount) },
      description: `Attesso Mollie rehearsal ${label} ${runID.slice(0, 8)}`,
      redirectUrl: `${returnOrigin(state)}/approved`,
      // The documented failure route is card-only; pinning the method lets
      // the test-mode status screen force a failed payment with a magic amount.
      ...(phase === 2 ? { method: 'creditcard' } : {}),
      ...(webhookURL === null ? {} : { webhookUrl: webhookURL }),
      metadata: {
        attesso_mandate_id: mandateID,
        attesso_authorization_id: authorizationID,
        attesso_external_reference: externalActionReference,
      },
    },
  });
  if (payment.status !== 201 || typeof payment.payload?.id !== 'string') {
    const detail =
      payment.payload?.field === 'webhookUrl'
        ? ' (webhookUrl was rejected as unreachable; set MOLLIE_WEBHOOK_URL to a public URL or unset it)'
        : '';
    throw new Error(`Mollie payment creation failed: HTTP ${payment.status}${detail}`);
  }
  const paymentID = payment.payload.id;
  process.stdout.write(`Mollie payment created: ${paymentID} (status ${payment.payload.status}).\n`);
  process.stdout.write(`PAYMENT_URL=${payment.payload._links?.checkout?.href ?? ''}\n`);

  const settled = await settlePayment(paymentID, control, webhookURL !== null);

  if (expectation === 'commit') {
    if (settled.status !== 'paid' && settled.status !== 'authorized') {
      throw new Error(`expected the payment to be paid/authorized, it is ${settled.status}`);
    }
    const committed = await apiRequest(state, {
      method: 'PUT',
      path: `/v1/authorizations/${authorizationID}/commit`,
      idempotencyKey: `mollie.${runID}.${label}.commit`,
      body: {
        external_action_reference: externalActionReference,
        opening,
        provider_transaction_reference: paymentID,
        reported_accepted_at: new Date().toISOString(),
      },
    });
    if (committed.status !== 200 || committed.payload?.state !== 'COMMITTED') {
      throw new Error(`commit failed: ${describeFailure(committed)}`);
    }
    process.stdout.write(`Mollie accepted (${paymentID}): authorization COMMITTED.\n`);
  } else {
    if (!['failed', 'expired', 'canceled'].includes(settled.status)) {
      throw new Error(`expected the payment to fail, it is ${settled.status}`);
    }
    const cancelled = await apiRequest(state, {
      method: 'PUT',
      path: `/v1/authorizations/${authorizationID}/cancellation`,
      idempotencyKey: `mollie.${runID}.${label}.cancel`,
      body: {
        reason: 'EXECUTION_FAILED',
        execution_disposition: 'NO_LONGER_POSSIBLE',
      },
    });
    if (cancelled.status !== 200 || cancelled.payload?.state !== 'CANCELLED') {
      throw new Error(`cancellation failed: ${describeFailure(cancelled)}`);
    }
    process.stdout.write(`Mollie reported ${settled.status} (${paymentID}): authorization CANCELLED.\n`);
  }

  const mandateRead = await apiRequest(state, { method: 'GET', path: `/v1/mandates/${mandateID}` });
  process.stdout.write(`Mandate state now: ${mandateRead.payload?.state ?? 'unknown'}.\n`);

  const evidence = await verifyEvidence(state, mandateID);
  const types = evidence.payload.events.map((event) => event.type);
  const required =
    expectation === 'commit' ? ['authorization.committed', 'mandate.consumed'] : ['authorization.cancelled'];
  const missing = required.filter((type) => !types.includes(type));
  if (missing.length > 0) {
    throw new Error(`evidence is missing expected event(s): ${missing.join(', ')}`);
  }
  const evidencePath = saveEvidence(mandateID, evidence.envelope);
  process.stdout.write(`Evidence verified locally against the published key ${evidence.keyID}:\n`);
  for (const [index, type] of types.entries()) {
    process.stdout.write(`  ${index + 1}. ${type}\n`);
  }
  process.stdout.write(`Evidence bundle saved: ${evidencePath}\n`);

  return {
    phase,
    mandateID,
    authorizationID,
    paymentID,
    paymentStatus: settled.status,
    webhookDelivered: settled.webhookDelivered,
    outcome: expectation === 'commit' ? 'COMMITTED' : 'CANCELLED',
    evidenceKeyID: evidence.keyID,
    evidencePath,
    eventCount: types.length,
  };
}

// -- run ---------------------------------------------------------------------

async function runMollie(options) {
  const mollieKey = typeof process.env.MOLLIE_API_KEY === 'string' ? process.env.MOLLIE_API_KEY.trim() : '';
  if (mollieKey === '') {
    throw new Error('set MOLLIE_API_KEY to a Mollie test-mode API key (test_...)');
  }
  if (!mollieKey.startsWith('test_')) {
    throw new Error('MOLLIE_API_KEY must be a test key (test_...); this harness never touches live mode');
  }
  MOLLIE_KEY = mollieKey;

  const webhookURL =
    typeof process.env.MOLLIE_WEBHOOK_URL === 'string' && process.env.MOLLIE_WEBHOOK_URL.trim() !== ''
      ? process.env.MOLLIE_WEBHOOK_URL.trim()
      : null;

  process.stdout.write('Attesso x Mollie rehearsal (test plane; activity here is free).\n');
  process.stdout.write(`Webhook: ${webhookURL === null ? 'polling fallback (MOLLIE_WEBHOOK_URL unset)' : webhookURL}\n`);

  const state = await loadStateOrPrompt();
  if (options.port !== null) {
    state.port = options.port;
  }

  const openEnv = { ...process.env };
  const { server, control } = await startServer(state);
  activeServer = server;
  process.stdout.write(`Local listener up on ${returnOrigin(state)} (approval return + /mollie-webhook).\n`);

  const runID = randomUUID().replaceAll('-', '').slice(0, 12);
  const startedAt = new Date().toISOString();
  // The `open` shim in the rig records the URL; PATH is inherited.
  const phases = [];
  try {
    phases.push(
      await runPhase(state, control, {
        runID,
        phase: 1,
        allowAmount: PHASE_ONE_ALLOW_AMOUNT,
        expectation: 'commit',
        webhookURL,
        openEnv,
      }),
    );
    phases.push(
      await runPhase(state, control, {
        runID,
        phase: 2,
        allowAmount: PHASE_TWO_ALLOW_AMOUNT,
        expectation: 'cancel',
        webhookURL,
        openEnv,
      }),
    );
  } finally {
    await sleep(RETURN_GRACE_MS);
    if (server.listening) {
      server.close();
    }
  }

  const summary = {
    runID,
    startedAt,
    finishedAt: new Date().toISOString(),
    webhookURL,
    phases,
  };
  const summaryPath = resolve(process.cwd(), 'mollie-run-summary.json');
  writeFileSync(summaryPath, JSON.stringify(summary, null, 2) + '\n');
  process.stdout.write('\n=== Rehearsal complete ===\n');
  for (const entry of phases) {
    process.stdout.write(
      `Phase ${entry.phase}: ${entry.outcome} (payment ${entry.paymentID}, status ${entry.paymentStatus}, ` +
        `webhook ${entry.webhookDelivered ? 'delivered' : 'not delivered'}), evidence bundle ${entry.evidencePath}\n`,
    );
  }
  process.stdout.write(`Summary saved: ${summaryPath}\n`);
}

// -- arguments and entry point -----------------------------------------------

function parseArguments(argv) {
  let mode = null;
  let port = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--help':
      case '-h':
        mode = 'help';
        break;
      case '--port': {
        const value = argv[index + 1];
        if (value === undefined || !/^[0-9]+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
          throw new Error('--port requires a number between 1 and 65535');
        }
        port = Number(value);
        index += 1;
        break;
      }
      default:
        throw new Error('unknown argument: ' + argument);
    }
  }
  return { mode: mode ?? 'run', port };
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write('FAILED: ' + error.message + '\n\n' + USAGE + '\n');
    process.exitCode = 2;
    return;
  }
  if (options.mode === 'help') {
    process.stdout.write(USAGE + '\n');
    return;
  }
  await runMollie(options);
}

try {
  await main();
} catch (error) {
  process.stderr.write('FAILED: ' + (error instanceof Error ? error.message : String(error)) + '\n');
  process.exitCode = 1;
} finally {
  if (activeServer !== null && activeServer.listening) {
    activeServer.close();
  }
  stopStdin();
}
