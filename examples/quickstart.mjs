#!/usr/bin/env node
// Attesso quickstart runner: run one test Mandate end to end (create, approve
// in the browser with a passkey, one over-cap DENY, one in-cap ALLOW, commit,
// then verify the signed evidence locally). Reference script, not a product:
// test plane only, no dependencies, Node.js 20+. Keep it one file and
// dependency-free.
//
// Canonical copy: attesso repo, docs/public-v1/examples/quickstart.mjs.
// Delivered copy: public docs repo, examples/quickstart.mjs; copy on change.
//
// Identity assertion contract (typ attesso-identity+jwt, alg ES256):
//   header { typ, alg, kid }; claims { iss, sub, aud, iat, exp, jti };
//   audience urn:attesso:approval:test:v1 (test) or urn:attesso:approval:live:v1;
//   signature is the 64-byte R || S form (IEEE P1363), never DER; every
//   segment is canonical unpadded base64url. Never sign in a browser; never
//   log the assertion, the API key, or the approval URL.
//
// Local state: ./attesso-quickstart.json (chmod 0600) holds the test API key
// and the identity key. Delete it (or run --reset) to start over.
//
// Usage:
//   node quickstart.mjs [--port N] [--reset]
//   node quickstart.mjs --selftest [--subject <subject_reference>]
//   node quickstart.mjs --help

import { spawn } from 'node:child_process';
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { resolve } from 'node:path';

const API_ORIGIN = 'https://api-staging.attesso.com';
const TEST_AUDIENCE = 'urn:attesso:approval:test:v1';
const LIVE_AUDIENCE = 'urn:attesso:approval:live:v1';
const ASSERTION_LIFETIME_SECONDS = 300;
const SUBJECT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const STATE_FILE = 'attesso-quickstart.json';
const DEFAULT_PORT = 43117;
const IDENTITY_KID = 'quickstart-1';
const IDENTITY_ISSUER = 'https://quickstart.local';
const MANDATE_ACTION = 'purchase.execute';
const MANDATE_MAX_AMOUNT = 25000; // minor units: EUR 250.00
const DEMO_DENY_AMOUNT = 32000; // minor units: EUR 320.00, deliberately above the cap
const DEMO_ALLOW_AMOUNT = 18900; // minor units: EUR 189.00, within the cap
const EXECUTION_WINDOW_SECONDS = 300;
const POLL_INTERVAL_MS = 2000;
const RETURN_WAIT_MS = 10 * 60 * 1000;
const MANDATE_WAIT_MS = 10 * 60 * 1000;
const RETURN_GRACE_MS = 15 * 1000; // let the browser's countdown land after the run

const SELFTEST_ISSUER = 'urn:example:quickstart';
const SELFTEST_KID = 'quickstart-selftest';
const SELFTEST_SUBJECT = 'user_selftest-1';

const USAGE = `Attesso quickstart runner (test plane; reference script, not a product).

Usage:
  node quickstart.mjs [--port N] [--reset]
      Run one test Mandate end to end against the free test plane: create it,
      approve it in the browser with a passkey, see one over-cap DENY and one
      in-cap ALLOW, commit the emulated execution, and verify the signed
      evidence locally. First run creates ./attesso-quickstart.json and walks
      the one-time dashboard step.

  node quickstart.mjs --selftest [--subject <subject_reference>]
      Offline check: generate a one-off P-256 identity key, sign an identity
      assertion, and print { issuer, kid, subject, audience, assertion,
      public_jwk } as JSON to stdout. No network; used by CI.

  node quickstart.mjs --help
`;

// The loopback return server while it is still listening; the entry-point
// finally closes it so a mid-flow failure can never keep the process alive.
let activeReturnServer = null;

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function jsonSegment(value) {
  return base64url(JSON.stringify(value));
}

// Generate a P-256 keypair in the shapes the API expects: the private JWK
// carries `d` plus the integrator's `kid` and `iss` metadata; the public JWK
// is what goes into approval trust.
function generateIdentityKey({ kid, issuer }) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  privateJwk.kid = kid;
  privateJwk.iss = issuer;
  return { privateJwk, publicJwk: publicIdentityJwk(privateJwk) };
}

function publicIdentityJwk(privateJwk) {
  if (privateJwk.kty !== 'EC' || privateJwk.crv !== 'P-256' || !privateJwk.x || !privateJwk.y) {
    throw new Error('identity key is not an EC P-256 JWK');
  }
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

// The one crypto step of the integration. Fails locally on any mistake the
// API would reject, so a broken assertion never reaches the network.
function signIdentityAssertion(privateJwk, subject, audience) {
  if (audience !== TEST_AUDIENCE && audience !== LIVE_AUDIENCE) {
    throw new Error('audience must be ' + TEST_AUDIENCE + ' or ' + LIVE_AUDIENCE);
  }
  if (typeof subject !== 'string' || !SUBJECT_PATTERN.test(subject)) {
    throw new Error('subject_reference must match ' + SUBJECT_PATTERN + ': ' + subject);
  }
  if (privateJwk.kty !== 'EC' || privateJwk.crv !== 'P-256') {
    throw new Error('identity key must be an EC P-256 JWK');
  }
  if (!privateJwk.d) {
    throw new Error('identity key has no private `d` value; that is a public key');
  }
  if (!privateJwk.kid || !privateJwk.iss) {
    throw new Error('identity key must carry `kid` and `iss`');
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
  if (signature.length !== 64) {
    throw new Error('signature is not the required 64-byte R || S form');
  }
  return { assertion: signingInput + '.' + base64url(signature), claims };
}

// -- terminal input ----------------------------------------------------------
// One reader for every interactive line. On a TTY it runs in raw mode with
// echo off, so the API key never appears on screen; piped input (tests,
// automation) is read line by line.

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
    throw new Error(`could not read ${STATE_FILE}; delete it and run again`);
  }
  if (!parsed.identity || !parsed.identity.d || !parsed.identity.kid || !parsed.identity.iss) {
    throw new Error(`${STATE_FILE} is missing the identity key; delete it and run again`);
  }
  return parsed;
}

function saveState(state) {
  const path = statePath();
  writeFileSync(path, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

async function loadOrCreateState(options) {
  let state = loadState();
  if (state) {
    if (options.port !== null && options.port !== state.port) {
      state = { ...state, port: options.port };
      saveState(state);
      process.stdout.write(
        `Return origin is now http://127.0.0.1:${state.port}; ` +
          'only change the port if approval trust is registered for it.\n',
      );
    }
    return state;
  }

  const environmentKey =
    typeof process.env.ATTESSO_API_KEY === 'string' ? process.env.ATTESSO_API_KEY.trim() : '';
  const apiKey =
    environmentKey !== ''
      ? environmentKey
      : ((await promptForLine('Paste your att_test_ API key (Dashboard -> Test): ')) ?? '');
  if (!apiKey.startsWith('att_test_')) {
    throw new Error('that is not an att_test_ key; the quickstart runs on the test plane only');
  }

  const { privateJwk } = generateIdentityKey({ kid: IDENTITY_KID, issuer: IDENTITY_ISSUER });
  state = { apiKey, port: options.port ?? DEFAULT_PORT, identity: privateJwk };
  saveState(state);
  process.stdout.write(`Created ${STATE_FILE} (test key + identity key, chmod 600).\n`);
  return state;
}

// -- API calls ---------------------------------------------------------------

function returnOrigin(state) {
  return `http://127.0.0.1:${state.port}`;
}

async function apiRequest(state, { method, path, idempotencyKey, body }) {
  let response;
  try {
    response = await fetch(new URL(path, API_ORIGIN + '/'), {
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
    throw new Error(`could not reach ${API_ORIGIN} (${cause}); check the connection and retry`);
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    // Keep payload null; status and request id still describe the failure.
  }
  return { status: response.status, payload, requestID: response.headers.get('attesso-request-id') };
}

function describeFailure(result) {
  const code = result.payload && typeof result.payload.code === 'string' ? result.payload.code : '';
  const requestID = result.requestID === null ? '' : `, request ${result.requestID}`;
  return code === '' ? `HTTP ${result.status}${requestID}` : `${code}${requestID}`;
}

function apiKeyRejected() {
  return (
    'the test API key was rejected. Create one under Dashboard -> Test, then delete ' +
    `${STATE_FILE} and run again`
  );
}

function euroAmount(minorUnits) {
  return 'EUR ' + (minorUnits / 100).toFixed(2);
}

function sleep(milliseconds) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds));
}

function withTimeout(promise, milliseconds, message) {
  return new Promise((resolveValue, rejectValue) => {
    const timer = setTimeout(() => rejectValue(new Error(message)), milliseconds);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolveValue(value);
      },
      (error) => {
        clearTimeout(timer);
        rejectValue(error);
      },
    );
  });
}

// Serves the exact loopback return origin registered in approval trust and
// resolves when the browser comes back from the ceremony. The redirect is a
// convenience only; the Mandate read is what proves the approval.
function startReturnServer(state) {
  return new Promise((resolveListen, rejectListen) => {
    let resolveApproved;
    const approved = new Promise((resolveReturn) => {
      resolveApproved = resolveReturn;
    });
    const server = createServer((request, response) => {
      const url = new URL(request.url, returnOrigin(state));
      const isReturn = url.pathname === '/approved';
      response.writeHead(isReturn ? 200 : 404, { 'Content-Type': 'text/html; charset=utf-8' });
      response.end(
        isReturn
          ? '<!doctype html><meta charset="utf-8"><title>Attesso quickstart</title>' +
            '<p>Approval received. Return to the terminal; it continues on its own.</p>'
          : 'Not found',
      );
      if (isReturn) {
        server.close();
        resolveApproved({ state: url.searchParams.get('state') });
      }
    });
    server.on('error', rejectListen);
    server.listen(state.port, '127.0.0.1', () => resolveListen({ server, approved }));
  });
}

function openApprovalPage(url) {
  const command =
    process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try {
    spawn(command, args, { detached: true, stdio: 'ignore' }).unref();
  } catch {
    // The printed URL remains the way in.
  }
}

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
      throw new Error(`the Mandate ended as ${lastName}; approve within the 15-minute window next time`);
    }
    if (Date.now() > deadline) {
      throw new Error('timed out waiting for the approval; approval sessions last 15 minutes');
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

function createAuthorization(state, mandateID, runID, label, amount) {
  return apiRequest(state, {
    method: 'POST',
    path: `/v1/mandates/${mandateID}/authorizations`,
    idempotencyKey: `quickstart.authorization.${label}.${runID}`,
    body: {
      external_reference: `candidate_${label}_${runID}`,
      proposed_action: {
        action: MANDATE_ACTION,
        attributes: {},
        payment: { amount, currency: 'EUR' },
      },
      execution_window_seconds: EXECUTION_WINDOW_SECONDS,
    },
  });
}

// Fetches the signed bundle only; the signature check below runs locally
// against the published keys, exactly as any third party would verify it.
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
    const response = await fetch(new URL('/.well-known/jwks.json', API_ORIGIN));
    keySet = await response.json();
  } catch (error) {
    throw new Error(`could not fetch the public verification keys: ${error.message}`);
  }
  const jwk = Array.isArray(keySet?.keys)
    ? keySet.keys.find((key) => key?.kid === keyID)
    : undefined;
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
  return { keyID, payload };
}

// -- run ---------------------------------------------------------------------

function printSetupBlock(state) {
  process.stdout.write('\n');
  process.stdout.write('One-time setup: this workspace has no approval trust yet.\n');
  process.stdout.write('Dashboard -> Test -> Approval trust; save exactly these values:\n\n');
  process.stdout.write(`  Identity issuer   ${state.identity.iss}\n`);
  process.stdout.write(`  Return origin     ${returnOrigin(state)}\n`);
  process.stdout.write(`  Public JWKs       ${JSON.stringify([publicIdentityJwk(state.identity)])}\n`);
  process.stdout.write('\nPaste them exactly as printed, save, then press Enter here.');
}

async function run(options) {
  process.stdout.write('Attesso quickstart (test plane; activity here is free).\n');
  const state = await loadOrCreateState(options);

  const runID = randomUUID().replaceAll('-', '');
  const subject = `quickstart_${runID}`;
  const returnURL = `${returnOrigin(state)}/approved`;

  const mandate = await apiRequest(state, {
    method: 'POST',
    path: '/v1/mandates',
    idempotencyKey: `quickstart.mandate.create.${runID}`,
    body: {
      subject_reference: subject,
      external_reference: `quickstart_${runID}`,
      policy: {
        version: '1',
        action: MANDATE_ACTION,
        constraints: [
          { path: 'payment.currency', operator: 'eq', value: 'EUR' },
          { path: 'payment.amount', operator: 'max', value: MANDATE_MAX_AMOUNT },
        ],
      },
      approval_deadline: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      valid_from: new Date(Date.now() - 60 * 1000).toISOString(),
      valid_until: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    },
  });
  if (mandate.status === 401) {
    throw new Error(apiKeyRejected());
  }
  if (mandate.status !== 201 || typeof mandate.payload?.id !== 'string') {
    throw new Error(`mandate creation failed: ${describeFailure(mandate)}`);
  }
  if (mandate.payload.state !== 'PENDING_APPROVAL') {
    throw new Error(`mandate creation returned an unexpected state: ${mandate.payload.state}`);
  }
  process.stdout.write(
    `\nMandate created: ${MANDATE_ACTION}, cap ${euroAmount(MANDATE_MAX_AMOUNT)} (${mandate.payload.id}, PENDING_APPROVAL).\n`,
  );

  let attempt = 0;
  for (;;) {
    attempt += 1;
    const { assertion } = signIdentityAssertion(state.identity, subject, TEST_AUDIENCE);
    const session = await apiRequest(state, {
      method: 'POST',
      path: `/v1/mandates/${mandate.payload.id}/approval-sessions`,
      idempotencyKey: `quickstart.approval.create.${runID}.${attempt}`,
      body: {
        identity_assertion: assertion,
        return_url: returnURL,
        return_state: `quickstart_${runID}`,
      },
    });

    if (session.status === 201 || session.status === 200) {
      const approvalURL = session.payload?.approval_url;
      if (typeof approvalURL !== 'string' || approvalURL === '') {
        throw new Error('the approval session did not include an approval_url');
      }
      process.stdout.write(`\nApproval session: OPEN (${session.payload.id}).\n`);

      const { server, approved } = await startReturnServer(state);
      activeReturnServer = server;
      process.stdout.write(
        'Opening the approval page in your browser; approve with the passkey there.\n' +
          'The terminal continues by itself once the approval is done.\n',
      );
      process.stdout.write(`\nIf no browser opened, visit this once:\n\n  ${approvalURL}\n`);
      openApprovalPage(approvalURL);

      // The redirect is a convenience; the Mandate read is the proof. Race
      // them so a closed tab or a blocked return cannot stall the run:
      // whichever lands first, the single poller below settles the rest.
      // On the active path the return server stays up: the browser may
      // still be mid-countdown, and the grace at the end of the run lets it
      // land on the local page before the process stops.
      const becameActive = waitForMandateActive(state, mandate.payload.id).then(
        (payload) => ({ kind: 'active', payload }),
        (error) => ({ kind: 'failed', error }),
      );
      let winner;
      try {
        winner = await withTimeout(
          Promise.race([
            approved.then((value) => ({ kind: 'returned', value })),
            becameActive,
          ]),
          RETURN_WAIT_MS,
          'no approval within 10 minutes; run the script again to start over',
        );
      } catch (error) {
        if (server.listening) {
          server.close();
        }
        throw error;
      }
      if (winner.kind === 'failed') {
        if (server.listening) {
          server.close();
        }
        throw winner.error;
      }
      const settled = winner.kind === 'active' ? winner : await becameActive;
      if (settled.kind === 'failed') {
        if (server.listening) {
          server.close();
        }
        throw settled.error;
      }
      process.stdout.write('Mandate is ACTIVE. (The redirect is not proof; this server-side read is.)\n');

      const denied = await createAuthorization(state, mandate.payload.id, runID, 'deny', DEMO_DENY_AMOUNT);
      if (denied.status !== 201) {
        throw new Error(`the over-cap probe failed: ${describeFailure(denied)}`);
      }
      if (denied.payload?.decision !== 'DENY' || denied.payload?.can_execute !== false) {
        throw new Error(
          `over-cap probe expected DENY with can_execute=false, got ${denied.payload?.decision}/${denied.payload?.state}`,
        );
      }
      process.stdout.write(
        `Over the cap (${euroAmount(DEMO_DENY_AMOUNT)}): ${denied.payload.decision}. Nothing was reserved.\n`,
      );

      const allowed = await createAuthorization(state, mandate.payload.id, runID, 'allow', DEMO_ALLOW_AMOUNT);
      if (allowed.status !== 201) {
        throw new Error(`authorization failed: ${describeFailure(allowed)}`);
      }
      if (allowed.payload?.decision !== 'ALLOW' || allowed.payload?.can_execute !== true) {
        throw new Error(
          `expected ALLOW with can_execute=true, got ${allowed.payload?.decision}/${allowed.payload?.state}`,
        );
      }
      process.stdout.write(
        `Within the cap (${euroAmount(DEMO_ALLOW_AMOUNT)}): ${allowed.payload.decision}, ` +
          `execute before ${allowed.payload.execute_before}.\n`,
      );

      const committed = await apiRequest(state, {
        method: 'PUT',
        path: `/v1/authorizations/${allowed.payload.id}/commit`,
        idempotencyKey: `quickstart.authorization.commit.${runID}`,
        body: { external_action_reference: `emu_${runID}` },
      });
      if (committed.status !== 200) {
        throw new Error(`commit failed: ${describeFailure(committed)}`);
      }
      process.stdout.write(
        `Emulated executor accepted (emu_${runID}); authorization ${committed.payload?.state}.\n`,
      );

      const evidence = await verifyEvidence(state, mandate.payload.id);
      process.stdout.write(`\nEvidence verified locally against the published key ${evidence.keyID}:\n`);
      for (const [index, event] of evidence.payload.events.entries()) {
        process.stdout.write(`  ${index + 1}. ${event.type}\n`);
      }
      process.stdout.write(
        `\nQuickstart complete: one test Mandate approved, executed, and evidenced ` +
          `(${evidence.payload.events.length} events inside the signed bundle).\n`,
      );

      // The browser may still be mid-countdown (or the human may be reading
      // the success screen); keep the return page up briefly so it lands on
      // the local page instead of a dead port, then stop.
      if (server.listening) {
        await Promise.race([approved, sleep(RETURN_GRACE_MS)]);
        if (server.listening) {
          server.close();
        }
      }
      return;
    }
    if (session.payload?.code === 'APPROVAL_NOT_CONFIGURED') {
      if (attempt > 1) {
        process.stdout.write('\n\nStill no approval trust for this workspace.');
      }
      printSetupBlock(state);
      const line = await promptForLine(' ');
      if (line === null) {
        throw new Error('standard input closed before approval trust was configured');
      }
      continue;
    }
    if (session.status === 401) {
      throw new Error(apiKeyRejected());
    }
    if (session.payload?.code === 'VALIDATION_FAILED') {
      throw new Error(
        'the approval session was rejected (VALIDATION_FAILED). Approval trust for this ' +
          'workspace likely holds different values: open Dashboard -> Test -> Approval trust ' +
          `and save the printed issuer, origin, and key exactly, or delete ${STATE_FILE} for a ` +
          'fresh identity',
      );
    }
    throw new Error(`the approval session was rejected: ${describeFailure(session)}`);
  }
}

// -- selftest ----------------------------------------------------------------

function runSelftest(subject) {
  const { privateJwk, publicJwk } = generateIdentityKey({
    kid: SELFTEST_KID,
    issuer: SELFTEST_ISSUER,
  });
  const { assertion } = signIdentityAssertion(privateJwk, subject, TEST_AUDIENCE);
  process.stdout.write(
    JSON.stringify(
      {
        issuer: SELFTEST_ISSUER,
        kid: SELFTEST_KID,
        subject,
        audience: TEST_AUDIENCE,
        assertion,
        public_jwk: publicJwk,
      },
      null,
      2,
    ) + '\n',
  );
}

// -- arguments and entry point -----------------------------------------------

function parseArguments(argv) {
  let mode = null;
  const setMode = (next) => {
    if (mode !== null && mode !== next) {
      throw new Error(`cannot combine --${mode} and --${next}`);
    }
    mode = next;
  };
  let subject = null;
  let port = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--selftest':
        setMode('selftest');
        break;
      case '--reset':
        setMode('reset');
        break;
      case '--subject': {
        const value = argv[index + 1];
        if (value === undefined) {
          throw new Error('--subject requires a value');
        }
        subject = value;
        index += 1;
        break;
      }
      case '--port': {
        const value = argv[index + 1];
        if (value === undefined || !/^[0-9]+$/.test(value) || Number(value) < 1 || Number(value) > 65535) {
          throw new Error('--port requires a number between 1 and 65535');
        }
        port = Number(value);
        index += 1;
        break;
      }
      case '--help':
      case '-h':
        setMode('help');
        break;
      default:
        throw new Error('unknown argument: ' + argument);
    }
  }
  if (subject !== null && mode !== 'selftest') {
    throw new Error('--subject requires --selftest');
  }
  if (port !== null && mode !== null && mode !== 'run') {
    throw new Error('--port applies to the run mode only');
  }
  return { mode: mode ?? 'run', subject, port };
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write('FAILED: ' + error.message + '\n\n' + USAGE);
    process.exitCode = 2;
    return;
  }
  if (options.mode === 'help') {
    process.stdout.write(USAGE);
    return;
  }
  if (options.mode === 'reset') {
    const path = statePath();
    if (existsSync(path)) {
      rmSync(path);
      process.stdout.write(`Removed ${path}. Run again to start fresh.\n`);
    } else {
      process.stdout.write('Nothing to reset: no local state file.\n');
    }
    return;
  }
  if (options.mode === 'selftest') {
    runSelftest(options.subject ?? SELFTEST_SUBJECT);
    return;
  }
  await run(options);
}

try {
  await main();
} catch (error) {
  process.stderr.write(
    'FAILED: ' + (error instanceof Error ? error.message : String(error)) + '\n',
  );
  process.exitCode = 1;
} finally {
  if (activeReturnServer !== null && activeReturnServer.listening) {
    activeReturnServer.close();
  }
  stopStdin();
}
