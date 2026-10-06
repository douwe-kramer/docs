#!/usr/bin/env node
/**
 * Verify an Attesso evidence bundle (Node.js, no dependencies).
 *
 * Usage:
 *   node verify-evidence.js <evidence.json> [jwks.json]
 *
 * - <evidence.json> is the JWS envelope returned by
 *   GET /v1/mandates/{mandate_id}/evidence
 * - [jwks.json] is optional; if omitted, it is fetched from
 *   https://api.attesso.com/.well-known/jwks.json
 *
 * Exit code 0 = verified, 1 = failed.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

const DEFAULT_JWKS_URL = 'https://api.attesso.com/.well-known/jwks.json';
const COMMITMENT_DOMAIN = 'attesso:authorization:commitment:v1\n';

function b64urlToBuffer(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('invalid JSON from ' + url));
        }
      });
    }).on('error', reject);
  });
}

// The single-use check: every committed event must reveal the opening its
// creation committed to. A creation with no commitment predates the
// requirement and is labelled historical, not failed.
function checkSingleUse(events) {
  const created = new Map();
  for (const event of events) {
    if (
      event.type === 'authorization.created' &&
      event.payload &&
      typeof event.payload.authorization_id === 'string'
    ) {
      created.set(event.payload.authorization_id, event.payload);
    }
  }

  let sealed = 0;
  let historical = 0;
  let failures = 0;
  const committedCounts = new Map();
  for (const event of events) {
    if (event.type !== 'authorization.committed' || !event.payload) continue;
    const id = event.payload.authorization_id;
    if (typeof id === 'string') {
      committedCounts.set(id, (committedCounts.get(id) || 0) + 1);
    }

    const creation = created.get(id);
    const commitment = creation ? creation.commitment : undefined;
    if (typeof commitment !== 'string' || commitment === '') {
      historical += 1;
      continue;
    }

    const opening = event.payload.opening;
    if (typeof opening !== 'string' || !/^[0-9a-f]{64}$/.test(opening)) {
      failures += 1;
      console.error('FAILED: committed event carries no well-formed opening for ' + id);
      continue;
    }

    const digest = crypto
      .createHash('sha256')
      .update(Buffer.concat([
        Buffer.from(COMMITMENT_DOMAIN),
        Buffer.from(opening, 'hex'),
      ]))
      .digest('hex');
    if ('sha256:' + digest === commitment) {
      sealed += 1;
    } else {
      failures += 1;
      console.error('FAILED: the opening does not open the commitment for ' + id);
    }
  }

  for (const [id, count] of committedCounts) {
    if (count > 1) {
      failures += 1;
      console.error('FAILED: ' + count + ' committed events for ' + id);
    }
  }
  return { sealed, historical, failures };
}

// The provenance check: report events carry the machine-readable
// integrator_reported label. An unlabelled report event is a failure.
function checkReports(events) {
  let reports = 0;
  let failures = 0;
  for (const event of events) {
    if (event.type !== 'authorization.reported' || !event.payload) continue;
    reports += 1;
    if (event.payload.source !== 'integrator_reported') {
      failures += 1;
      console.error(
        'FAILED: report event carries no integrator_reported source label for ' +
          (event.payload.report_id || event.payload.authorization_id)
      );
    }
  }
  return { reports, failures };
}

async function main() {
  const [evidencePath, jwksPath] = process.argv.slice(2);
  if (!evidencePath) {
    console.error('usage: node verify-evidence.js <evidence.json> [jwks.json]');
    process.exit(2);
  }

  const envelope = JSON.parse(fs.readFileSync(evidencePath, 'utf8'));
  if (envelope.format !== 'attesso.evidence.v1') {
    throw new Error('unexpected evidence format: ' + envelope.format);
  }

  const protectedHeader = JSON.parse(
    b64urlToBuffer(envelope.protected).toString('utf8')
  );
  const kid = protectedHeader.kid;

  const jwks = jwksPath
    ? JSON.parse(fs.readFileSync(jwksPath, 'utf8'))
    : await fetchJson(DEFAULT_JWKS_URL);

  const key = jwks.keys.find((k) => k.kid === kid);
  if (!key) {
    throw new Error('no verification key found for kid ' + kid);
  }
  if (key.kty !== 'EC' || key.crv !== 'P-256' || key.alg !== 'ES256') {
    throw new Error('key ' + kid + ' is not an ES256 P-256 key');
  }

  const x = b64urlToBuffer(key.x);
  const y = b64urlToBuffer(key.y);
  const publicKey = crypto.createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: key.x,
      y: key.y,
    },
    format: 'jwk',
  });

  const signingInput = envelope.protected + '.' + envelope.payload;
  const signature = b64urlToBuffer(envelope.signature);

  const verified = crypto.verify(
    'sha256',
    Buffer.from(signingInput, 'utf8'),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    signature
  );

  if (!verified) {
    console.error('FAILED: signature did not verify');
    process.exit(1);
  }

  const payload = JSON.parse(b64urlToBuffer(envelope.payload).toString('utf8'));
  const events = Array.isArray(payload.events) ? payload.events : [];
  const singleUse = checkSingleUse(events);
  const reportCheck = checkReports(events);
  if (singleUse.failures === 0 && reportCheck.failures === 0) {
    console.log('OK: evidence verified');
  }
  console.log('  mandate:      ' + payload.mandate.id);
  console.log('  state:        ' + payload.mandate.state);
  console.log('  policy_digest:' + payload.mandate.policy_digest);
  console.log('  events:       ' + events.length);
  console.log(
    '  sealed pairs checked: ' + singleUse.sealed +
    ', historical commits skipped: ' + singleUse.historical +
    ', failures: ' + singleUse.failures
  );
  console.log('  report events (integrator_reported): ' + reportCheck.reports);
  if (singleUse.failures > 0 || reportCheck.failures > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('FAILED: ' + err.message);
  process.exit(1);
});
