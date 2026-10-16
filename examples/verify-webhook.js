#!/usr/bin/env node
// Verifies Attesso webhook deliveries against the shared vectors file.
//
// Usage: node verify-webhook.js [verify-webhook-vectors.json]
//
// Exit 0 when every vector behaves as its expect_valid says; exit 1
// otherwise. The recomputation is the whole recipe: check the timestamp is
// inside the window, then recompute HMAC-SHA256 over `t + "." + body` with
// the endpoint signing secret and compare against the header's v1 value.
// Never verify a re-serialized body: sign and verify the exact bytes.
"use strict";

const { createHmac, timingSafeEqual } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");

function headerFields(header) {
  const parts = String(header).split(",");
  if (parts.length !== 2 || !parts[0].startsWith("t=") || !parts[1].startsWith("v1=")) {
    return null;
  }
  const timestampText = parts[0].slice(2);
  const signatureHex = parts[1].slice(3);
  // Strict shapes: canonical base-10 seconds and exactly 64 hex characters.
  // Node's Buffer.from silently truncates invalid hex, so a lax parse here
  // would accept trailing junk the Go sibling rejects.
  if (!/^[0-9]+$/.test(timestampText) || !/^[0-9a-fA-F]{64}$/.test(signatureHex)) {
    return null;
  }
  return { timestamp: Number(timestampText), hex: signatureHex };
}

function verifyDelivery(secret, header, body, now, windowSeconds) {
  const fields = headerFields(header);
  if (fields === null) {
    return { valid: false, reason: "malformed_header" };
  }
  if (Math.abs(now - fields.timestamp) > windowSeconds) {
    return { valid: false, reason: "timestamp_out_of_window" };
  }
  const expected = createHmac("sha256", secret)
    .update(String(fields.timestamp))
    .update(".")
    .update(body)
    .digest();
  const provided = Buffer.from(fields.hex, "hex");
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return { valid: false, reason: "signature_mismatch" };
  }
  return { valid: true, reason: "ok" };
}

function main() {
  const path = process.argv[2] || join(__dirname, "verify-webhook-vectors.json");
  const document = JSON.parse(readFileSync(path, "utf8"));
  let failed = 0;
  for (const vector of document.vectors) {
    const secret = Buffer.from(vector.secret_hex, "hex");
    const outcome = verifyDelivery(secret, vector.header, vector.body, vector.now, vector.window_seconds);
    const conforming = outcome.valid === vector.expect_valid;
    if (!conforming) {
      failed += 1;
    }
    console.log(
      `${conforming ? "PASS" : "FAIL"} ${vector.name.padEnd(24)} valid=${outcome.valid} expected=${vector.expect_valid} (${outcome.reason})`
    );
  }
  if (failed > 0) {
    console.log(`${failed} vector(s) misbehaved`);
    process.exit(1);
  }
  console.log("all vectors behaved as expected");
}

main();
