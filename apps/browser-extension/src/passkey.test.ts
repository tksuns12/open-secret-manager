import assert from "node:assert/strict";
import { test } from "node:test";
import { base64url, CHANNEL, creationJSON, isAnswer, isAsk, isForTheApp, isOutcome, isWithdraw, outcomeOf, requestJSON, siteKeyOf, unbase64url, waitFor } from "./passkey.ts";

const bytes = (...values: number[]) => new Uint8Array(values);

test("a page's options become WebAuthn's JSON, keeping only what the app reads", () => {
  const user = bytes(1, 2, 3, 4);
  const created = JSON.parse(creationJSON({
    rp: { id: "example.com", name: "Example", icon: "dropped" },
    user: { id: user.buffer, name: "owner", displayName: "Owner" },
    challenge: new DataView(bytes(250, 251, 252).buffer),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    timeout: 60000,
    excludeCredentials: [{ type: "public-key", id: bytes(9, 9), transports: ["internal", 5] }],
    authenticatorSelection: { residentKey: "required", userVerification: "preferred", other: {} },
    attestation: "direct",
    extensions: { credProps: true, prf: { eval: { first: bytes(1).buffer } } },
  }));
  assert.deepEqual(created, {
    rp: { id: "example.com", name: "Example" },
    user: { id: "AQIDBA", name: "owner", displayName: "Owner" },
    challenge: "-vv8",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    timeout: 60000,
    excludeCredentials: [{ type: "public-key", id: "CQk", transports: ["internal"] }],
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    attestation: "direct",
  });
  assert.deepEqual(JSON.parse(requestJSON({ challenge: bytes(1, 2), rpId: "example.com", allowCredentials: [{ type: "public-key", id: bytes(7) }], userVerification: "required" })), {
    challenge: "AQI", rpId: "example.com", allowCredentials: [{ type: "public-key", id: "Bw" }], userVerification: "required",
  });
  // Options it cannot read are the browser's own to answer.
  for (const unreadable of [undefined, {}, { rp: {}, user: { id: "not bytes" }, challenge: bytes(1) }, { rp: {}, user: { id: bytes(1) } }]) {
    assert.throws(() => creationJSON(unreadable));
  }
  assert.throws(() => requestJSON({ challenge: "AQI" }));
  assert.deepEqual([...unbase64url(base64url(bytes(0, 255, 128, 1)))], [0, 255, 128, 1]);
});

test("only a passkey's call of the page, not one for the browser's own list, goes to the app", () => {
  assert.equal(isForTheApp({ publicKey: {} }), true);
  assert.equal(isForTheApp({ publicKey: {}, signal: new AbortController().signal, mediation: "optional" }), true);
  for (const other of [undefined, null, {}, { publicKey: {}, mediation: "conditional" }, { publicKey: {}, mediation: "silent" }, { publicKey: {}, password: true }, { password: true }, { publicKey: "x" }]) {
    assert.equal(isForTheApp(other), false, JSON.stringify(other));
  }
  assert.deepEqual([waitFor(null), waitFor(1), waitFor(30_000), waitFor(600_000)], [120_000, 10_000, 30_000, 120_000]);
});

test("the page's script and the bridge take only messages of their own shape", () => {
  const id = crypto.randomUUID();
  assert.equal(isAsk({ channel: CHANNEL, type: "ask", id, kind: "get", options: "{}", timeout: null }), true);
  for (const other of [
    { channel: CHANNEL, type: "ask", id: "not-an-id", kind: "get", options: "{}", timeout: null },
    { channel: CHANNEL, type: "ask", id, kind: "delete", options: "{}", timeout: null },
    { channel: CHANNEL, type: "ask", id, kind: "get", options: {}, timeout: null },
    { channel: "other", type: "ask", id, kind: "get", options: "{}", timeout: null },
  ]) {
    assert.equal(isAsk(other), false, JSON.stringify(other));
  }
  assert.equal(isWithdraw({ channel: CHANNEL, type: "withdraw", id }), true);
  assert.equal(isAnswer({ channel: CHANNEL, type: "answer", id, outcome: { credential: "{}" } }), true);
  assert.equal(isAnswer({ channel: CHANNEL, type: "answer", id, outcome: { credential: "{}", extra: 1 } }), false);
  assert.equal(isOutcome({ error: "SecurityError", message: "" }), false);
  assert.equal(isOutcome(outcomeOf("denied")), true);
  assert.equal(isOutcome(outcomeOf("anything else")), true);
  assert.deepEqual(outcomeOf("desktop_session_unavailable"), { fallback: true, waitForFocus: false });
});

test("siteKeyOf groups subdomains by valid rpId or parent domain", () => {
  assert.equal(siteKeyOf("https://a.login.test", JSON.stringify({ rpId: "login.test" })), "site:login.test");
  assert.equal(siteKeyOf("https://b.login.test", JSON.stringify({ rp: { id: "login.test" } })), "site:login.test");
  assert.equal(siteKeyOf("https://www.login.test"), "site:login.test");
  assert.equal(siteKeyOf("https://other.test"), "site:other.test");
  // An unrelated rpId cannot redirect cooldown to another site.
  assert.equal(siteKeyOf("https://evil.test", JSON.stringify({ rpId: "login.test" })), "site:evil.test");
});
