import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { answers, answersCard, answersPasskey, CARD_FIELDS, CARD_VERSION, cancel, cardRequest, explain, fillRequest, MAX_MESSAGE_BYTES, NATIVE_HOST, pageOrigin, PASSKEY_VERSION, passkeyRequest, readResponse, VERSION, type CardReply, type FillReply, type PasskeyReply } from "./protocol.ts";
import { outcomeOf } from "./passkey.ts";

test("only an https page has an origin to ask for", () => {
  assert.equal(pageOrigin("https://example.com/login?next=/home#form"), "https://example.com");
  assert.equal(pageOrigin("https://EXAMPLE.com:443/"), "https://example.com");
  assert.equal(pageOrigin("https://example.com:8443/login"), "https://example.com:8443");
  assert.equal(pageOrigin("https://bücher.example/"), "https://xn--bcher-kva.example");
  for (const address of [
    undefined,
    "",
    "http://example.com/login",
    "https://user:secret@example.com/",
    "https://user@example.com/",
    "file:///etc/passwd",
    "about:blank",
    "data:text/html,<form>",
    "chrome://settings/",
    "chrome-extension://hjgekjgkjnakgmiopldddikdkcjhnmge/page.html",
    "view-source:https://example.com/",
    "blob:https://example.com/0b4e1e0a",
    "not an address",
  ]) {
    assert.equal(pageOrigin(address), null, String(address));
  }
});

test("a request names the page's own document and nothing of the vault", () => {
  assert.deepEqual(fillRequest("request-1", 12, "document-1", "https://example.com"), {
    type: "fill_request",
    version: 1,
    requestId: "request-1",
    tabId: 12,
    frameId: 0,
    documentId: "document-1",
    origin: "https://example.com",
  });
});

const request = fillRequest("request-1", 12, "document-1", "https://example.com");
const reply: FillReply = { type: "fill_reply", requestId: "request-1", tabId: 12, frameId: 0, documentId: "document-1", origin: "https://example.com", username: "alice", password: "correct horse" };

test("a reply is for a request only if everything it names is the same", () => {
  assert.equal(answers(reply, request), true);
  const changes: Partial<FillReply>[] = [
    { requestId: "request-2" },
    { tabId: 13 },
    { frameId: 1 },
    { documentId: "document-2" },
    { origin: "https://www.example.com" },
    { origin: "https://example.com:8443" },
    { origin: "http://example.com" },
  ];
  for (const change of changes) assert.equal(answers({ ...reply, ...change }, request), false, JSON.stringify(change));
});

test("only the three responses, exactly as specified, are read", () => {
  assert.deepEqual(readResponse(reply), reply);
  assert.deepEqual(readResponse({ type: "waiting", requestId: "request-1" }), { type: "waiting", requestId: "request-1" });
  assert.deepEqual(readResponse({ type: "error", requestId: "request-1", code: "denied" }), { type: "error", requestId: "request-1", code: "denied" });
  assert.deepEqual(readResponse({ type: "error", requestId: null, code: "invalid_message" }), { type: "error", requestId: null, code: "invalid_message" });

  const { password, ...withoutPassword } = reply;
  void password;
  for (const message of [
    null,
    undefined,
    "fill_reply",
    7,
    [reply],
    {},
    { type: "fill" },
    { ...reply, note: "one field too many" },
    withoutPassword,
    { ...reply, username: 7 },
    { ...reply, password: null },
    { ...reply, tabId: "12" },
    { ...reply, password: "x".repeat(MAX_MESSAGE_BYTES) },
    { type: "waiting" },
    { type: "waiting", requestId: 1 },
    { type: "waiting", requestId: "request-1", password: "x" },
    { type: "error", requestId: "request-1" },
    { type: "error", requestId: "request-1", code: 3 },
    { type: "error", requestId: 4, code: "denied" },
    { type: "error", requestId: "request-1", code: "denied", extra: true },
  ]) {
    assert.equal(readResponse(message), null, JSON.stringify(message)?.slice(0, 80));
  }
});

test("every refusal is explained in words, and none claims a fill", () => {
  for (const code of ["denied", "expired", "cancelled", "busy", "desktop_session_unavailable", "extension_not_allowed", "origin_rejected", "frame_rejected", "invalid_message", "something_new"]) {
    const text = explain(code);
    assert.ok(text.length > 20, code);
    assert.ok(!/was filled\b/.test(text) || /Nothing was filled/.test(text), code);
  }
  assert.match(explain("desktop_session_unavailable"), /not running/);
  assert.match(explain("busy"), /Another request/);
});

// The messages as the Rust side wrote them when the format was frozen. The
// host and the desktop session are tested against the same file, so the two
// implementations stay on one format.
const frozen = JSON.parse(readFileSync(new URL("../../../crates/browser-link/fixtures/messages.json", import.meta.url), "utf8"));

test("the extension writes and reads the frozen messages the host is tested against", () => {
  assert.equal(VERSION, frozen.version);
  assert.equal(NATIVE_HOST, frozen.host_name);
  const firefox = JSON.parse(readFileSync(new URL("../manifest.firefox.json", import.meta.url), "utf8"));
  assert.equal(firefox.browser_specific_settings.gecko.id, frozen.firefox_extension_id);

  // What the extension sends is what the host was frozen reading.
  const asked = JSON.parse(frozen.from_extension.fill_request);
  assert.deepEqual(fillRequest(asked.requestId, asked.tabId, asked.documentId, asked.origin), asked);
  assert.deepEqual(cancel(asked.requestId), JSON.parse(frozen.from_extension.cancel));

  // What the host was frozen writing is what the extension reads.
  const waiting = JSON.parse(frozen.to_extension.waiting);
  assert.deepEqual(readResponse(waiting), waiting);
  const filled = JSON.parse(frozen.to_extension.fill_reply);
  const read = readResponse(filled);
  assert.deepEqual(read, filled);
  assert.ok(read?.type === "fill_reply" && answers(read, asked));
  const unnamed = JSON.parse(frozen.to_extension.error_naming_no_request);
  assert.deepEqual(readResponse(unnamed), unnamed);
  const codes = Object.keys(frozen.to_extension.errors);
  assert.equal(codes.length, 12);
  for (const code of codes) {
    const failure = JSON.parse(frozen.to_extension.errors[code]);
    assert.deepEqual(readResponse(failure), failure, code);
    assert.equal(failure.code, code);
    assert.match(explain(code), /\S/, code);
  }
});

// The messages of a card's fill, which came with version 2.
const frozenCard = JSON.parse(readFileSync(new URL("../../../crates/browser-link/fixtures/messages-2.json", import.meta.url), "utf8"));

test("the extension writes and reads the frozen messages of a card's fill", () => {
  assert.equal(CARD_VERSION, frozenCard.version);
  assert.deepEqual([...CARD_FIELDS], frozenCard.card_fields);
  const asked = JSON.parse(frozenCard.from_extension.card_request);
  assert.equal(JSON.stringify(cardRequest(asked.requestId, asked.tabId, asked.topOrigin, asked.frames)), frozenCard.from_extension.card_request);
  const reply = readResponse(JSON.parse(frozenCard.to_extension.card_reply));
  assert.ok(reply !== null && reply.type === "card_reply");
  assert.ok(answersCard(reply as CardReply, asked));
  assert.equal((reply as CardReply).card.number, "4111111111111111");

  // A reply that names a document otherwise, or one more field, is not for it.
  const other = (change: (reply: CardReply) => void) => {
    const changed = JSON.parse(frozenCard.to_extension.card_reply) as CardReply;
    change(changed);
    return changed;
  };
  for (const changed of [
    other((reply) => { reply.frames[1].origin = "https://other.example"; }),
    other((reply) => { reply.frames[1].documentId = "another"; }),
    other((reply) => { reply.frames[0].fields.push("security_code"); }),
    other((reply) => { reply.frames.pop(); }),
    other((reply) => { reply.topOrigin = "https://other.example"; }),
  ]) {
    assert.equal(answersCard(changed, asked), false, JSON.stringify(changed.frames));
  }
  // A card's reply missing a value, or with one more, is no reply.
  for (const changed of [
    other((reply) => { delete (reply.card as Partial<CardReply["card"]>).securityCode; }),
    other((reply) => { (reply.card as Record<string, string>).pin = "1234"; }),
    other((reply) => { (reply.frames[0] as unknown as Record<string, unknown>).fields = ["pin"]; }),
  ]) {
    assert.equal(readResponse(changed), null);
  }
  // An app that does not know a card's request says so, and the owner is told to update it.
  assert.match(explain("unsupported_message"), /Update the app/);
  assert.match(explain("unsupported_version"), /Update the app/);
});

// The messages of a passkey's request, which came with version 2 too.
const frozenPasskey = JSON.parse(readFileSync(new URL("../../../crates/browser-link/fixtures/messages-2-passkeys.json", import.meta.url), "utf8"));

test("the extension writes and reads the frozen messages of a passkey's request", () => {
  assert.equal(PASSKEY_VERSION, frozenPasskey.version);
  for (const [name, kind] of [["passkey_create", "create"], ["passkey_get", "get"]] as const) {
    const asked = JSON.parse(frozenPasskey.from_extension[name]);
    assert.equal(JSON.stringify(passkeyRequest(kind, asked.requestId, asked.tabId, asked.origin, asked.options)), frozenPasskey.from_extension[name]);
  }
  const asked = JSON.parse(frozenPasskey.from_extension.passkey_get);
  const reply = readResponse(JSON.parse(frozenPasskey.to_extension.passkey_reply));
  assert.ok(reply !== null && reply.type === "passkey_reply" && answersPasskey(reply, asked));
  const changed = (change: (reply: PasskeyReply) => void) => {
    const copy = JSON.parse(frozenPasskey.to_extension.passkey_reply) as PasskeyReply;
    change(copy);
    return copy;
  };
  assert.equal(answersPasskey(changed((reply) => { reply.origin = "https://example.com"; }), asked), false);
  assert.equal(answersPasskey(changed((reply) => { reply.tabId += 1; }), asked), false);
  assert.equal(readResponse(changed((reply) => { (reply as unknown as Record<string, unknown>).credential = null; })), null);
  // Each refusal the passkeys brought reads, and ends the page's call as it should.
  const outcomes: Record<string, string> = {};
  for (const [code, text] of Object.entries(frozenPasskey.to_extension.errors as Record<string, string>)) {
    const failure = readResponse(JSON.parse(text));
    assert.ok(failure?.type === "error" && failure.code === code);
    outcomes[code] = JSON.stringify(outcomeOf(code));
  }
  assert.deepEqual(outcomes, {
    no_passkey: JSON.stringify({ fallback: true, waitForFocus: false }),
    passkey_refused: JSON.stringify({ fallback: true, waitForFocus: false }),
    passkey_exists: JSON.stringify({ error: "InvalidStateError", message: "Open Secret Manager already holds a passkey of this account for this site." }),
    use_browser: JSON.stringify({ fallback: true, waitForFocus: true }),
  });
});

