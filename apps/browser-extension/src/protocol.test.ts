import assert from "node:assert/strict";
import { test } from "node:test";
import { answers, explain, fillRequest, MAX_MESSAGE_BYTES, pageOrigin, readResponse, type FillReply } from "./protocol.ts";

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
