// What a page's script, the native messaging host, or a tab's address
// could hand the extension, made by a seeded generator: the valid messages
// changed a little or a lot, and anything else a connection can carry. Each
// check holds for every one. A failure names its seed; `OSM_SEED=<seed>`
// runs only that one.

import assert from "node:assert/strict";
import { test } from "node:test";
import { isFilled, isPrepared } from "./page.ts";
import { answers, fillRequest, MAX_MESSAGE_BYTES, pageOrigin, readResponse, type FillReply } from "./protocol.ts";

const SEEDS = process.env.OSM_SEED ? [Number(process.env.OSM_SEED)] : Array.from({ length: 16 }, (_, index) => 0x5eed + index);
const CASES = 400;

/** A small generator (mulberry32) that gives the same values for a seed. */
function generator(seed: number) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = state;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
  const int = (below: number) => Math.floor(next() * below);
  const pick = <T>(items: readonly T[]): T => items[int(items.length)];
  return { int, pick };
}

type Generator = ReturnType<typeof generator>;

const KEYS = ["type", "requestId", "tabId", "frameId", "documentId", "origin", "username", "password", "code", "fields", "version", "__proto__", "constructor", "toString", ""];
const WORDS = ["", "prepared", "filled", "waiting", "fill_reply", "error", "fill", "username", "password", "user name", "request-1", "document-1", "https://example.com", "http://example.com", "denied", "__proto__", "😀", "\u0000", "a".repeat(64), "a".repeat(65), "x".repeat(MAX_MESSAGE_BYTES)];
const NUMBERS = [0, -0, 1, -1, 12, 13, 0.5, 2 ** 53, -(2 ** 31), NaN, Infinity, -Infinity];

function text(g: Generator): string {
  const alphabet = "abcAZ09-_:/.@%?#\\ \t\n\u0000é😀";
  return Array.from({ length: g.int(12) }, () => alphabet[g.int(alphabet.length)]).join("");
}

/** Anything a message could be. */
function anything(g: Generator, depth = 0): unknown {
  switch (g.int(depth > 2 ? 7 : 10)) {
    case 0: return null;
    case 1: return undefined;
    case 2: return g.int(2) === 0;
    case 3: return g.pick(NUMBERS);
    case 4: return g.pick(WORDS);
    case 5: return text(g);
    case 6: return g.pick(["username", "password"]);
    case 7: return Array.from({ length: g.int(4) }, () => anything(g, depth + 1));
    case 8: return Object.fromEntries(Array.from({ length: g.int(5) }, () => [g.pick(KEYS), anything(g, depth + 1)]));
    // A key the page's own JSON can set, which an object literal cannot.
    default: return JSON.parse(`{"__proto__": {"type": "filled"}, "type": ${JSON.stringify(g.pick(["filled", "prepared", "waiting"]))}}`);
  }
}

/** One of `valid`, changed in a few ways: a field gone, added, or replaced. */
function changed(g: Generator, valid: Record<string, unknown>[]): unknown {
  const message: Record<string, unknown> = { ...g.pick(valid) };
  for (let change = g.int(4); change > 0; change--) {
    const keys = Object.keys(message);
    switch (g.int(6)) {
      case 0: if (keys.length) delete message[g.pick(keys)]; break;
      // Fields named twice, or not fields at all.
      case 5: message.fields = Array.from({ length: g.int(4) }, () => (g.int(3) ? g.pick(["username", "password"]) : anything(g))); break;
      case 1: message[g.pick(KEYS)] = anything(g); break;
      case 2: if (keys.length) message[g.pick(keys)] = anything(g); break;
      case 3: if (keys.length) message[g.pick(keys)] = g.pick(WORDS); break;
      default: return g.int(2) ? [message] : JSON.parse(JSON.stringify(message) ?? "null");
    }
  }
  return message;
}

function each(name: string, check: (g: Generator) => void) {
  test(name, () => {
    for (const seed of SEEDS) {
      const g = generator(seed);
      try {
        for (let index = 0; index < CASES; index++) check(g);
      } catch (error) {
        throw new Error(`seed ${seed}: ${(error as Error).message}`, { cause: error });
      }
    }
  });
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const keysAre = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).sort().join() === [...keys].sort().join();
const isField = (field: unknown) => field === "username" || field === "password";
const fieldsOnceEach = (fields: unknown) => Array.isArray(fields) && fields.every(isField) && new Set(fields).size === fields.length;

each("the page's script is believed only when it says what a page's script says", (g) => {
  const message = g.int(3) === 0 ? anything(g) : changed(g, [
    { type: "prepared", documentId: "8c5ad2a4-0f7c-4e7e-9a53-1f0e8a4e3b11", origin: "https://example.com", fields: ["username", "password"] },
    { type: "prepared", documentId: "d1", origin: "https://example.com", fields: [] },
    { type: "filled", fields: ["password"] },
    { type: "filled", fields: ["username", "password"] },
  ]);
  if (isPrepared(message)) {
    assert.ok(isObject(message) && message.type === "prepared", JSON.stringify(message));
    assert.match(message.documentId, /^[A-Za-z0-9-]{1,64}$/);
    assert.equal(typeof message.origin, "string");
    assert.ok(fieldsOnceEach(message.fields), JSON.stringify(message.fields));
  }
  if (isFilled(message)) {
    assert.ok(isObject(message) && message.type === "filled", JSON.stringify(message));
    assert.ok(fieldsOnceEach(message.fields), JSON.stringify(message.fields));
    // What the button then says names only those fields.
    assert.ok(message.fields.length <= 2);
  }
});

const request = fillRequest("request-1", 12, "document-1", "https://example.com");
const reply: FillReply = { type: "fill_reply", requestId: "request-1", tabId: 12, frameId: 0, documentId: "document-1", origin: "https://example.com", username: "alice", password: "correct horse" };

each("only a response exactly as specified is read from the host, and nothing in it is thrown at", (g) => {
  const message = g.int(3) === 0 ? anything(g) : changed(g, [
    reply as unknown as Record<string, unknown>,
    { type: "waiting", requestId: "request-1" },
    { type: "error", requestId: "request-1", code: "denied" },
    { type: "error", requestId: null, code: "invalid_message" },
  ]);
  const read = readResponse(message);
  if (read === null) return;
  assert.equal(read, message);
  assert.ok(isObject(read));
  assert.ok(JSON.stringify(read).length <= MAX_MESSAGE_BYTES);
  const strings = (...names: string[]) => names.every((name) => typeof (read as Record<string, unknown>)[name] === "string");
  switch (read.type) {
    case "waiting":
      assert.ok(keysAre(read, ["type", "requestId"]) && strings("requestId"), JSON.stringify(read));
      break;
    case "fill_reply":
      assert.ok(keysAre(read, ["type", "requestId", "tabId", "frameId", "documentId", "origin", "username", "password"]), JSON.stringify(read));
      assert.ok(strings("requestId", "documentId", "origin", "username", "password") && typeof read.tabId === "number" && typeof read.frameId === "number");
      break;
    case "error":
      assert.ok(keysAre(read, ["type", "requestId", "code"]) && strings("code") && (read.requestId === null || strings("requestId")), JSON.stringify(read));
      break;
    default:
      assert.fail(`read a response of type ${JSON.stringify((read as { type: unknown }).type)}`);
  }
});

each("a reply answers the request only when everything it names is the same", (g) => {
  const changes = changed(g, [reply as unknown as Record<string, unknown>]);
  if (!isObject(changes)) return;
  const candidate = { ...reply, ...changes } as FillReply;
  const same = (["requestId", "tabId", "frameId", "documentId", "origin"] as const).every((name) => Object.is(candidate[name], request[name]) || (candidate[name] === request[name]));
  assert.equal(answers(candidate, request), same, JSON.stringify(candidate));
});

each("a tab's address gives an origin only when it is an https page with no one's name in it", (g) => {
  const scheme = g.pick(["https://", "HTTPS://", "http://", "https:", "https:/", "file://", "javascript:", "data:text/html,", "blob:https://", "view-source:https://", " https://", ""]);
  const user = g.pick(["", "", "", "user@", "user:pass@", ":@", "@"]);
  const host = g.pick(["example.com", "EXAMPLE.com", "bücher.example", "127.0.0.1", "[::1]", "", "exa mple.com", "example.com.", "xn--bcher-kva.example", text(g)]);
  const port = g.pick(["", "", ":443", ":8443", ":0", ":65536", ":abc"]);
  const rest = g.pick(["", "/", "/login?next=/home#form", "#", "?@evil.example", "\\@evil.example", text(g)]);
  const address = g.int(10) === 0 ? text(g) : `${scheme}${user}${host}${port}${rest}`;
  const origin = pageOrigin(address);
  if (origin === null) return;
  const url = new URL(address);
  assert.equal(url.protocol, "https:", address);
  assert.equal(url.username + url.password, "", address);
  assert.equal(origin, url.origin, address);
  assert.ok(origin.startsWith("https://") && !origin.includes("@"), address);
});
