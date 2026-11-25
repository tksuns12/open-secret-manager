// The extension's background: it acts only when the owner presses its
// toolbar button on a page. It then asks the desktop app, through the
// native messaging host, for a login for that page's origin, or for a card
// if the page has a card form, and puts the one the owner chooses there
// into the page. It holds no login or card before that and keeps none
// after, and never learns what the vault contains.
//
// Once the owner gives it access to all sites on its options page, it also
// puts scripts into pages for passkeys (passkey-page.ts, passkey-bridge.ts),
// and hands a page's call for a passkey to the app, for the page's origin
// as the browser reports it; and it reaches a card form's frames of other
// sites.

import { answers, answersCard, answersPasskey, cancel, cardRequest, explain, fillRequest, GIVE_UP_AFTER_MS, MAX_CARD_FRAMES, MAX_PASSKEY_OPTIONS, NATIVE_HOST, pageOrigin, passkeyRequest, readResponse, type CardField, type CardFrame, type CardReply, type CardRequest, type CardValues, type FillReply, type FillRequest, type PasskeyRequest } from "./protocol";
import { isFilled, isFilledCard, isPrepared, type Field, type Prepared, type ToPage } from "./page";
import { outcomeOf, siteKeyOf, toBrowser, waitFor, type Outcome } from "./passkey";

/**
 * A request the owner has yet to decide in the app: a login's, with the
 * connection to the document it was made in, or a card's, with one to each
 * document it names.
 */
type Waiting = { tabId: number; giveUp: ReturnType<typeof setTimeout> } & (
  | { kind: "login"; request: FillRequest; page: chrome.runtime.Port }
  | { kind: "card"; request: CardRequest; pages: Map<number, chrome.runtime.Port> }
  | { kind: "passkey"; request: PasskeyRequest; page: chrome.runtime.Port }
);

/** A document of the tab, connected to, and what its script found. */
type Document = { frameId: number; port: chrome.runtime.Port; found: Prepared; attested: string | "null" | null };

type PendingFillPort = {
  tabId: number;
  frameId: number;
  resolve: (connected: { port: chrome.runtime.Port; attested: string | "null" | null }) => void;
};

type Mark = "waiting" | "filled" | "problem" | "none";

const TITLE = "Fill a login from Open Secret Manager";
const NOT_CONNECTED = "This browser is not connected to Open Secret Manager. In the app, open Browser and connect it.";
/** How long the page's script has to answer. */
const PAGE_ANSWERS_WITHIN_MS = 5_000;
/** How long the mark for a finished fill stays on the button. */
const FILLED_MARK_MS = 6_000;
/** How long a site's requests for passkeys go to the browser's own after the owner turned one down, or let it run out. */
const PASSKEY_PAUSE_MS = 60_000;
/** How many silent `no_passkey` responses in a window trigger a per-origin/site cooldown. */
const NO_PASSKEY_LIMIT = 3;
const NO_PASSKEY_WINDOW_MS = 60_000;
const SESSION_STATE_KEY = "osmPasskeyThrottle";
/** The access the owner gives on the options page: every https site, which is all the extension ever serves. */
const ALL_SITES = ["https://*/*"];

/** How a card's fields are named to the owner. */
const CARD_FIELD_NAMES: Record<CardField, string> = {
  number: "number", cardholder: "cardholder's name", expiry: "expiry", expiry_month: "expiry month", expiry_year: "expiry year", security_code: "security code",
};

const waiting = new Map<string, Waiting>();
let host: chrome.runtime.Port | undefined;
/** Until when each origin or site's requests for passkeys are the browser's own. */
const paused = new Map<string, number>();
/** Recent `no_passkey` response timestamps per origin and site, to bound probing. */
const noPasskeyHits = new Map<string, number[]>();
/** Reverse-connect handshakes waiting for content scripts to connect back. */
const pendingFillPorts = new Map<string, PendingFillPort>();

function sessionStorageArea(): chrome.storage.StorageArea | undefined {
  return (chrome.storage as { session?: chrome.storage.StorageArea } | undefined)?.session;
}

/** Loads persisted cooldown state on service-worker wake so restarts cannot reset throttling. */
const throttleReady: Promise<void> = (async () => {
  const area = sessionStorageArea();
  if (!area) return;
  try {
    const stored = await area.get(SESSION_STATE_KEY);
    const saved = stored?.[SESSION_STATE_KEY] as { paused?: Record<string, number>; hits?: Record<string, number[]> } | undefined;
    const now = Date.now();
    if (saved?.paused && typeof saved.paused === "object") {
      for (const [key, until] of Object.entries(saved.paused)) {
        if (typeof until === "number" && until > now) paused.set(key, until);
      }
    }
    if (saved?.hits && typeof saved.hits === "object") {
      for (const [key, list] of Object.entries(saved.hits)) {
        if (Array.isArray(list)) {
          const recent = list.filter((at): at is number => typeof at === "number" && now - at < NO_PASSKEY_WINDOW_MS);
          if (recent.length > 0) noPasskeyHits.set(key, recent);
        }
      }
    }
  } catch { /* in-memory fallback */ }
})();

function saveThrottle() {
  const area = sessionStorageArea();
  if (!area) return;
  const now = Date.now();
  const pausedObj: Record<string, number> = {};
  for (const [key, until] of paused) {
    if (until > now) pausedObj[key] = until;
    else paused.delete(key);
  }
  const hitsObj: Record<string, number[]> = {};
  for (const [key, list] of noPasskeyHits) {
    const recent = list.filter((at) => now - at < NO_PASSKEY_WINDOW_MS);
    if (recent.length > 0) {
      noPasskeyHits.set(key, recent);
      hitsObj[key] = recent;
    } else {
      noPasskeyHits.delete(key);
    }
  }
  void area.set({ [SESSION_STATE_KEY]: { paused: pausedObj, hits: hitsObj } }).catch(() => {});
}

function throttleKeys(origin: string, options?: string): [string, string] {
  return [origin, siteKeyOf(origin, options)];
}

function isPasskeyPaused(origin: string, options?: string): boolean {
  const now = Date.now();
  return throttleKeys(origin, options).some((key) => (paused.get(key) ?? 0) > now);
}

function pausePasskey(origin: string, options?: string) {
  const until = Date.now() + PASSKEY_PAUSE_MS;
  for (const key of throttleKeys(origin, options)) paused.set(key, until);
  saveThrottle();
}

function recordNoPasskeyHit(origin: string, options?: string) {
  const now = Date.now();
  let exceeded = false;
  for (const key of throttleKeys(origin, options)) {
    const recent = (noPasskeyHits.get(key) ?? []).filter((at) => now - at < NO_PASSKEY_WINDOW_MS);
    recent.push(now);
    noPasskeyHits.set(key, recent);
    if (recent.length >= NO_PASSKEY_LIMIT) exceeded = true;
  }
  if (exceeded) {
    for (const key of throttleKeys(origin, options)) paused.set(key, now + PASSKEY_PAUSE_MS);
  }
  saveThrottle();
}

/** Says on the toolbar button, for one tab, how its request stands. */
function show(tabId: number, mark: Mark, text: string) {
  const badge = { waiting: "…", filled: "✓", problem: "!", none: "" }[mark];
  const color = mark === "problem" ? "#b3402a" : "#8d673a";
  // The tab may be gone by now; then there is nobody to tell.
  void chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
  void chrome.action.setBadgeText({ tabId, text: badge }).catch(() => {});
  void chrome.action.setTitle({ tabId, title: text ? `${TITLE}\n${text}` : TITLE }).catch(() => {});
}

/** "a, b, and c", as a sentence names several things. */
function listed(names: string[]): string {
  return names.length <= 2 ? names.join(" and ") : `${names.slice(0, -1).join(", ")}, and ${names[names.length - 1]}`;
}

/** What the page's script found, once it says. */
function prepared(page: chrome.runtime.Port): Promise<Prepared> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("the page did not answer")), PAGE_ANSWERS_WITHIN_MS);
    page.onDisconnect.addListener(() => { clearTimeout(timer); reject(new Error("the page went away")); });
    page.onMessage.addListener((message: unknown) => {
      if (!isPrepared(message)) return;
      clearTimeout(timer);
      resolve(message);
    });
    page.postMessage({ type: "prepare" } satisfies ToPage);
  });
}

/**
 * Puts the page's script into every document of the tab the extension may
 * reach, the page itself and the frames of its origin, and says which. Its
 * press gives it the page's origin only; frames of another origin are not
 * reached.
 */
async function reachable(tabId: number): Promise<number[]> {
  try {
    const injected = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ["content.js"] });
    const frames = [...new Set(injected.map((result) => result.frameId))];
    if (frames.includes(0)) return frames;
  } catch { /* a browser that refuses for a frame it may not reach: the page itself, then */ }
  await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
  return [0];
}

/** The origin the browser process attests for a connected frame's sender. */
function attestedOrigin(sender: chrome.runtime.MessageSender | undefined): string | "null" | null {
  if (!sender) return null;
  if (sender.origin === "null") return "null";
  const fromUrl = pageOrigin(sender.url);
  if (!fromUrl) return null;
  if (sender.origin !== undefined && sender.origin !== fromUrl) return null;
  return fromUrl;
}

/** Completes a reverse-connect handshake initiated by `connectFrame`. */
function acceptFillPort(port: chrome.runtime.Port) {
  const pending = pendingFillPorts.get(port.name);
  if (!pending || port.sender?.tab?.id !== pending.tabId || port.sender?.frameId !== pending.frameId) {
    try { port.disconnect(); } catch { /* already closed */ }
    return;
  }
  pendingFillPorts.delete(port.name);
  pending.resolve({ port, attested: attestedOrigin(port.sender) });
}

/** Asks `frameId` in `tabId` to open a connection back so `port.sender` is browser-attested. */
function connectFrame(tabId: number, requestId: string, frameId: number): Promise<{ port: chrome.runtime.Port; attested: string | "null" | null }> {
  const portName = `fill:${requestId}:${frameId}`;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingFillPorts.delete(portName);
      reject(new Error("the page did not connect"));
    }, PAGE_ANSWERS_WITHIN_MS);
    pendingFillPorts.set(portName, {
      tabId,
      frameId,
      resolve: (connected) => {
        clearTimeout(timer);
        resolve(connected);
      },
    });
    void chrome.tabs.sendMessage(tabId, { type: "connect", name: portName }, { frameId }).catch(() => {
      if (pendingFillPorts.delete(portName)) {
        clearTimeout(timer);
        reject(new Error("the page could not be reached"));
      }
    });
  });
}

/** The owner pressed the button on this tab. */
async function ask(tab: chrome.tabs.Tab) {
  const tabId = tab.id;
  if (tabId === undefined) return;
  // A page's own call for a passkey gives way to the owner's press, and
  // goes on to the browser's own passkeys.
  for (const [requestId, other] of waiting) {
    if (other.tabId === tabId && other.kind === "passkey") end(requestId, "none", "", true, toBrowser(true));
  }
  // This tab's request is already waiting in the app.
  if ([...waiting.values()].some((other) => other.tabId === tabId)) return;
  // The address comes from the browser, not from the page.
  const origin = pageOrigin(tab.url);
  if (!origin) { show(tabId, "problem", "Only pages opened over https can be filled."); return; }

  const requestId = crypto.randomUUID();
  let documents: Document[];
  try {
    const frames = await reachable(tabId);
    documents = (await Promise.all(frames.map(async (frameId) => {
      try {
        const { port, attested } = await connectFrame(tabId, requestId, frameId);
        return { frameId, port, found: await prepared(port), attested };
      } catch {
        return null;
      }
    }))).filter((document): document is Document => document !== null);
  } catch {
    show(tabId, "problem", "This page cannot be filled.");
    return;
  }
  /** Lets go of the documents a request does not name. */
  const release = (kept: number[] = []) => {
    for (const document of documents) if (!kept.includes(document.frameId)) document.port.disconnect();
  };
  const top = documents.find((document) => document.frameId === 0);
  if (!top) {
    release();
    show(tabId, "problem", "This page cannot be filled.");
    return;
  }
  if (top.attested === "null" || top.found.origin === "null") {
    release();
    show(tabId, "problem", "This page is sandboxed by its site and has no origin of its own, so no login can be filled into it.");
    return;
  }
  if (top.attested !== origin || top.found.origin !== origin) {
    release();
    show(tabId, "problem", "The page changed while you asked. Try again.");
    return;
  }

  // A card form, when one of the documents asks for the number: each
  // document with a card's fields, verified against the browser-attested
  // `port.sender` origin.
  const carded = documents
    .filter((document): document is Document & { attested: string } =>
      document.found.card.length > 0
      && typeof document.attested === "string"
      && document.attested !== "null"
      && document.attested === document.found.origin
      && pageOrigin(`${document.attested}/`) === document.attested)
    .slice(0, MAX_CARD_FRAMES);
  if (carded.some((document) => document.found.card.includes("number"))) {
    const otherOrigins = new Set(carded.map((document) => document.attested).filter((frameOrigin) => frameOrigin !== origin));
    if (otherOrigins.size > 1) {
      release();
      show(tabId, "problem", "This page has card fields from more than one other site. Nothing was filled.");
      return;
    }
    const seenFields = new Set<CardField>();
    for (const document of carded) {
      for (const field of document.found.card) {
        if (seenFields.has(field)) {
          release();
          show(tabId, "problem", "This page has more than one card form. Nothing was filled.");
          return;
        }
        seenFields.add(field);
      }
    }
    release(carded.map((document) => document.frameId));
    const frames: CardFrame[] = carded.map((document) => ({ frameId: document.frameId, documentId: document.found.documentId, origin: document.attested, fields: document.found.card }));
    const pages = new Map(carded.map((document) => [document.frameId, document.port]));
    begin(requestId, { kind: "card", request: cardRequest(requestId, tabId, origin, frames), pages, tabId, giveUp: giveUp(requestId) });
    // A document went away: a navigation, a reload, or the tab closing.
    for (const port of pages.values()) port.onDisconnect.addListener(() => end(requestId, "none", "", true));
    return;
  }
  if (top.found.fields.length > 0) {
    release([0]);
    begin(requestId, { kind: "login", request: fillRequest(requestId, tabId, top.found.documentId, origin), page: top.port, tabId, giveUp: giveUp(requestId) });
    top.port.onDisconnect.addListener(() => end(requestId, "none", "", true));
    return;
  }
  release();
  show(tabId, "problem", carded.length > 0
    ? "This page's card number is in a frame of another site, which the extension cannot reach. Give it access to all sites in its options, or copy the number in Open Secret Manager."
    : "No login form or card form was found on this page.");
}

function giveUp(requestId: string): ReturnType<typeof setTimeout> {
  return setTimeout(() => end(requestId, "problem", "Open Secret Manager did not answer. Nothing was filled.", true), GIVE_UP_AFTER_MS);
}

/** Sends a request to the app, through the host. */
function begin(requestId: string, request: Waiting) {
  waiting.set(requestId, request);
  show(request.tabId, "waiting", "Asking Open Secret Manager…");
  try {
    connectHost().postMessage(request.request);
  } catch {
    end(requestId, "problem", NOT_CONNECTED, false);
  }
}

/** The host's process, started by the browser when first needed. */
function connectHost(): chrome.runtime.Port {
  if (host) return host;
  const port = chrome.runtime.connectNative(NATIVE_HOST);
  port.onMessage.addListener(fromHost);
  port.onDisconnect.addListener(() => {
    // The browser says why: no host is registered for it, the host does not
    // allow this extension, or the host's process ended. Firefox says it on
    // the connection itself, Chromium beside it.
    const reason = (port as { error?: { message?: string } | null }).error?.message ?? chrome.runtime.lastError?.message ?? "";
    if (host === port) host = undefined;
    const text = /not found|forbidden|no such native application/i.test(reason) ? NOT_CONNECTED : "The connection to Open Secret Manager was lost. Nothing was filled.";
    for (const requestId of [...waiting.keys()]) end(requestId, "problem", text, false);
  });
  host = port;
  return port;
}

/** Lets the host's process end once nothing waits for it. */
function releaseHost() {
  if (waiting.size > 0 || !host) return;
  const port = host;
  host = undefined;
  port.disconnect();
}

/**
 * Ends a request without a fill. `withdraw` tells the host, for a request
 * the app may still be showing. A page's call for a passkey ends as
 * `outcome` says, or else goes on to the browser's own passkeys.
 */
function end(requestId: string, mark: Mark, text: string, withdraw: boolean, outcome?: Outcome) {
  const request = waiting.get(requestId);
  if (!request) return;
  waiting.delete(requestId);
  clearTimeout(request.giveUp);
  if (withdraw) {
    try { host?.postMessage(cancel(requestId)); } catch { /* the host is gone, which withdraws it too */ }
  }
  finish(request, mark, text, outcome);
}

function finish(request: Waiting, mark: Mark, text: string, outcome?: Outcome) {
  if (request.kind === "passkey") {
    try { request.page.postMessage(outcome ?? toBrowser()); } catch { /* the page went away */ }
  }
  const pages = request.kind === "card" ? [...request.pages.values()] : [request.page];
  for (const page of pages) {
    try { page.disconnect(); } catch { /* already closed */ }
  }
  show(request.tabId, mark, text);
  if (mark === "filled") setTimeout(() => show(request.tabId, "none", ""), FILLED_MARK_MS);
  releaseHost();
}

function fromHost(message: unknown) {
  const response = readResponse(message);
  if (!response || response.requestId === null) return;
  // A response for a request that is not waiting is dropped: one that was
  // never made, one that ended, and a reply that comes a second time.
  const request = waiting.get(response.requestId);
  if (!request) return;
  if (response.type === "waiting") {
    show(request.tabId, "waiting", request.kind === "passkey"
      ? "The page asks for a passkey. Choose in Open Secret Manager how to answer it."
      : `Waiting for you in Open Secret Manager. Choose a ${request.kind === "card" ? "card" : "login"} there.`);
    return;
  }
  if (response.type === "error") {
    if (request.kind === "passkey") {
      // A request the owner turned down, deferred to the browser, or let run
      // out is not asked again at once: the site may not nag across subdomains.
      if (response.code === "denied" || response.code === "expired" || response.code === "use_browser") {
        pausePasskey(request.request.origin, request.request.options);
      }
      if (response.code === "no_passkey") {
        recordNoPasskeyHit(request.request.origin, request.request.options);
      }
      end(response.requestId, response.code === "denied" ? "problem" : "none", response.code === "denied" ? "You turned down the page's request for a passkey." : "", false, outcomeOf(response.code));
      return;
    }
    end(response.requestId, "problem", explain(response.code), false);
    return;
  }
  // A reply is used once, and only if it answers exactly this request.
  waiting.delete(response.requestId);
  clearTimeout(request.giveUp);
  if (response.type === "fill_reply" && request.kind === "login" && answers(response, request.request)) {
    void deliver(request, response);
  } else if (response.type === "card_reply" && request.kind === "card" && answersCard(response, request.request)) {
    void deliverCard(request, response);
  } else if (response.type === "passkey_reply" && request.kind === "passkey" && answersPasskey(response, request.request)) {
    void deliverPasskey(request, response.credential);
  } else {
    finish(request, "problem", "The answer from Open Secret Manager was not for this page. Nothing was filled.");
  }
}

/**
 * Which document the browser says a frame of the tab shows now: the script
 * put into the one the request was made in left that document's name
 * there, and a document loaded since has none. This is the browser's
 * answer, not the page's.
 */
async function documentIn(tabId: number, frameId: number): Promise<unknown> {
  try {
    const [inTab] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, func: () => globalThis.osmFillDocument ?? null });
    return inTab?.result ?? null;
  } catch {
    // The tab is gone, or is no longer one the extension may look at.
    return null;
  }
}

/** The page's origin now, asked of the browser at the last moment. */
async function originNow(tabId: number): Promise<string | null> {
  try { return pageOrigin((await chrome.tabs.get(tabId)).url); } catch { return null; }
}

/** Puts the owner's choice into the page, if the page is still the one that asked. */
async function deliver(request: Waiting & { kind: "login" }, reply: FillReply) {
  const { tabId, origin } = request.request;
  if (await originNow(tabId) !== origin || await documentIn(tabId, 0) !== request.request.documentId) {
    finish(request, "problem", "The page changed before the login arrived. Nothing was filled.");
    return;
  }
  const filled = await new Promise<Field[]>((resolve) => {
    const timer = setTimeout(() => resolve([]), PAGE_ANSWERS_WITHIN_MS);
    const done = (fields: Field[]) => { clearTimeout(timer); resolve(fields); };
    request.page.onDisconnect.addListener(() => done([]));
    // Only an answer that names fields of a form, each once, is believed.
    request.page.onMessage.addListener((message: unknown) => { if (isFilled(message)) done(message.fields); });
    try {
      request.page.postMessage({ type: "fill", documentId: reply.documentId, origin: reply.origin, username: reply.username, password: reply.password } satisfies ToPage);
    } catch {
      done([]);
    }
  });
  if (filled.length > 0) finish(request, "filled", `Filled the ${filled.join(" and ").replace("username", "user name")}. The form was not submitted.`);
  else finish(request, "problem", "The login form is gone. Nothing was filled.");
}

/** A card's values for one document: only those of the fields it found. */
function forDocument(card: CardValues, fields: CardField[]): CardValues {
  const has = (...wanted: CardField[]) => wanted.some((field) => fields.includes(field));
  return {
    cardholder: has("cardholder") ? card.cardholder : "",
    number: has("number") ? card.number : "",
    expiryMonth: has("expiry_month", "expiry") ? card.expiryMonth : "",
    expiryYear: has("expiry_year", "expiry") ? card.expiryYear : "",
    securityCode: has("security_code") ? card.securityCode : "",
  };
}

/** Puts the owner's card into each document of the page that asked, if the page still shows each. */
async function deliverCard(request: Waiting & { kind: "card" }, reply: CardReply) {
  const { tabId, topOrigin, frames } = request.request;
  const shown = await Promise.all(frames.map((frame) => documentIn(tabId, frame.frameId)));
  if (await originNow(tabId) !== topOrigin || frames.some((frame, index) => shown[index] !== frame.documentId)) {
    finish(request, "problem", "The page changed before the card arrived. Nothing was filled.");
    return;
  }
  const filled = new Set<CardField>();
  await Promise.all(frames.map((frame) => new Promise<void>((resolve) => {
    const page = request.pages.get(frame.frameId);
    if (!page) { resolve(); return; }
    const timer = setTimeout(resolve, PAGE_ANSWERS_WITHIN_MS);
    const done = () => { clearTimeout(timer); resolve(); };
    page.onDisconnect.addListener(done);
    // Only an answer that names fields of a card form, each once, and only
    // those the document was asked for, is believed.
    page.onMessage.addListener((message: unknown) => {
      if (!isFilledCard(message)) return;
      for (const field of message.fields) if (frame.fields.includes(field)) filled.add(field);
      done();
    });
    try {
      page.postMessage({ type: "fill_card", documentId: frame.documentId, origin: frame.origin, card: forDocument(reply.card, frame.fields) } satisfies ToPage);
    } catch {
      done();
    }
  })));
  const names = (Object.keys(CARD_FIELD_NAMES) as CardField[]).filter((field) => filled.has(field)).map((field) => CARD_FIELD_NAMES[field]);
  if (names.length > 0) finish(request, "filled", `Filled the card's ${listed(names)}. The form was not submitted.`);
  else finish(request, "problem", "The card form is gone. Nothing was filled.");
}

/** Hands the page the credential, if access is still granted and the tab still shows a page of the origin that asked. */
async function deliverPasskey(request: Waiting & { kind: "passkey" }, credential: string) {
  const granted = await chrome.permissions.contains({ origins: ALL_SITES }).catch(() => false);
  if (!granted) {
    finish(request, "none", "", toBrowser());
    return;
  }
  if (await originNow(request.tabId) !== request.request.origin) {
    finish(request, "problem", "The page changed before the passkey's answer arrived. Nothing was sent.");
    return;
  }
  finish(request, "filled", "Open Secret Manager answered the page's request for a passkey.", { credential });
}

/** Whether the bridge's first message is a request: a call, its options as WebAuthn's JSON, and the page's time limit. */
function isBridgeAsk(message: unknown): message is { type: "ask"; kind: "create" | "get"; options: string; timeout: number | null } {
  if (typeof message !== "object" || message === null) return false;
  const asked = message as Record<string, unknown>;
  return asked.type === "ask" && (asked.kind === "create" || asked.kind === "get") && typeof asked.options === "string"
    && asked.options.length > 0 && asked.options.length <= MAX_PASSKEY_OPTIONS && (asked.timeout === null || typeof asked.timeout === "number");
}

/**
 * A page's call for a passkey, from the bridge in the page. The page's
 * origin is the browser's: what it reports for the connection's sender,
 * which must be the page itself, of an https address, and the origin of
 * both that document's address and the tab's. One request per tab, and
 * none from a site while it is paused or after all-sites access is revoked;
 * anything else goes on to the browser's own passkeys.
 */
function servePasskey(port: chrome.runtime.Port) {
  const sender = port.sender;
  const tabId = sender?.tab?.id;
  const origin = sender?.origin ?? pageOrigin(sender?.url);
  const refuse = () => {
    try { port.postMessage(toBrowser()); port.disconnect(); } catch { /* the page went away */ }
  };
  if (tabId === undefined || sender?.frameId !== 0 || !origin || origin === "null" || pageOrigin(sender.url) !== origin || pageOrigin(sender.tab?.url) !== origin) {
    refuse();
    return;
  }
  let requestId: string | null = null;
  let requestOptions: string | undefined;
  let starting = false;
  let disconnected = false;
  port.onMessage.addListener((message: unknown) => {
    if (requestId !== null) {
      // The page's call was aborted: throttle repeat nag loops on withdraw too.
      if ((message as { type?: unknown } | null)?.type === "withdraw") {
        pausePasskey(origin, requestOptions);
        end(requestId, "none", "", true, outcomeOf("cancelled"));
      }
      return;
    }
    if (starting) return;
    if (!isBridgeAsk(message)) {
      refuse();
      return;
    }
    starting = true;
    void (async () => {
      await throttleReady;
      const granted = await chrome.permissions.contains({ origins: ALL_SITES }).catch(() => false);
      if (
        disconnected
        || !granted
        || [...waiting.values()].some((other) => other.tabId === tabId)
        || isPasskeyPaused(origin, message.options)
      ) {
        if (!disconnected) refuse();
        return;
      }
      const id = crypto.randomUUID();
      requestId = id;
      requestOptions = message.options;
      const giveUp = setTimeout(() => {
        pausePasskey(origin, message.options);
        end(id, "none", "", true, outcomeOf("expired"));
      }, waitFor(message.timeout));
      begin(id, { kind: "passkey", request: passkeyRequest(message.kind, id, tabId, origin, message.options), page: port, tabId, giveUp });
    })();
  });
  // The document went: a navigation, a reload, or the tab closing.
  port.onDisconnect.addListener(() => {
    disconnected = true;
    if (requestId !== null) end(requestId, "none", "", true);
  });
}

/** The scripts for passkeys, put into the page itself of every https page once the owner gives access to all sites. */
const PASSKEY_SCRIPTS = [
  { id: "passkey-page", js: ["passkey-page.js"], matches: ["https://*/*"], runAt: "document_start", world: "MAIN", allFrames: false, persistAcrossSessions: true },
  { id: "passkey-bridge", js: ["passkey-bridge.js"], matches: ["https://*/*"], runAt: "document_start", world: "ISOLATED", allFrames: false, persistAcrossSessions: true },
] satisfies chrome.scripting.RegisteredContentScript[];

/** Brings the scripts for passkeys in line with the access the owner gave, one change at a time. */
let following: Promise<void> = Promise.resolve();
function followAccess() {
  following = following.then(async () => {
    const granted = await chrome.permissions.contains({ origins: ALL_SITES });
    if (!granted) {
      for (const [requestId, request] of [...waiting]) {
        if (request.kind === "passkey") end(requestId, "none", "", true, toBrowser());
      }
    }
    const registered = await chrome.scripting.getRegisteredContentScripts({ ids: PASSKEY_SCRIPTS.map((script) => script.id) });
    if (granted && registered.length === PASSKEY_SCRIPTS.length) return;
    if (registered.length > 0) await chrome.scripting.unregisterContentScripts({ ids: registered.map((script) => script.id) });
    if (granted) await chrome.scripting.registerContentScripts(PASSKEY_SCRIPTS);
  }).catch(() => { /* tried again at the next change or start */ });
}

/** Ends the request made in a tab, when the browser says the tab navigated or closed. */
function tabLeft(tabId: number) {
  for (const [requestId, request] of waiting) {
    if (request.tabId === tabId) end(requestId, "none", "", true);
  }
}

chrome.action.onClicked.addListener((tab) => { void ask(tab); });
chrome.tabs.onRemoved.addListener(tabLeft);
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading" || changeInfo.url !== undefined) tabLeft(tabId);
});
chrome.tabs.onReplaced.addListener((_addedTabId, removedTabId) => tabLeft(removedTabId));
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === "passkey") {
    servePasskey(port);
  } else if (port.name.startsWith("fill:")) {
    acceptFillPort(port);
  } else {
    try { port.disconnect(); } catch { /* already closed */ }
  }
});
chrome.permissions.onAdded.addListener(followAccess);
chrome.permissions.onRemoved.addListener(followAccess);
chrome.runtime.onInstalled.addListener(followAccess);
chrome.runtime.onStartup.addListener(followAccess);
followAccess();
