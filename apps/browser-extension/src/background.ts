// The extension's background: it acts only when the owner presses its
// toolbar button on a page. It then asks the desktop app, through the
// native messaging host, for a login for that page's origin, or for a card
// if the page has a card form, and puts the one the owner chooses there
// into the page. It holds no login or card before that and keeps none
// after, and never learns what the vault contains.

import { answers, answersCard, cancel, cardRequest, explain, fillRequest, GIVE_UP_AFTER_MS, MAX_CARD_FRAMES, NATIVE_HOST, pageOrigin, readResponse, type CardField, type CardFrame, type CardReply, type CardRequest, type CardValues, type FillReply, type FillRequest } from "./protocol";
import { isFilled, isFilledCard, isPrepared, type Field, type Prepared, type ToPage } from "./page";

/**
 * A request the owner has yet to decide in the app: a login's, with the
 * connection to the document it was made in, or a card's, with one to each
 * document it names.
 */
type Waiting = { tabId: number; giveUp: ReturnType<typeof setTimeout> } & (
  | { kind: "login"; request: FillRequest; page: chrome.runtime.Port }
  | { kind: "card"; request: CardRequest; pages: Map<number, chrome.runtime.Port> }
);

/** A document of the tab, connected to, and what its script found. */
type Document = { frameId: number; port: chrome.runtime.Port; found: Prepared };

type Mark = "waiting" | "filled" | "problem" | "none";

const TITLE = "Fill a login from Open Secret Manager";
const NOT_CONNECTED = "This browser is not connected to Open Secret Manager. In the app, open Browser and connect it.";
/** How long the page's script has to answer. */
const PAGE_ANSWERS_WITHIN_MS = 5_000;
/** How long the mark for a finished fill stays on the button. */
const FILLED_MARK_MS = 6_000;

/** How a card's fields are named to the owner. */
const CARD_FIELD_NAMES: Record<CardField, string> = {
  number: "number", cardholder: "cardholder's name", expiry: "expiry", expiry_month: "expiry month", expiry_year: "expiry year", security_code: "security code",
};

const waiting = new Map<string, Waiting>();
let host: chrome.runtime.Port | undefined;

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

/** The owner pressed the button on this tab. */
async function ask(tab: chrome.tabs.Tab) {
  const tabId = tab.id;
  if (tabId === undefined) return;
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
        const port = chrome.tabs.connect(tabId, { name: `${requestId}-${frameId}`, frameId });
        return { frameId, port, found: await prepared(port) };
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
  if (top.found.origin === "null") {
    release();
    show(tabId, "problem", "This page is sandboxed by its site and has no origin of its own, so no login can be filled into it.");
    return;
  }
  if (top.found.origin !== origin) {
    release();
    show(tabId, "problem", "The page changed while you asked. Try again.");
    return;
  }

  // A card form, when one of the documents asks for the number: each
  // document with a card's fields, as its own origin, which its script
  // reports and its page cannot change.
  const carded = documents
    .filter((document) => document.found.card.length > 0 && pageOrigin(`${document.found.origin}/`) === document.found.origin)
    .slice(0, MAX_CARD_FRAMES);
  if (carded.some((document) => document.found.card.includes("number"))) {
    release(carded.map((document) => document.frameId));
    const frames: CardFrame[] = carded.map((document) => ({ frameId: document.frameId, documentId: document.found.documentId, origin: document.found.origin, fields: document.found.card }));
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
    ? "This page's card number is in a frame of another site, which the extension cannot reach. Copy the number in Open Secret Manager."
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

/** Ends a request without a fill. `withdraw` tells the host, for a request the app may still be showing. */
function end(requestId: string, mark: Mark, text: string, withdraw: boolean) {
  const request = waiting.get(requestId);
  if (!request) return;
  waiting.delete(requestId);
  clearTimeout(request.giveUp);
  if (withdraw) {
    try { host?.postMessage(cancel(requestId)); } catch { /* the host is gone, which withdraws it too */ }
  }
  finish(request, mark, text);
}

function finish(request: Waiting, mark: Mark, text: string) {
  const pages = request.kind === "login" ? [request.page] : [...request.pages.values()];
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
    show(request.tabId, "waiting", `Waiting for you in Open Secret Manager. Choose a ${request.kind === "card" ? "card" : "login"} there.`);
    return;
  }
  if (response.type === "error") {
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

/** Ends the request made in a tab, when the browser says the tab is gone. */
function tabLeft(tabId: number) {
  for (const [requestId, request] of waiting) {
    if (request.tabId === tabId) end(requestId, "none", "", true);
  }
}

chrome.action.onClicked.addListener((tab) => { void ask(tab); });
chrome.tabs.onRemoved.addListener(tabLeft);
