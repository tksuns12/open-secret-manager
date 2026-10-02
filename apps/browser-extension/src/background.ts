// The extension's background: it acts only when the owner presses its
// toolbar button on a page. It then asks the desktop app, through the
// native messaging host, for a login for that page's origin, and puts the
// one the owner chooses there into the page. It holds no login before that
// and keeps none after, and never learns what the vault contains.

import { answers, cancel, explain, fillRequest, GIVE_UP_AFTER_MS, NATIVE_HOST, pageOrigin, readResponse, type FillReply, type FillRequest } from "./protocol";
import type { Field, FromPage, Prepared, ToPage } from "./page";

/** A request the owner has yet to decide in the app. */
type Waiting = {
  request: FillRequest;
  /** The connection to the document the request was made in. */
  page: chrome.runtime.Port;
  giveUp: ReturnType<typeof setTimeout>;
};

type Mark = "waiting" | "filled" | "problem" | "none";

const TITLE = "Fill a login from Open Secret Manager";
const NOT_CONNECTED = "This browser is not connected to Open Secret Manager. In the app, open Browser and connect it.";
/** How long the page's script has to answer. */
const PAGE_ANSWERS_WITHIN_MS = 5_000;
/** How long the mark for a finished fill stays on the button. */
const FILLED_MARK_MS = 6_000;

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

function isPrepared(message: unknown): message is Prepared {
  const value = message as Partial<Prepared> | null;
  return typeof value === "object" && value !== null && value.type === "prepared"
    && typeof value.documentId === "string" && /^[A-Za-z0-9-]{1,64}$/.test(value.documentId)
    && typeof value.origin === "string"
    && Array.isArray(value.fields) && value.fields.every((field) => field === "username" || field === "password");
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

/** The owner pressed the button on this tab. */
async function ask(tab: chrome.tabs.Tab) {
  const tabId = tab.id;
  if (tabId === undefined) return;
  // This tab's request is already waiting in the app.
  if ([...waiting.values()].some((other) => other.request.tabId === tabId)) return;
  // The address comes from the browser, not from the page.
  const origin = pageOrigin(tab.url);
  if (!origin) { show(tabId, "problem", "Only pages opened over https can be filled."); return; }

  const requestId = crypto.randomUUID();
  let page: chrome.runtime.Port;
  let found: Prepared;
  try {
    // Only the page's own document, never a frame inside it.
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
    page = chrome.tabs.connect(tabId, { name: requestId, frameId: 0 });
    found = await prepared(page);
  } catch {
    show(tabId, "problem", "This page cannot be filled.");
    return;
  }
  if (found.origin !== origin) {
    page.disconnect();
    show(tabId, "problem", "The page changed while you asked. Try again.");
    return;
  }
  if (found.fields.length === 0) {
    page.disconnect();
    show(tabId, "problem", "No login form was found on this page.");
    return;
  }

  const request = fillRequest(requestId, tabId, found.documentId, origin);
  const giveUp = setTimeout(() => end(requestId, "problem", "Open Secret Manager did not answer. Nothing was filled.", true), GIVE_UP_AFTER_MS);
  waiting.set(requestId, { request, page, giveUp });
  // The document went away: a navigation, a reload, or the tab closing.
  page.onDisconnect.addListener(() => end(requestId, "none", "", true));
  show(tabId, "waiting", "Asking Open Secret Manager…");
  try {
    connectHost().postMessage(request);
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
  try { request.page.disconnect(); } catch { /* already closed */ }
  show(request.request.tabId, mark, text);
  if (mark === "filled") setTimeout(() => show(request.request.tabId, "none", ""), FILLED_MARK_MS);
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
    show(request.request.tabId, "waiting", "Waiting for you in Open Secret Manager. Choose a login there.");
    return;
  }
  if (response.type === "error") {
    end(response.requestId, "problem", explain(response.code), false);
    return;
  }
  // A reply is used once, and only if it answers exactly this request.
  waiting.delete(response.requestId);
  clearTimeout(request.giveUp);
  if (!answers(response, request.request)) {
    finish(request, "problem", "The answer from Open Secret Manager was not for this page. Nothing was filled.");
    return;
  }
  void deliver(request, response);
}

/** Puts the owner's choice into the page, if the page is still the one that asked. */
async function deliver(request: Waiting, reply: FillReply) {
  const { tabId, origin } = request.request;
  // Asked of the browser again at the last moment.
  let current: string | null = null;
  try { current = pageOrigin((await chrome.tabs.get(tabId)).url); } catch { /* the tab is gone */ }
  // And which document the tab shows now: the script put into the one the
  // request was made in left that document's name there, and a document
  // loaded since has none. This is the browser's answer, not the page's.
  let shown: unknown = null;
  try {
    const [inTab] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: () => globalThis.osmFillDocument ?? null });
    shown = inTab?.result ?? null;
  } catch { /* the tab is gone, or is no longer one the extension may look at */ }
  if (current !== origin || shown !== request.request.documentId) {
    finish(request, "problem", "The page changed before the login arrived. Nothing was filled.");
    return;
  }
  const filled = await new Promise<Field[]>((resolve) => {
    const timer = setTimeout(() => resolve([]), PAGE_ANSWERS_WITHIN_MS);
    const done = (fields: Field[]) => { clearTimeout(timer); resolve(fields); };
    request.page.onDisconnect.addListener(() => done([]));
    request.page.onMessage.addListener((message: FromPage) => { if (message.type === "filled") done(message.fields); });
    try {
      request.page.postMessage({ type: "fill", documentId: reply.documentId, origin: reply.origin, username: reply.username, password: reply.password } satisfies ToPage);
    } catch {
      done([]);
    }
  });
  if (filled.length > 0) finish(request, "filled", `Filled the ${filled.join(" and ").replace("username", "user name")}. The form was not submitted.`);
  else finish(request, "problem", "The login form is gone. Nothing was filled.");
}

/** Ends the request made in a tab, when the browser says the tab is gone. */
function tabLeft(tabId: number) {
  for (const [requestId, request] of waiting) {
    if (request.request.tabId === tabId) end(requestId, "none", "", true);
  }
}

chrome.action.onClicked.addListener((tab) => { void ask(tab); });
chrome.tabs.onRemoved.addListener(tabLeft);
