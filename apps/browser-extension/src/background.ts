import { isAllowedDocument, MAX_MESSAGE_BYTES, type FillReply, type FillRequest, type HostMessage } from "./protocol";

const NATIVE_HOST = "org.opensecretmanager.native";
let host: chrome.runtime.Port | undefined;
const pending = new Map<string, (reply: FillReply | Error) => void>();
type NativeResponse = { type?: "fill_reply" | "error"; requestId?: string; origin?: string; username?: unknown; password?: unknown; totp?: unknown; code?: string };

function connectHost(): chrome.runtime.Port {
  if (host) return host;
  host = chrome.runtime.connectNative(NATIVE_HOST);
  host.onMessage.addListener((message: unknown) => {
    let encoded: string;
    try { encoded = JSON.stringify(message); } catch { return; }
    if (encoded.length > MAX_MESSAGE_BYTES) return;
    const value = message as NativeResponse;
    if (typeof value.requestId !== "string") return;
    if (value.type === "error") {
      pending.get(value.requestId)?.(new Error(typeof value.code === "string" ? value.code : "native host rejected request"));
      pending.delete(value.requestId);
      return;
    }
    if (value.type !== "fill_reply") return;
    pending.get(value.requestId)?.(value as FillReply);
    pending.delete(value.requestId);
  });
  host.onDisconnect.addListener(() => { host = undefined; for (const resolve of pending.values()) resolve(new Error("Native host disconnected")); pending.clear(); });
  return host;
}

async function requestFill(request: FillRequest): Promise<FillReply> {
  const port = connectHost();
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pending.delete(request.requestId);
      reject(new Error("native fill request expired"));
    }, 30_000);
    pending.set(request.requestId, (reply) => {
      clearTimeout(timeout);
      if (reply instanceof Error) return reject(reply);
      // The native response is one-use and must remain bound to the request's
      // exact origin. A host response with another origin is discarded before
      // any credential reaches a content script.
      if (reply.requestId !== request.requestId || reply.origin !== request.origin || !isAllowedDocument(reply.origin, request.frameOrigin, request.origin)) return reject(new Error("native response binding failed"));
      if (reply.username !== undefined && typeof reply.username !== "string") return reject(new Error("invalid username response"));
      if (reply.password !== undefined && typeof reply.password !== "string") return reject(new Error("invalid password response"));
      resolve(reply);
    });
    port.postMessage(request);
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "fill-selected", title: "Open Secret Manager: fill selected login", contexts: ["page", "editable"] });
});

chrome.contextMenus.onClicked.addListener(async (_info, tab) => {
  const tabId = tab?.id;
  const tabUrl = tab?.url;
  if (tabId === undefined || !tabUrl) return;
  let origin: string;
  try { origin = new URL(tabUrl).origin; } catch { return; }
  const requestId = crypto.randomUUID();
  try {
    const result = await chrome.tabs.sendMessage(tabId, { type: "select_fill", requestId }, { frameId: 0 });
    if (result?.cancelled || !result?.frameOrigin || !result.topOrigin || !result.documentId || !isAllowedDocument(origin, result.frameOrigin, result.topOrigin)) return;
    const reply = await requestFill({ type: "fill_request", requestId, origin, frameOrigin: result.frameOrigin, documentId: result.documentId, tabId, frameId: result.frameId ?? 0 });
    // Re-read the tab immediately before releasing any credential to content code.
    const current = await chrome.tabs.get(tabId);
    if (!current.url || new URL(current.url).origin !== origin) return;
    await chrome.tabs.sendMessage(tabId, { ...reply, type: "release_fill", requestId, expectedOrigin: origin, documentId: result.documentId }, { frameId: 0 });
  } catch {
    // Native host errors are intentionally silent; the page never receives a secret.
  }
});

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (!sender.tab?.id || !sender.tab.url) return false;
  const value = message as { type?: string; requestId?: string; frameOrigin?: string; topOrigin?: string; frameId?: number };
  if (value.type !== "selected_fill" || typeof value.requestId !== "string" || typeof value.frameOrigin !== "string" || typeof value.topOrigin !== "string") return false;
  const pageOrigin = new URL(sender.tab.url).origin;
  if (!isAllowedDocument(pageOrigin, value.frameOrigin, value.topOrigin)) return false;
  sendResponse({ ok: true, frameId: value.frameId ?? sender.frameId ?? 0 });
  return false;
});

export type { HostMessage };
