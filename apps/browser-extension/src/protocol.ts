// What the extension and the native messaging host say to each other, and
// the checks the extension makes on what comes back. Nothing here touches a
// browser API, so it can be tested on its own.

/** The protocol version every message to the host names. */
export const VERSION = 1;

/** The name the browser knows the native messaging host by. */
export const NATIVE_HOST = "org.opensecretmanager.native";

/** The largest message either side sends. */
export const MAX_MESSAGE_BYTES = 64 * 1024;

/** How long the extension waits before it withdraws a request itself. The
 * app gives the owner two minutes; this is only for an app that went quiet. */
export const GIVE_UP_AFTER_MS = 150_000;

/** Asks for a login to be filled into one document of one tab. */
export type FillRequest = {
  type: "fill_request";
  version: number;
  requestId: string;
  tabId: number;
  /** Always 0, the page itself: frames inside a page are not filled. */
  frameId: number;
  /** Names the document the request was made in; a navigation makes another. */
  documentId: string;
  /** The page's origin, as the browser reports it for the tab. */
  origin: string;
};

export type Cancel = { type: "cancel"; version: number; requestId: string };

/** The owner has not decided yet. */
export type Waiting = { type: "waiting"; requestId: string };

/** The login the owner chose, for the one request it answers. */
export type FillReply = {
  type: "fill_reply";
  requestId: string;
  tabId: number;
  frameId: number;
  documentId: string;
  origin: string;
  username: string;
  password: string;
};

/** The request ended without a login. */
export type Failure = { type: "error"; requestId: string | null; code: string };

export type Response = Waiting | FillReply | Failure;

/** The origin of a tab's address, if that address is an https page. Any
 * other page, and a tab whose address the browser does not tell, has none. */
export function pageOrigin(address: string | undefined): string | null {
  if (!address) return null;
  try {
    const url = new URL(address);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    return url.origin;
  } catch {
    return null;
  }
}

export function fillRequest(requestId: string, tabId: number, documentId: string, origin: string): FillRequest {
  return { type: "fill_request", version: VERSION, requestId, tabId, frameId: 0, documentId, origin };
}

/** Withdraws a request whose page went away. */
export function cancel(requestId: string): Cancel {
  return { type: "cancel", version: VERSION, requestId };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Whether `value` has exactly the fields named, each a string or a number as said. */
function hasExactly(value: Record<string, unknown>, fields: Record<string, "string" | "number">): boolean {
  const names = Object.keys(fields);
  return Object.keys(value).length === names.length + 1 && names.every((name) => typeof value[name] === fields[name]);
}

/** Reads a message from the host. Anything that is not exactly one of the
 * three responses, or is larger than a message may be, is not one. */
export function readResponse(message: unknown): Response | null {
  if (!isRecord(message)) return null;
  let size: number;
  try { size = JSON.stringify(message).length; } catch { return null; }
  if (size > MAX_MESSAGE_BYTES) return null;
  switch (message.type) {
    case "waiting":
      return hasExactly(message, { requestId: "string" }) ? (message as Waiting) : null;
    case "fill_reply":
      return hasExactly(message, { requestId: "string", tabId: "number", frameId: "number", documentId: "string", origin: "string", username: "string", password: "string" }) ? (message as FillReply) : null;
    case "error":
      return Object.keys(message).length === 3 && typeof message.code === "string" && (message.requestId === null || typeof message.requestId === "string") ? (message as Failure) : null;
    default:
      return null;
  }
}

/** Whether a reply answers exactly this request: the same request, tab,
 * frame, document, and origin. Only such a reply is filled. */
export function answers(reply: FillReply, request: FillRequest): boolean {
  return reply.requestId === request.requestId
    && reply.tabId === request.tabId
    && reply.frameId === request.frameId
    && reply.documentId === request.documentId
    && reply.origin === request.origin;
}

/** What to tell the owner when a request ended without a login. */
export function explain(code: string): string {
  switch (code) {
    case "denied": return "You denied this request in Open Secret Manager. Nothing was filled.";
    case "expired": return "The request ran out of time in Open Secret Manager. Nothing was filled.";
    case "cancelled": return "The request was withdrawn. Nothing was filled.";
    case "busy": return "Another request is waiting in Open Secret Manager. Decide that one first.";
    case "desktop_session_unavailable": return "Open Secret Manager is not running. Open the app and try again.";
    case "extension_not_allowed": return "Open Secret Manager does not accept this extension.";
    case "origin_rejected":
    case "frame_rejected": return "This page cannot be filled.";
    default: return "Open Secret Manager refused the request. Nothing was filled.";
  }
}
