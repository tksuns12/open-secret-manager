// What the extension and the native messaging host say to each other, and
// the checks the extension makes on what comes back. Nothing here touches a
// browser API, so it can be tested on its own.

/** The protocol version of a login's request and a withdrawal. */
export const VERSION = 1;

/** The protocol version of a card's request, which came later: an older app refuses it. */
export const CARD_VERSION = 2;

/** What a field of a card form asks for. */
export type CardField = "number" | "cardholder" | "expiry" | "expiry_month" | "expiry_year" | "security_code";

export const CARD_FIELDS: readonly CardField[] = ["number", "cardholder", "expiry", "expiry_month", "expiry_year", "security_code"];

/** The most documents of a tab one card request names. */
export const MAX_CARD_FRAMES = 8;

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

/** A document of the tab with a card's fields: the page itself (frame 0) or a frame in it. */
export type CardFrame = { frameId: number; documentId: string; origin: string; fields: CardField[] };

/** Asks for a card to be filled into the documents of one tab that have a card's fields. */
export type CardRequest = { type: "card_request"; version: number; requestId: string; tabId: number; topOrigin: string; frames: CardFrame[] };

/** A card's fields: only those some document asked for, the others empty. */
export type CardValues = { cardholder: string; number: string; expiryMonth: string; expiryYear: string; securityCode: string };

/** The card the owner chose, for the one request it answers. */
export type CardReply = { type: "card_reply"; requestId: string; tabId: number; topOrigin: string; frames: CardFrame[]; card: CardValues };

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

export type Response = Waiting | FillReply | Failure | CardReply;

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

export function cardRequest(requestId: string, tabId: number, topOrigin: string, frames: CardFrame[]): CardRequest {
  return { type: "card_request", version: CARD_VERSION, requestId, tabId, topOrigin, frames };
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

/** Whether `fields` names fields of a card form, each at most once, and at least one. */
export function areCardFields(fields: unknown): fields is CardField[] {
  return Array.isArray(fields) && fields.length > 0 && fields.every((field) => CARD_FIELDS.includes(field)) && new Set(fields).size === fields.length;
}

function isCardFrame(value: unknown): value is CardFrame {
  return isRecord(value) && Object.keys(value).length === 4 && typeof value.frameId === "number" && typeof value.documentId === "string"
    && typeof value.origin === "string" && areCardFields(value.fields);
}

function isCardValues(value: unknown): value is CardValues {
  return isRecord(value) && Object.keys(value).length === 5
    && ["cardholder", "number", "expiryMonth", "expiryYear", "securityCode"].every((name) => typeof value[name] === "string");
}

/** Reads a message from the host. Anything that is not exactly one of the
 * responses, or is larger than a message may be, is not one. */
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
    case "card_reply":
      return Object.keys(message).length === 6 && typeof message.requestId === "string" && typeof message.tabId === "number" && typeof message.topOrigin === "string"
        && Array.isArray(message.frames) && message.frames.every(isCardFrame) && isCardValues(message.card) ? (message as CardReply) : null;
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

/** Whether a card's reply answers exactly this request: the same request, tab, page, and documents, each with the same fields. */
export function answersCard(reply: CardReply, request: CardRequest): boolean {
  return reply.requestId === request.requestId
    && reply.tabId === request.tabId
    && reply.topOrigin === request.topOrigin
    && reply.frames.length === request.frames.length
    && reply.frames.every((frame, index) => {
      const asked = request.frames[index];
      return frame.frameId === asked.frameId && frame.documentId === asked.documentId && frame.origin === asked.origin
        && frame.fields.length === asked.fields.length && frame.fields.every((field, at) => field === asked.fields[at]);
    });
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
    case "unsupported_message":
    case "unsupported_version": return "Open Secret Manager on this computer does not fill cards yet. Update the app.";
    default: return "Open Secret Manager refused the request. Nothing was filled.";
  }
}
