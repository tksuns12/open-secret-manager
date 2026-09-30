export const MAX_MESSAGE_BYTES = 64 * 1024;

export type FillRequest = {
  type: "fill_request";
  requestId: string;
  origin: string;
  frameOrigin: string;
  documentId: string;
  tabId: number;
  frameId: number;
};

export type FillReply = {
  type: "fill_reply";
  requestId: string;
  origin: string;
  username?: string;
  password?: string;
  totp?: string;
};

export type HostMessage = FillRequest | { type: "cancel"; requestId: string };

export function isAllowedDocument(origin: string, frameOrigin: string, topOrigin: string): boolean {
  // URL parsing rejects opaque origins such as data:, about:blank, and file:.
  try {
    const page = new URL(origin);
    const frame = new URL(frameOrigin);
    const top = new URL(topOrigin);
    return page.protocol === "https:" && frame.protocol === "https:" && top.protocol === "https:" && page.origin === frame.origin && page.origin === top.origin;
  } catch {
    return false;
  }
}

export function exactOriginMatches(expected: string, current: string): boolean {
  try {
    const wanted = new URL(expected);
    const actual = new URL(current);
    return wanted.protocol === "https:" && actual.protocol === "https:" && wanted.origin === actual.origin;
  } catch {
    return false;
  }
}
