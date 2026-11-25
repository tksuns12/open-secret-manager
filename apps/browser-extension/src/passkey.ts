// What a page's call of WebAuthn and the extension's parts say to each
// other: the script in the page's own world (passkey-page.ts), the bridge
// beside it (passkey-bridge.ts), and the background. And how the options a
// page gives become WebAuthn's JSON, which the app reads. Nothing here
// touches a browser API, so it can be tested on its own. No secret passes
// through here: a passkey's key stays in the app, and what comes back is
// what the site is sent.

/** Marks the messages between the page's script and the bridge, on the page's window. */
export const CHANNEL = "osm-passkey";

/** Which call the page made. */
export type Kind = "create" | "get";

/** The page's script asks: WebAuthn's JSON of the call's options, and the page's own time limit in milliseconds. */
export type Ask = { channel: typeof CHANNEL; type: "ask"; id: string; kind: Kind; options: string; timeout: number | null };

/** The page's call was aborted. */
export type Withdraw = { channel: typeof CHANNEL; type: "withdraw"; id: string };

/** How a call ends: with the credential, as WebAuthn's JSON writes it; with an error the page's call throws; or left to the browser's own passkeys. */
export type Outcome =
  | { credential: string }
  | { error: "NotAllowedError" | "InvalidStateError" | "AbortError"; message: string }
  | { fallback: true; waitForFocus: boolean };

/** The bridge answers the page's script. */
export type Answer = { channel: typeof CHANNEL; type: "answer"; id: string; outcome: Outcome };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Request IDs as `crypto.randomUUID` makes them. */
const ID = /^[0-9a-f-]{36}$/;

export function isAsk(value: unknown): value is Ask {
  return isRecord(value) && value.channel === CHANNEL && value.type === "ask" && typeof value.id === "string" && ID.test(value.id)
    && (value.kind === "create" || value.kind === "get") && typeof value.options === "string"
    && (value.timeout === null || (typeof value.timeout === "number" && Number.isFinite(value.timeout)));
}

export function isWithdraw(value: unknown): value is Withdraw {
  return isRecord(value) && value.channel === CHANNEL && value.type === "withdraw" && typeof value.id === "string" && ID.test(value.id);
}

export function isOutcome(value: unknown): value is Outcome {
  if (!isRecord(value)) return false;
  if ("credential" in value) return Object.keys(value).length === 1 && typeof value.credential === "string";
  if ("error" in value) return Object.keys(value).length === 2 && ["NotAllowedError", "InvalidStateError", "AbortError"].includes(value.error as string) && typeof value.message === "string";
  return Object.keys(value).length === 2 && value.fallback === true && typeof value.waitForFocus === "boolean";
}

export function isAnswer(value: unknown): value is Answer {
  return isRecord(value) && value.channel === CHANNEL && value.type === "answer" && typeof value.id === "string" && isOutcome(value.outcome);
}

/** The browser's own passkeys answer: at once, or once the page has the focus back from the app's window. */
export const toBrowser = (waitForFocus = false): Outcome => ({ fallback: true, waitForFocus });

/** How the page's call ends when the app refused the request with `code`. */
export function outcomeOf(code: string): Outcome {
  switch (code) {
    case "denied": return { error: "NotAllowedError", message: "The request was turned down in Open Secret Manager." };
    case "expired": return { error: "NotAllowedError", message: "The request timed out in Open Secret Manager." };
    case "passkey_exists": return { error: "InvalidStateError", message: "Open Secret Manager already holds a passkey of this account for this site." };
    case "cancelled": return { error: "AbortError", message: "The request was withdrawn." };
    // The app's window took the focus: the browser asks once the page has it back.
    case "use_browser":
    case "busy": return toBrowser(true);
    // The app holds no passkey for the site, does not answer such a
    // request, is not running, or is too old to: the browser's own.
    default: return toBrowser(false);
  }
}

/** Bytes as base64url, without padding, as WebAuthn's JSON writes them. */
export function base64url(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unbase64url(text: string): Uint8Array<ArrayBuffer> {
  const plain = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(plain.length);
  for (let index = 0; index < plain.length; index += 1) bytes[index] = plain.charCodeAt(index);
  return bytes;
}

/** The bytes of a `BufferSource`, or an error for anything else. */
function bytesOf(value: unknown): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError("not a BufferSource");
}

/** A credential descriptor, as WebAuthn's JSON writes one. */
function descriptor(value: unknown): { type: string; id: string; transports?: string[] } {
  if (!isRecord(value) || typeof value.type !== "string") throw new TypeError("not a credential descriptor");
  return {
    type: value.type,
    id: base64url(bytesOf(value.id)),
    ...(Array.isArray(value.transports) ? { transports: value.transports.filter((transport): transport is string => typeof transport === "string") } : {}),
  };
}

/** Copies the named fields that are strings, numbers, or booleans. */
function plain(value: unknown, names: string[]): Record<string, string | number | boolean> {
  const copied: Record<string, string | number | boolean> = {};
  if (!isRecord(value)) return copied;
  for (const name of names) {
    const field = value[name];
    if (typeof field === "string" || typeof field === "number" || typeof field === "boolean") copied[name] = field;
  }
  return copied;
}

/**
 * The options of a page's `navigator.credentials.create`, as WebAuthn's
 * `PublicKeyCredentialCreationOptionsJSON` writes them. Only what the app
 * reads is kept; extensions are not, and the app answers none but the
 * passkey's properties. Throws for options it cannot read, which are then
 * the browser's own to answer.
 */
export function creationJSON(publicKey: unknown): string {
  if (!isRecord(publicKey) || !isRecord(publicKey.rp) || !isRecord(publicKey.user)) throw new TypeError("not creation options");
  const parameters = Array.isArray(publicKey.pubKeyCredParams) ? publicKey.pubKeyCredParams.map((parameter) => plain(parameter, ["type", "alg"])) : [];
  return JSON.stringify({
    rp: plain(publicKey.rp, ["id", "name"]),
    user: { id: base64url(bytesOf(publicKey.user.id)), ...plain(publicKey.user, ["name", "displayName"]) },
    challenge: base64url(bytesOf(publicKey.challenge)),
    pubKeyCredParams: parameters,
    ...(typeof publicKey.timeout === "number" ? { timeout: publicKey.timeout } : {}),
    excludeCredentials: Array.isArray(publicKey.excludeCredentials) ? publicKey.excludeCredentials.map(descriptor) : [],
    ...(isRecord(publicKey.authenticatorSelection) ? { authenticatorSelection: plain(publicKey.authenticatorSelection, ["authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"]) } : {}),
    ...(typeof publicKey.attestation === "string" ? { attestation: publicKey.attestation } : {}),
  });
}

/** The options of a page's `navigator.credentials.get`, as `PublicKeyCredentialRequestOptionsJSON` writes them; as [`creationJSON`]. */
export function requestJSON(publicKey: unknown): string {
  if (!isRecord(publicKey)) throw new TypeError("not request options");
  return JSON.stringify({
    challenge: base64url(bytesOf(publicKey.challenge)),
    ...(typeof publicKey.timeout === "number" ? { timeout: publicKey.timeout } : {}),
    ...(typeof publicKey.rpId === "string" ? { rpId: publicKey.rpId } : {}),
    allowCredentials: Array.isArray(publicKey.allowCredentials) ? publicKey.allowCredentials.map(descriptor) : [],
    ...(typeof publicKey.userVerification === "string" ? { userVerification: publicKey.userVerification } : {}),
  });
}

/**
 * Whether a page's call is one the app may answer: options for a passkey
 * only, of the page itself, made while the page is in front, and not one a
 * page makes to offer passkeys in its form's list (`conditional`), which
 * the browser's own list answers.
 */
export function isForTheApp(options: unknown): options is { publicKey: Record<string, unknown>; signal?: AbortSignal } {
  if (!isRecord(options) || !isRecord(options.publicKey)) return false;
  const others = Object.keys(options).filter((name) => !["publicKey", "signal", "mediation"].includes(name));
  return others.length === 0 && (options.mediation === undefined || options.mediation === "optional" || options.mediation === "required");
}

/** How long the extension waits for the owner: the page's own limit, between 10 seconds and 2 minutes. */
export function waitFor(timeout: number | null): number {
  return Math.min(120_000, Math.max(10_000, timeout ?? 120_000));
}

/**
 * Site/RP-level cooldown key for a passkey request so subdomain rotation
 * cannot bypass per-origin cooldowns or `no_passkey` limits. Uses an explicit
 * valid `rpId` / `rp.id` suffix of the origin's hostname when present, else
 * falls back to the last two labels (or hostname).
 */
export function siteKeyOf(origin: string, optionsJson?: string): string {
  let host = origin;
  try {
    host = new URL(origin).hostname.toLowerCase().replace(/\.+$/, "");
  } catch {
    return origin;
  }
  if (optionsJson) {
    try {
      const parsed: unknown = JSON.parse(optionsJson);
      if (isRecord(parsed)) {
        const candidate = typeof parsed.rpId === "string"
          ? parsed.rpId
          : isRecord(parsed.rp) && typeof parsed.rp.id === "string"
            ? parsed.rp.id
            : null;
        if (candidate) {
          const rp = candidate.trim().toLowerCase().replace(/\.+$/, "");
          if (rp && rp.includes(".") && (host === rp || host.endsWith(`.${rp}`))) {
            return `site:${rp}`;
          }
        }
      }
    } catch { /* fall through to hostname */ }
  }
  const labels = host.split(".").filter(Boolean);
  const site = labels.length >= 2 ? labels.slice(-2).join(".") : host;
  return `site:${site}`;
}
