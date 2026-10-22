// Runs in the page's own world, at the start of the page itself (never in
// a frame), and only once the owner gave the extension access to all sites
// on its options page. It puts Open Secret Manager in front of the
// browser's own passkeys: a page's call of `navigator.credentials.create`
// or `get` for a passkey goes to the app, through the bridge beside this
// script (passkey-bridge.ts); a call the app does not answer goes on to
// the browser's own, as if this script were not here.
//
// It holds no secret and decides nothing: the page could do here whatever
// this script does. What a page is given comes from the app, which checks
// the request against the page's origin as the browser reports it to the
// extension, not as this script says it.

import { CHANNEL, creationJSON, isAnswer, isForTheApp, requestJSON, unbase64url, type Kind, type Outcome } from "./passkey.ts";

type Credential = {
  id: string;
  rawId: string;
  authenticatorAttachment?: string | null;
  response: Record<string, unknown>;
  clientExtensionResults?: Record<string, unknown>;
};

(() => {
  // A sandboxed document has an origin of its own, not its address's.
  if (window.top !== window || location.protocol !== "https:" || self.origin !== location.origin) return;
  const container = globalThis.CredentialsContainer?.prototype;
  if (!container || typeof PublicKeyCredential === "undefined") return;
  const original = { create: container.create, get: container.get };
  const origin = self.origin;

  /** Asks the app, through the bridge, and waits for how the call ends. */
  function ask(kind: Kind, options: string, timeout: number | null, signal?: AbortSignal): Promise<Outcome> {
    const id = crypto.randomUUID();
    return new Promise((resolve) => {
      const heard = (event: MessageEvent) => {
        if (event.source !== window || !isAnswer(event.data) || event.data.id !== id) return;
        window.removeEventListener("message", heard);
        resolve(event.data.outcome);
      };
      window.addEventListener("message", heard);
      signal?.addEventListener("abort", () => window.postMessage({ channel: CHANNEL, type: "withdraw", id }, origin), { once: true });
      window.postMessage({ channel: CHANNEL, type: "ask", id, kind, options, timeout }, origin);
    });
  }

  /** Once the page has the focus, which the browser needs before it asks the owner itself. */
  function focused(): Promise<void> {
    return document.hasFocus() ? Promise.resolve() : new Promise((resolve) => window.addEventListener("focus", () => resolve(), { once: true }));
  }

  function buffer(text: unknown): ArrayBuffer | null {
    return typeof text === "string" ? unbase64url(text).buffer : null;
  }

  /** Defines each value as an own property, as a credential's are read. */
  function own<T extends object>(object: T, values: Record<string, unknown>): T {
    for (const [name, value] of Object.entries(values)) Object.defineProperty(object, name, { value, enumerable: true });
    return object;
  }

  /** What the page's call returns: a `PublicKeyCredential`, from the credential's JSON. */
  function credential(kind: Kind, json: Credential): PublicKeyCredential {
    const answered = json.response;
    const response = kind === "create"
      ? own(Object.create(AuthenticatorAttestationResponse.prototype), {
        clientDataJSON: buffer(answered.clientDataJSON),
        attestationObject: buffer(answered.attestationObject),
        getTransports: () => (Array.isArray(answered.transports) ? [...answered.transports] : []),
        getAuthenticatorData: () => buffer(answered.authenticatorData),
        getPublicKey: () => buffer(answered.publicKey),
        getPublicKeyAlgorithm: () => answered.publicKeyAlgorithm,
      })
      : own(Object.create(AuthenticatorAssertionResponse.prototype), {
        clientDataJSON: buffer(answered.clientDataJSON),
        authenticatorData: buffer(answered.authenticatorData),
        signature: buffer(answered.signature),
        userHandle: buffer(answered.userHandle),
      });
    return own(Object.create(PublicKeyCredential.prototype), {
      id: json.id,
      rawId: buffer(json.rawId),
      type: "public-key",
      authenticatorAttachment: json.authenticatorAttachment ?? null,
      response,
      getClientExtensionResults: () => structuredClone(json.clientExtensionResults ?? {}),
      toJSON: () => structuredClone(json),
    });
  }

  async function call(kind: Kind, self: CredentialsContainer, options?: CredentialCreationOptions | CredentialRequestOptions): Promise<Credential | null | unknown> {
    const goOn = () => (original[kind] as (options?: unknown) => Promise<unknown>).call(self, options);
    if (!isForTheApp(options)) return goOn();
    const signal = options.signal;
    if (signal?.aborted) throw signal.reason;
    let json: string;
    try {
      json = kind === "create" ? creationJSON(options.publicKey) : requestJSON(options.publicKey);
    } catch {
      return goOn();
    }
    const timeout = typeof options.publicKey.timeout === "number" ? options.publicKey.timeout : null;
    const outcome = await ask(kind, json, timeout, signal);
    if ("credential" in outcome) return credential(kind, JSON.parse(outcome.credential) as Credential);
    if ("error" in outcome) throw outcome.error === "AbortError" && signal?.aborted ? signal.reason : new DOMException(outcome.message, outcome.error);
    if (outcome.waitForFocus) await focused();
    return goOn();
  }

  // Methods named and shaped as the browser's own.
  const replacements = {
    create(this: CredentialsContainer, options?: CredentialCreationOptions) { return call("create", this, options); },
    get(this: CredentialsContainer, options?: CredentialRequestOptions) { return call("get", this, options); },
  };
  for (const name of ["create", "get"] as const) {
    Object.defineProperty(container, name, { value: replacements[name], writable: true, enumerable: true, configurable: true });
  }
})();
