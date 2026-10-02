// Put into a page's own document, and only its top one, when the owner
// asks for a fill there. It finds the login form, and later puts a user
// name and password into it. It never submits the form and shows nothing
// in the page. It runs apart from the page's scripts, which cannot read it.

import type { ToPage, FromPage } from "./page";

type Target = { username: HTMLInputElement | null; password: HTMLInputElement | null };

/** Names this document. A navigation loads another, with another name. */
const documentId = crypto.randomUUID();

/** An input the owner could type into now. */
function usable(element: Element | null): element is HTMLInputElement {
  return element instanceof HTMLInputElement
    && !element.disabled
    && !element.readOnly
    && element.getClientRects().length > 0;
}

function isPassword(input: HTMLInputElement): boolean {
  return input.type === "password";
}

function isName(input: HTMLInputElement): boolean {
  return input.type === "text" || input.type === "email" || input.type === "tel";
}

function looksLikeName(input: HTMLInputElement): boolean {
  return /username|email/i.test(input.autocomplete) || /user|email|login/i.test(`${input.name} ${input.id}`);
}

/** The fields of a login form among `inputs`, in document order. */
function among(inputs: HTMLInputElement[], focused: Element | null): Target | null {
  const fields = inputs.filter(usable);
  const password = (usable(focused) && isPassword(focused) ? focused : null) ?? fields.find(isPassword) ?? null;
  if (password) {
    // The user name is asked for just before the password.
    const before = fields.filter((input) => isName(input) && (input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0);
    return { username: before[before.length - 1] ?? null, password };
  }
  // A form that asks for the user name first and the password on a later page.
  const username = (usable(focused) && isName(focused) ? focused : null) ?? fields.find((input) => isName(input) && looksLikeName(input)) ?? null;
  return username ? { username, password: null } : null;
}

/** The login form the owner means: the one being typed into, else the first one in the page. */
function findTarget(): Target | null {
  const focused = document.activeElement;
  const form = focused instanceof HTMLInputElement ? focused.form : null;
  const inForm = form ? among(Array.from(form.elements).filter((element): element is HTMLInputElement => element instanceof HTMLInputElement), focused) : null;
  return inForm ?? among(Array.from(document.querySelectorAll("input")), focused);
}

/** Puts `value` into `input` the way typing would, so that the page notices. */
function put(input: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/** Whether this is the page itself, opened over https, and not a frame in another page. */
function isTopHttpsDocument(): boolean {
  return window.top === window && window.location.protocol === "https:";
}

// Done once per document: putting the script in again does nothing. The
// name stays where the extension can ask the browser for it later, to see
// that the tab still shows this document.
if (globalThis.osmFillDocument === undefined) {
  globalThis.osmFillDocument = documentId;
  // Each request has its own connection from the extension. It closes when
  // this document goes away, which is how the extension learns of that.
  chrome.runtime.onConnect.addListener((port) => {
    let target: Target | null = null;
    let used = false;
    const say = (message: FromPage) => port.postMessage(message);
    // A browser may keep a document it has left, for the Back button, and
    // with it this connection. Leaving ends the request all the same: the
    // connection is closed here, and nothing is filled into this document
    // afterwards even if it is shown again.
    window.addEventListener("pagehide", () => {
      used = true;
      target = null;
      port.disconnect();
    }, { once: true });
    port.onMessage.addListener((message: ToPage) => {
      if (message.type === "prepare") {
        target = isTopHttpsDocument() ? findTarget() : null;
        say({
          type: "prepared",
          documentId,
          origin: window.location.origin,
          fields: target ? [...(target.username ? ["username" as const] : []), ...(target.password ? ["password" as const] : [])] : [],
        });
        return;
      }
      if (message.type !== "fill") return;
      // One fill for one request, into the document it was asked for.
      const allowed = !used && target !== null && isTopHttpsDocument()
        && message.documentId === documentId && message.origin === window.location.origin;
      used = true;
      const filled: ("username" | "password")[] = [];
      if (allowed && target) {
        if (target.username?.isConnected && usable(target.username)) { put(target.username, message.username); filled.push("username"); }
        if (target.password?.isConnected && usable(target.password)) { put(target.password, message.password); filled.push("password"); }
      }
      target = null;
      say({ type: "filled", fields: filled });
    });
  });
}
