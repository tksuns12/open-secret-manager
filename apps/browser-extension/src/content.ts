// Put into a page's documents, the page itself and the frames in it the
// extension may reach, when the owner asks for a fill there. It finds the
// login form (in the page itself only) and a card form's fields, and later
// puts a user name and password, or a card, into them. It never submits a
// form and shows nothing in the page. It runs apart from the page's
// scripts, which cannot read it.

import type { ToPage, FromPage } from "./page";
import { CARD_FIELDS, type CardField, type CardValues } from "./protocol";

type Target = { username: HTMLInputElement | null; password: HTMLInputElement | null };

/** Names this document. A navigation loads another, with another name. */
const documentId = crypto.randomUUID();

/** An input or select the owner can see and type into now. */
function isVisibleControl(element: CardElement): boolean {
  if (element.disabled || (element instanceof HTMLInputElement && element.readOnly)) return false;
  if (window.innerWidth < 4 || window.innerHeight < 4) return false;
  if (element.getClientRects().length === 0) return false;
  const box = element.getBoundingClientRect();
  if (box.width < 4 || box.height < 4) return false;
  const check = (element as { checkVisibility?: (options: object) => boolean }).checkVisibility;
  if (check && !check.call(element, { opacityProperty: true, visibilityProperty: true, checkOpacity: true, checkVisibilityCSS: true })) {
    return false;
  }
  let visLeft = box.left;
  let visTop = box.top;
  let visRight = box.right;
  let visBottom = box.bottom;
  let opacity = 1;
  let current: Element | null = element;
  while (current) {
    const style = getComputedStyle(current);
    if (style.display === "none" || style.visibility !== "visible") return false;
    const value = Number(style.opacity);
    if (Number.isFinite(value)) opacity *= value;
    if (opacity < 0.1) return false;
    const clipPath = style.clipPath;
    if (
      clipPath
      && clipPath !== "none"
      && (
        /^inset\(\s*(?:[5-9]\d|100)%/.test(clipPath)
        || /^circle\(\s*0(?:px|%)?\b/.test(clipPath)
        || /^polygon\(\s*0(?:px)?\s+0(?:px)?\s*\)/.test(clipPath)
      )
    ) {
      return false;
    }
    if (style.clip === "rect(0px, 0px, 0px, 0px)") return false;
    if (
      current !== element
      && (style.overflowX === "hidden" || style.overflowX === "clip" || style.overflowY === "hidden" || style.overflowY === "clip")
    ) {
      const parentBox = current.getBoundingClientRect();
      if (style.overflowX === "hidden" || style.overflowX === "clip") {
        visLeft = Math.max(visLeft, parentBox.left);
        visRight = Math.min(visRight, parentBox.right);
      }
      if (style.overflowY === "hidden" || style.overflowY === "clip") {
        visTop = Math.max(visTop, parentBox.top);
        visBottom = Math.min(visBottom, parentBox.bottom);
      }
      if (visRight - visLeft < 4 || visBottom - visTop < 4) return false;
    }
    const root: Node | null = current.parentElement
      ?? (current.getRootNode() instanceof ShadowRoot ? (current.getRootNode() as ShadowRoot).host : null);
    current = root instanceof Element ? root : null;
  }
  if (visRight < 4 || visBottom < 4) return false;
  if (window.top !== window) {
    const frameVisLeft = Math.max(visLeft, 0);
    const frameVisTop = Math.max(visTop, 0);
    const frameVisRight = Math.min(visRight, window.innerWidth);
    const frameVisBottom = Math.min(visBottom, window.innerHeight);
    if (frameVisRight - frameVisLeft < 4 || frameVisBottom - frameVisTop < 4) return false;
    try {
      const frame = window.frameElement;
      if (frame instanceof Element) {
        const frameBox = frame.getBoundingClientRect();
        const frameStyle = getComputedStyle(frame);
        if (
          frameBox.width < 4
          || frameBox.height < 4
          || frameStyle.display === "none"
          || frameStyle.visibility !== "visible"
          || Number(frameStyle.opacity) < 0.1
        ) {
          return false;
        }
      }
    } catch { /* cross-origin iframe */ }
  }
  return true;
}

/** An input the owner could type into now. */
function usable(element: Element | null): element is HTMLInputElement {
  return element instanceof HTMLInputElement && isVisibleControl(element);
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

/** A card form's fields in this document, by what each asks for, in document order. */
type CardTarget = Map<CardField, CardElement[]>;
type CardElement = HTMLInputElement | HTMLSelectElement;

/** What a page's `autocomplete` says of a card's field. */
const CC_AUTOCOMPLETE: Record<string, CardField> = {
  "cc-number": "number", "cc-name": "cardholder", "cc-exp": "expiry", "cc-exp-month": "expiry_month", "cc-exp-year": "expiry_year", "cc-csc": "security_code",
};
/** What else an `autocomplete` may say without saying the field is something else. */
const SAYS_NOTHING = /^(on|off|shipping|billing|section-.*)$/;
/** The kinds of input a card's field can be. */
const CARD_INPUTS = new Set(["", "text", "tel", "number", "password"]);
// In a name, anywhere; Korean words take particles after them.
const CODE_PARTS = ["cvc", "cvv", "csc", "securitycode", "security_code", "security-code", "cardcode", "card_code", "보안코드", "보안 코드"];
const NUMBER_PARTS = ["cardnumber", "card_number", "card-number", "cardno", "card_no", "ccnumber", "cc_number", "ccnum", "카드번호", "카드 번호"];
const EXPIRY_PARTS = ["expir", "유효기간", "만료"];
const HOLDER_PARTS = ["cardholder", "card_holder", "card-holder", "nameoncard", "name_on_card", "holdername", "holder_name", "카드소유자", "소유자", "명의"];

/** The words of a name, `cardNumber` and `card_number` alike giving `card` and `number`. */
function wordsOf(name: string): string[] {
  return name.replace(/(\p{Ll})(\p{Lu})/gu, "$1 $2").toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
}

/** What a field of a card form asks for, by its `autocomplete`, or else by its names, as the Android app reads a field. */
function cardFieldOf(element: CardElement): CardField | null {
  const tokens = (element.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
  const said = tokens.map((token) => CC_AUTOCOMPLETE[token]).find(Boolean);
  if (said) return said;
  // A field that says it is something else, as an email address, is not a card's.
  if (tokens.some((token) => !SAYS_NOTHING.test(token))) return null;
  const names = [element.name, element.id, element.getAttribute("placeholder") ?? "", element.getAttribute("aria-label") ?? "",
    ...Array.from(element.labels ?? [], (label) => label.textContent ?? "")].filter(Boolean);
  const words = new Set(names.flatMap(wordsOf));
  const has = (parts: string[]) => names.some((name) => parts.some((part) => name.toLowerCase().includes(part)));
  const card = words.has("card") || words.has("cc");
  if (has(CODE_PARTS) || (card && words.has("cid"))) return "security_code";
  if (has(NUMBER_PARTS) || (card && ["number", "num", "no"].some((word) => words.has(word)))) return "number";
  if (
    has(EXPIRY_PARTS)
    || (words.has("exp") && (card || has(["month", "year", "월", "년", "valid", "thru"]) || words.has("mm") || words.has("yy") || words.has("yyyy")))
  ) {
    if (has(["month", "월"]) || words.has("mm")) return "expiry_month";
    if (has(["year", "년"]) || words.has("yy") || words.has("yyyy")) return "expiry_year";
    return "expiry";
  }
  if (has(HOLDER_PARTS) || (card && words.has("name"))) return "cardholder";
  return null;
}

/**
 * A card's field the owner can see and change now: enabled, drawn with a
 * size, and not hidden by its style or an ancestor's. A page cannot hide a
 * second field to have the security code beside the number.
 */
function shown(element: CardElement): boolean {
  return isVisibleControl(element);
}

/** The card form's fields in this document, if it has any. */
function findCard(): CardTarget {
  const found: CardTarget = new Map();
  for (const element of Array.from(document.querySelectorAll("input, select"))) {
    if (!(element instanceof HTMLSelectElement) && !(element instanceof HTMLInputElement && CARD_INPUTS.has(element.type))) continue;
    if (!shown(element)) continue;
    const field = cardFieldOf(element);
    if (field) found.set(field, [...(found.get(field) ?? []), element]);
  }
  return found;
}

/** Chooses the option of `select` whose text or value is `value`, or whose first number is one of `numbers`, the way choosing it would, so that the page notices. */
function choose(select: HTMLSelectElement, value: string, numbers: number[] = []): boolean {
  const options = Array.from(select.options);
  const first = (text: string) => Number(/\d+/.exec(text)?.[0] ?? NaN);
  const option = options.find((candidate) => candidate.value === value || candidate.text.trim() === value)
    ?? options.find((candidate) => numbers.includes(first(candidate.text)) || numbers.includes(first(candidate.value)));
  if (!option) return false;
  const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set;
  if (setter) setter.call(select, option.value);
  else select.value = option.value;
  select.dispatchEvent(new Event("input", { bubbles: true }));
  select.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

/** Puts `value` into a card's field. Nothing for an empty value. */
function putCard(element: CardElement, value: string, numbers: number[] = []): boolean {
  if (!value) return false;
  if (element instanceof HTMLSelectElement) return choose(element, value, numbers);
  put(element, value);
  return true;
}

/** Fills the card form's fields with `card`, as each takes it. Says which were filled. */
function fillCard(target: CardTarget, card: CardValues): CardField[] {
  const month = Number(card.expiryMonth);
  const fullYear = Number(card.expiryYear) < 100 ? 2000 + Number(card.expiryYear) : Number(card.expiryYear);
  const mm = card.expiryMonth ? String(month).padStart(2, "0") : "";
  const yy = card.expiryYear ? String(fullYear % 100).padStart(2, "0") : "";
  const yyyy = card.expiryYear ? String(fullYear) : "";
  const filled: CardField[] = [];
  for (const field of CARD_FIELDS) {
    const elements = (target.get(field) ?? []).filter((element) => element.isConnected && shown(element));
    const [element] = elements;
    if (!element) continue;
    let done = false;
    switch (field) {
      case "number": {
        // Whole in one field, or in turn over a split-PAN group in the same
        // container and form (at most 4 short inputs, maxLength <= 6).
        const splitPan = elements.length > 1 && elements.length <= 4
          && elements.every((part) => part instanceof HTMLInputElement && part.maxLength > 0 && part.maxLength <= 6 && part.form === element.form && part.parentElement === element.parentElement);
        const targets = splitPan ? elements : [element];
        let at = 0;
        targets.forEach((part, index) => {
          const length = index === targets.length - 1 ? card.number.length - at : part instanceof HTMLInputElement && part.maxLength > 0 ? part.maxLength : 4;
          if (putCard(part, card.number.slice(at, at + length))) done = true;
          at += length;
        });
        break;
      }
      case "cardholder": done = putCard(element, card.cardholder); break;
      case "security_code": done = putCard(element, card.securityCode); break;
      case "expiry_month": done = putCard(element, mm, [month]); break;
      case "expiry_year": done = putCard(element, element instanceof HTMLInputElement && element.maxLength === 2 ? yy : yyyy, [fullYear, fullYear % 100]); break;
      case "expiry": {
        if (!mm || !yy) break;
        const length = element instanceof HTMLInputElement ? element.maxLength : -1;
        const long = /yyyy/i.test(element.getAttribute("placeholder") ?? "");
        const text = length === 4 ? `${mm}${yy}` : length === 6 ? `${mm}${yyyy}` : length === 7 || (long && length !== 5) ? `${mm}/${yyyy}` : `${mm}/${yy}`;
        done = putCard(element, text);
        break;
      }
    }
    if (done) filled.push(field);
  }
  return filled;
}

/** Whether this document, the page itself or a frame in it, was opened over https and has the origin of its address. */
function isHttpsDocument(): boolean {
  return window.location.protocol === "https:" && self.origin === window.location.origin;
}

/**
 * Whether this is the page itself, opened over https, with the origin of its
 * address, and not a frame in another page. A page its site serves
 * sandboxed (`Content-Security-Policy: sandbox`) has the site's address but
 * an origin of its own, which no login is for.
 */
function isTopHttpsDocument(): boolean {
  return window.top === window && window.location.protocol === "https:" && self.origin === window.location.origin;
}

function attachPort(port: chrome.runtime.Port) {
  let target: Target | null = null;
  let card: CardTarget | null = null;
  let used = false;
  const say = (message: FromPage) => port.postMessage(message);
  // A browser may keep a document it has left, for the Back button, and
  // with it this connection. Leaving ends the request all the same: the
  // connection is closed here, and nothing is filled into this document
  // afterwards even if it is shown again.
  window.addEventListener("pagehide", () => {
    used = true;
    target = null;
    card = null;
    port.disconnect();
  }, { once: true });
  port.onMessage.addListener((message: ToPage) => {
    if (message.type === "prepare") {
      target = isTopHttpsDocument() ? findTarget() : null;
      card = isHttpsDocument() ? findCard() : null;
      const found = card;
      say({
        type: "prepared",
        documentId,
        origin: self.origin,
        fields: target ? [...(target.username ? ["username" as const] : []), ...(target.password ? ["password" as const] : [])] : [],
        card: found ? CARD_FIELDS.filter((field) => found.has(field)) : [],
      });
      return;
    }
    if (message.type === "fill_card") {
      // One fill for one request, into the document it was asked for.
      const allowed = !used && card !== null && isHttpsDocument()
        && message.documentId === documentId && message.origin === self.origin;
      used = true;
      const filled = allowed && card ? fillCard(card, message.card) : [];
      card = null;
      say({ type: "filled_card", fields: filled });
      return;
    }
    if (message.type !== "fill") return;
    // One fill for one request, into the document it was asked for.
    const allowed = !used && target !== null && isTopHttpsDocument()
      && message.documentId === documentId && message.origin === self.origin;
    used = true;
    const filled: ("username" | "password")[] = [];
    if (allowed && target) {
      if (target.username?.isConnected && usable(target.username)) { put(target.username, message.username); filled.push("username"); }
      if (target.password?.isConnected && usable(target.password)) { put(target.password, message.password); filled.push("password"); }
    }
    target = null;
    say({ type: "filled", fields: filled });
  });
}

// Done once per document: putting the script in again does nothing. The
// name stays where the extension can ask the browser for it later, to see
// that the tab still shows this document.
if (globalThis.osmFillDocument === undefined) {
  globalThis.osmFillDocument = documentId;
  // The background asks this document to open its own connection back so
  // that the browser process attests `port.sender` (tab, frame, origin, url).
  chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return;
    if (
      typeof message === "object"
      && message !== null
      && (message as { type?: unknown }).type === "connect"
      && typeof (message as { name?: unknown }).name === "string"
      && (message as { name: string }).name.startsWith("fill:")
    ) {
      const port = chrome.runtime.connect({ name: (message as { name: string }).name });
      attachPort(port);
      sendResponse({ ok: true });
    }
  });
}
