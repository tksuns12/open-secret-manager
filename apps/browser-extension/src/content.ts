import { exactOriginMatches, isAllowedDocument, type FillReply } from "./protocol";

type SelectMessage = { type: "select_fill"; requestId: string };
type ReleaseMessage = Omit<FillReply, "type"> & { type: "release_fill"; expectedOrigin: string; documentId: string };
const marker = "data-osm-fill-ui";
const documentId = crypto.randomUUID();
let approvedGrant: { requestId: string; origin: string; documentId: string; expiresAt: number } | null = null;

function documentOrigins(): { origin: string; topOrigin: string } | null {
  try {
    const origin = window.location.origin;
    const topOrigin = window.top?.location.origin ?? "null";
    if (!isAllowedDocument(origin, origin, topOrigin)) return null;
    return { origin, topOrigin };
  } catch { return null; }
}

function focusedForm(): HTMLFormElement | null {
  const element = document.activeElement;
  return element instanceof HTMLInputElement ? element.form : element instanceof HTMLFormElement ? element : element?.closest("form") ?? null;
}

function removePrompt() { document.querySelector(`[${marker}]`)?.remove(); }

function showPrompt(requestId: string, respond: (response: unknown) => void) {
  removePrompt();
  const origins = documentOrigins();
  if (!origins) { respond({ cancelled: true }); return; }
  const form = focusedForm();
  const prompt = document.createElement("div");
  prompt.setAttribute(marker, "true");
  prompt.style.cssText = "position:fixed;z-index:2147483647;right:18px;bottom:18px;padding:12px 14px;border:1px solid #c98b43;border-radius:8px;background:#201912;color:#f6e5cc;font:12px system-ui;box-shadow:0 8px 28px #0008";
  prompt.innerHTML = `<strong>Open Secret Manager</strong><div style="margin-top:5px;opacity:.75">Choose a matching login to fill this page.</div><button data-osm-ok style="margin-top:9px;padding:6px 9px;border:0;border-radius:5px;background:#dda45b;color:#201912">Continue</button><button data-osm-cancel style="margin-left:5px;padding:6px 9px;border:0;border-radius:5px;background:transparent;color:#dbc6aa">Cancel</button>`;
  prompt.querySelector("[data-osm-ok]")?.addEventListener("click", () => {
    const current = documentOrigins();
    if (!current || !form || !isAllowedDocument(origins.origin, window.location.origin, origins.topOrigin)) { respond({ cancelled: true }); return removePrompt(); }
    approvedGrant = { requestId, origin: current.origin, documentId, expiresAt: Date.now() + 30_000 };
    respond({ frameOrigin: current.origin, topOrigin: current.topOrigin, documentId, frameId: 0 });
    void chrome.runtime.sendMessage({ type: "selected_fill", requestId, frameOrigin: origins.origin, topOrigin: origins.topOrigin, frameId: 0 });
    removePrompt();
  });
  prompt.querySelector("[data-osm-cancel]")?.addEventListener("click", () => { respond({ cancelled: true }); removePrompt(); });
  document.documentElement.append(prompt);
}

chrome.runtime.onMessage.addListener((message: SelectMessage | ReleaseMessage, _sender, sendResponse) => {
  if (message.type === "select_fill") {
    const origins = documentOrigins();
    if (!origins) return false;
    showPrompt(message.requestId, sendResponse);
    return true;
  }
  if (message.type === "release_fill") {
    const origins = documentOrigins();
    // Recheck both the origin and the document before assigning credentials.
    if (!origins || !exactOriginMatches(message.expectedOrigin, origins.origin) || !approvedGrant || approvedGrant.requestId !== message.requestId || approvedGrant.documentId !== message.documentId || approvedGrant.expiresAt < Date.now()) return false;
    approvedGrant = null;
    const form = focusedForm();
    if (!form) return false;
    const password = Array.from(form.elements).find((field): field is HTMLInputElement => field instanceof HTMLInputElement && field.type === "password");
    const username = Array.from(form.elements).find((field): field is HTMLInputElement => field instanceof HTMLInputElement && /user|email|login/i.test(`${field.name} ${field.autocomplete}`));
    if (username && message.username !== undefined) username.value = message.username;
    if (password && message.password !== undefined) password.value = message.password;
    // No submit event is generated. TOTP is deliberately not auto-filled in alpha.
    return false;
  }
  return false;
});

window.addEventListener("pagehide", () => { approvedGrant = null; removePrompt(); });
