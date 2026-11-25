// Runs beside the page's script for passkeys (passkey-page.ts), in the
// extension's own world of the page itself, and only once the owner gave
// the extension access to all sites. It hands what the page's script asks
// to the background, over a connection of its own for each request, which
// the browser ties to this document: when the document goes, so does the
// request. It takes only messages the page's own window posted to its own
// origin, and answers only there. Whether the owner is using the page is
// asked here, of the browser, where the page cannot say otherwise.

import { CHANNEL, isAsk, isOutcome, isWithdraw, toBrowser, type Outcome } from "./passkey.ts";
import { MAX_PASSKEY_OPTIONS } from "./protocol.ts";

(() => {
  if (window.top !== window || location.protocol !== "https:" || self.origin !== location.origin) return;
  const origin = self.origin;
  const asking = new Map<string, chrome.runtime.Port>();
  const answer = (id: string, outcome: Outcome) => window.postMessage({ channel: CHANNEL, type: "answer", id, outcome }, origin);

  // Single-use trusted user gesture token in the isolated world so one click
  // or key press cannot trigger a burst of background passkey queries.
  const GESTURE_TTL_MS = 5_000;
  let gestureAt = 0;
  const markGesture = (event: Event) => {
    if (event.isTrusted) gestureAt = Date.now();
  };
  for (const kind of ["pointerdown", "keydown", "click"] as const) {
    window.addEventListener(kind, markGesture, { capture: true, passive: true });
  }

  window.addEventListener("message", (event) => {
    // Only the page's own window, not a frame in it, and only to this origin.
    if (event.source !== window || event.origin !== origin) return;
    const message: unknown = event.data;
    if (isWithdraw(message)) {
      asking.get(message.id)?.postMessage({ type: "withdraw" });
      return;
    }
    if (!isAsk(message) || asking.has(message.id)) return;
    const { id } = message;
    const now = Date.now();
    const freshGesture = gestureAt > 0 && now - gestureAt <= GESTURE_TTL_MS;
    // A call the owner did not just make in the visible, focused page is the
    // browser's own. Consume the gesture so one click serves at most one ask.
    if (
      document.visibilityState !== "visible"
      || !document.hasFocus()
      || !navigator.userActivation?.isActive
      || !freshGesture
      || message.options.length > MAX_PASSKEY_OPTIONS
    ) {
      answer(id, toBrowser());
      return;
    }
    gestureAt = 0;
    let port: chrome.runtime.Port;
    try {
      port = chrome.runtime.connect({ name: "passkey" });
    } catch {
      answer(id, toBrowser());
      return;
    }
    asking.set(id, port);
    port.onMessage.addListener((told: unknown) => {
      if (!asking.has(id) || !isOutcome(told)) return;
      asking.delete(id);
      port.disconnect();
      answer(id, told);
    });
    port.onDisconnect.addListener(() => {
      if (asking.delete(id)) answer(id, toBrowser());
    });
    port.postMessage({ type: "ask", kind: message.kind, options: message.options, timeout: message.timeout });
  });

  // Registered before the page's own scripts run, so a page cannot keep it
  // from hearing that the document goes.
  window.addEventListener("pagehide", () => {
    for (const port of asking.values()) port.disconnect();
    asking.clear();
  });
})();
