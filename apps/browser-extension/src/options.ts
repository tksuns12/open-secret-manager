// The extension's options: one switch, the access to all sites that
// passkeys and a card form's frames of other sites need. The browser asks
// the owner when it is turned on; the background follows what was granted
// (see followAccess in background.ts).

const ALL_SITES = { origins: ["<all_urls>"] };
const box = document.getElementById("all-sites") as HTMLInputElement;
const state = document.getElementById("state") as HTMLElement;

async function shown() {
  box.checked = await chrome.permissions.contains(ALL_SITES);
  state.textContent = box.checked ? "On: the extension has access to all sites." : "Off: the extension has access only to the page you press its button on.";
}

box.addEventListener("change", () => {
  // Asked for in the owner's click, as the browser requires.
  const asked = box.checked ? chrome.permissions.request(ALL_SITES) : chrome.permissions.remove(ALL_SITES);
  void asked.catch(() => false).finally(() => { void shown(); });
});
chrome.permissions.onAdded.addListener(() => { void shown(); });
chrome.permissions.onRemoved.addListener(() => { void shown(); });
void shown();
