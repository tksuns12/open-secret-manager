// The window's items and the panels used every day, driven as the owner
// would, in the browser preview.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { edges, SMALLEST_SIZE, start, titles } from "./harness.mjs";

let window;
before(async () => {
  window = await start();
});
after(async () => {
  await window?.stop();
});

const toast = (page) => page.locator(".toast");

test("the list shows the vault's items, and the search and the filters narrow it", async () => {
  const { page, errors } = await window.open();
  assert.deepEqual(await titles(page), ["Proton Mail", "GitHub", "Banking — checking", "Recovery codes", "Studio Wi-Fi", "Everyday card"]);
  await page.getByLabel("Search vault").fill("git");
  assert.deepEqual(await titles(page), ["GitHub"]);
  await page.getByLabel("Search vault").fill("nothing like it");
  await page.getByText("No matching items").waitFor();
  await page.getByLabel("Search vault").fill("");
  await page.getByRole("navigation", { name: "Vault filters" }).getByRole("button", { name: /Favorites/ }).click();
  assert.deepEqual(await titles(page), ["Proton Mail", "GitHub"]);
  await page.getByRole("navigation", { name: "Vault filters" }).getByRole("button", { name: /Secure notes/ }).click();
  assert.deepEqual(await titles(page), ["Recovery codes"]);
  const cards = page.getByRole("navigation", { name: "Vault filters" }).getByRole("button", { name: /Cards/ });
  assert.equal(await cards.locator(".nav-count").textContent(), "1");
  await cards.click();
  assert.deepEqual(await titles(page), ["Everyday card"]);
  // A card is listed by its brand and the last four digits of its number.
  assert.equal(await page.locator(".entry-row .entry-copy span").first().textContent(), "Visa •••• 4242");
  assert.deepEqual(errors, []);
});

test("a card is made with a card's fields, shown without its number, and edited keeping what was left blank", async () => {
  const { page, errors } = await window.open();
  const editor = page.locator(".entry-editor");
  await page.getByRole("button", { name: /New item/ }).click();
  await editor.getByLabel("Title").fill("Travel card");
  await editor.getByLabel("Type").selectOption("card");
  // A card asks for a card's fields, not a login's.
  assert.equal(await editor.getByLabel("Username").count(), 0);
  await editor.getByLabel("Cardholder name").fill("Alex Northstar");
  await editor.getByLabel("Number").fill("5555 5555 5555 4440");
  await editor.getByText("This number fails a card number's check").waitFor();
  await editor.getByLabel("Number").fill("5555 5555 5555 4444");
  assert.equal(await editor.getByText("This number fails a card number's check").count(), 0);
  assert.equal(await editor.getByLabel("Brand").inputValue(), "Mastercard");
  await editor.getByLabel("Expiry month").selectOption("11");
  await editor.getByLabel("Expiry year").fill("2030");
  await editor.getByLabel("Security code").fill("987");
  await editor.getByRole("button", { name: "Create item" }).click();
  await page.locator(".entry-row.selected", { hasText: "Travel card" }).waitFor();
  assert.equal(await page.locator(".entry-row.selected .entry-copy span").textContent(), "Mastercard •••• 4444");

  const record = page.locator(".detail-column .record-card");
  await record.getByText("•••• 4444").waitFor();
  await record.getByText("11 / 2030").waitFor();
  await record.getByText("Alex Northstar").waitFor();
  for (const label of ["Number", "Security code"]) await record.getByRole("button", { name: `Copy ${label}` }).waitFor();
  // Neither the number nor the code is in the window once saved.
  const shown = await page.locator(".detail-column").textContent();
  assert.ok(!shown.includes("5555") && !shown.includes("987"), shown);

  await page.getByRole("button", { name: /Edit$/ }).click();
  assert.equal(await editor.getByLabel("Number").inputValue(), "");
  assert.equal(await editor.getByLabel("Number").getAttribute("placeholder"), "Unchanged (•••• 4444)");
  await editor.getByLabel("Cardholder name").fill("A. Northstar");
  await editor.getByRole("button", { name: "Save changes" }).click();
  await record.getByText("A. Northstar").waitFor();
  await record.getByText("•••• 4444").waitFor();
  await record.getByRole("button", { name: "Copy Security code" }).waitFor();
  assert.deepEqual(errors, []);
});

test("an item is made and changed, and its history brings back the first version", async () => {
  const { page, errors } = await window.open();
  const editor = page.locator(".entry-editor");
  await page.getByRole("button", { name: /New item/ }).click();
  await editor.getByLabel("Title").fill("Forum");
  await editor.getByLabel("Username").fill("first-name");
  await editor.getByLabel("Website").fill("forum.example");
  await editor.getByRole("button", { name: "Create item" }).click();
  await page.locator(".entry-row.selected", { hasText: "Forum" }).waitFor();
  await page.locator(".detail-column").getByText("first-name").waitFor();

  await page.getByRole("button", { name: /Edit$/ }).click();
  await editor.getByLabel("Username").fill("second-name");
  await editor.getByRole("button", { name: "Save changes" }).click();
  await page.locator(".detail-column").getByText("second-name").waitFor();

  await page.getByRole("button", { name: /^History/ }).click();
  const versions = page.locator(".version-card");
  await versions.nth(1).waitFor();
  assert.equal(await versions.count(), 2);
  assert.match(await versions.nth(0).textContent(), /· current.*Changed username/);
  assert.match(await versions.nth(1).textContent(), /Made the item.*first-name/);
  // Each says when it was saved, as this computer writes dates.
  const year = String(new Date().getFullYear());
  for (const index of [0, 1]) assert.match(await versions.nth(index).locator(".history-time").textContent(), new RegExp(year));
  await versions.nth(1).getByRole("button", { name: "Restore this version…" }).click();
  await versions.nth(1).getByRole("button", { name: "Restore this version", exact: true }).click();
  await toast(page).filter({ hasText: "Version restored" }).waitFor();
  await page.locator(".detail-column").getByText("first-name").waitFor();
  assert.deepEqual(errors, []);
});

test("a login's passkeys are listed by site and account, and one is removed after saying what that does", async () => {
  const { page, errors } = await window.open();
  const github = page.locator(".entry-row", { hasText: "GitHub" });
  assert.equal(await github.locator(".entry-copy span").textContent(), "northstar-labs · passkey");
  await github.click();
  const passkeys = page.locator(".passkey-list");
  await passkeys.waitFor();
  assert.match(await passkeys.textContent(), /^Passkey for github\.comnorthstar-labs \(Northstar Labs\) · made /);
  const remove = passkeys.getByRole("button", { name: "Remove the passkey for github.com" });
  await remove.click();
  assert.match(await passkeys.textContent(), /You will no longer sign in to github\.com with it\. Its key stays in this item's history and in backups\./);
  await passkeys.getByRole("button", { name: "Keep" }).click();
  assert.equal(await passkeys.locator(".delete-confirm").count(), 0);
  await remove.click();
  await passkeys.getByRole("button", { name: "Remove passkey" }).click();
  await toast(page).filter({ hasText: "Passkey removed" }).waitFor();
  await passkeys.waitFor({ state: "detached" });
  assert.equal(await github.locator(".entry-copy span").textContent(), "northstar-labs");
  assert.deepEqual(errors, []);
});

test("a deleted item is listed under Recently deleted and comes back from there", async () => {
  const { page, errors } = await window.open();
  await page.locator(".entry-row", { hasText: "Studio Wi-Fi" }).click();
  // A sample item was saved before times were kept, as an item from an
  // older build was.
  await page.getByRole("button", { name: /^History/ }).click();
  assert.equal(await page.locator(".version-card .history-time").textContent(), "Time not recorded");
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: /Edit$/ }).click();
  await page.getByRole("button", { name: "Delete…" }).click();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await page.locator(".entry-row", { hasText: "Studio Wi-Fi" }).waitFor({ state: "detached" });

  await page.getByRole("button", { name: /Recently deleted/ }).click();
  const card = page.locator(".version-card", { hasText: "Studio Wi-Fi" });
  assert.match(await card.textContent(), new RegExp(`Deleted on this device · .*${new Date().getFullYear()}`));
  await card.getByRole("button", { name: "Restore" }).click();
  await toast(page).filter({ hasText: "Studio Wi-Fi restored" }).waitFor();
  await page.locator(".entry-row", { hasText: "Studio Wi-Fi" }).waitFor();
  assert.deepEqual(errors, []);
});

/** Waits until the shown text of `selector` matches `pattern`. */
async function shownMatches(page, selector, pattern) {
  await page.waitForFunction(([selector, source]) => {
    const element = document.querySelector(selector);
    return new RegExp(source).test(element?.value ?? element?.textContent ?? "");
  }, [selector, pattern.source]);
}

test("the generator makes a password of the length and kinds chosen, and keeps the choice", async () => {
  const { page, errors } = await window.open();
  await page.getByRole("button", { name: /Generator/ }).click();
  const generator = page.locator(".generator-modal .generator");
  const shown = ".generator-modal .generated-value code";
  // One is made as it opens: 20 characters, without look-alikes.
  await shownMatches(page, shown, /^[^lIO01]{20}$/);
  await generator.getByLabel("Length").focus();
  await page.keyboard.press("End");
  await generator.locator(".range-label", { hasText: "64" }).waitFor();
  await shownMatches(page, shown, /^[A-HJ-NP-Za-km-z2-9!@#$%^&*()\-_=+[\]{}:,.?]{64}$/);
  await generator.getByLabel(/Avoid look-alikes/).uncheck();
  await shownMatches(page, shown, /^[A-Za-z0-9!@#$%^&*()\-_=+[\]{}:,.?]{64}$/);

  // Digits alone, the last kind not to be turned off.
  for (const kind of ["A–Z", "a–z", "!@#$"]) await generator.getByLabel(kind, { exact: true }).uncheck();
  // The page catches up with the last box a moment after it is unchecked.
  await generator.getByLabel("0–9").and(page.locator(":disabled")).waitFor();
  await shownMatches(page, shown, /^[0-9]{64}$/);
  await page.getByRole("button", { name: /Generate new password/ }).click();
  await shownMatches(page, shown, /^[0-9]{64}$/);

  // Opened again, it is as it was left.
  await page.locator(".generator-modal").getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: /Generator/ }).click();
  await generator.locator(".range-label", { hasText: "64" }).waitFor();
  assert.equal(await generator.getByLabel("A–Z", { exact: true }).isChecked(), false);
  assert.equal(await generator.getByLabel("0–9").isChecked(), true);
  await shownMatches(page, shown, /^[0-9]{64}$/);
  // The preview has no clipboard to clear, so it copies nothing.
  await generator.getByRole("button", { name: "Copy" }).click();
  await toast(page).filter({ hasText: "Copying is not available in the browser preview" }).waitFor();
  assert.deepEqual(errors, []);
});

test("a new login opens with a password made for it, which the owner types over, makes again, or clears", async () => {
  const { page, errors } = await window.open();
  const editor = page.locator(".entry-editor");
  const field = ".entry-editor input[autocomplete=new-password]";
  await page.getByRole("button", { name: /New item/ }).click();
  await shownMatches(page, field, /^[^lIO01]{20}$/);
  assert.equal(await editor.getByLabel("Password").getAttribute("type"), "text");
  await editor.getByText("Made for this item with the generator's choice").waitFor();

  // Typed over, it is the owner's.
  await editor.getByLabel("Password").fill("my own password");
  assert.equal(await editor.getByText("Made for this item").count(), 0);

  // The generator's options, opened under the field, make one of 8 digits.
  await editor.getByRole("button", { name: "Generator options" }).click();
  for (const kind of ["A–Z", "a–z", "!@#$"]) await editor.getByLabel(kind, { exact: true }).uncheck();
  await editor.getByLabel("Length").focus();
  await page.keyboard.press("Home");
  await shownMatches(page, ".entry-editor .generated-value code", /^[0-9]{8}$/);
  await editor.getByRole("button", { name: "Use this password" }).click();
  await shownMatches(page, field, /^[0-9]{8}$/);
  assert.equal(await editor.locator(".generator").count(), 0);
  // The editor's own button uses the same choice, kept for the next time.
  await editor.getByRole("button", { name: "Generate" }).click();
  await shownMatches(page, field, /^[0-9]{8}$/);

  // Cleared, there is none.
  await editor.getByRole("button", { name: "Clear" }).click();
  assert.equal(await editor.getByLabel("Password").inputValue(), "");
  await editor.getByLabel("Title").fill("Router");
  await editor.getByRole("button", { name: "Create item" }).click();
  await page.locator(".entry-row.selected", { hasText: "Router" }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Copy password" }).count(), 0);
  assert.deepEqual(errors, []);
});

test("a new item made a note keeps none of the password made for it", async () => {
  const { page, errors } = await window.open();
  const editor = page.locator(".entry-editor");
  await page.getByRole("button", { name: /New item/ }).click();
  await shownMatches(page, ".entry-editor input[autocomplete=new-password]", /^.{20}$/);
  await editor.getByLabel("Title").fill("Door code");
  await editor.getByLabel("Type").selectOption("secure_note");
  await editor.getByLabel("Notes").fill("4711");
  await editor.getByRole("button", { name: "Create item" }).click();
  await page.locator(".entry-row.selected", { hasText: "Door code" }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Copy password" }).count(), 0);

  // A login made with it keeps it.
  await page.getByRole("button", { name: /New item/ }).click();
  await shownMatches(page, ".entry-editor input[autocomplete=new-password]", /^.{20}$/);
  await editor.getByLabel("Title").fill("Mail");
  await editor.getByRole("button", { name: "Create item" }).click();
  await page.locator(".entry-row.selected", { hasText: "Mail" }).waitFor();
  await page.getByRole("button", { name: "Copy password", exact: true }).waitFor();
  assert.deepEqual(errors, []);
});

test("an import says what it would add, and adds it only when asked", async () => {
  const { page, errors } = await window.open();
  await page.getByTitle("Import").click();
  await page.getByRole("button", { name: /Chrome/ }).click();
  const summary = page.getByLabel("What the import adds");
  await summary.getByText("2 items to add: 2 logins").waitFor();
  await summary.getByText(/1 of them looks like an item you already have/).waitFor();
  await summary.getByText("1 entry was skipped").waitFor();
  assert.equal((await titles(page)).length, 6);
  await page.getByRole("button", { name: "Add 2 items" }).click();
  await page.locator(".entry-row", { hasText: "Sample import two" }).waitFor();
  assert.equal((await titles(page)).length, 8);
  assert.deepEqual(errors, []);
});

test("the time after which the vault locks is kept", async () => {
  const { page, errors } = await window.open();
  await page.getByRole("button", { name: /Settings/ }).click();
  await page.getByLabel("Lock the vault after").selectOption("15");
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: /Settings/ }).click();
  assert.equal(await page.getByLabel("Lock the vault after").inputValue(), "15");
  assert.deepEqual(
    await page.getByLabel("Lock the vault after").locator("option").allTextContents(),
    ["a minute", "5 minutes", "15 minutes", "an hour", "4 hours"].map((time) => `${time} without activity`),
  );
  assert.deepEqual(errors, []);
});

/** Tells the window it was hidden or covered ("hidden"), or shown again ("visible"), as WebKit does. */
async function seen(page, state) {
  await page.evaluate((state) => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
    document.dispatchEvent(new Event("visibilitychange"));
  }, state);
}

/** Moves the window's clock on without running its timers, as a hidden window's can be held back. */
async function laterWithoutTimers(page, milliseconds) {
  await page.clock.setSystemTime(await page.evaluate(() => Date.now()) + milliseconds);
}

test("hidden or covered, the window leaves the vault unlocked for the time without input, and coming back checks it", async () => {
  const { page, errors } = await window.open();
  await page.clock.install();
  await page.reload();
  await page.locator(".entry-row", { hasText: "Proton Mail" }).waitFor();
  const password = page.getByLabel("Vault password");

  // Five minutes unless changed. Hidden, the window hands what is left of
  // them to the native side, and takes it back once shown.
  const handedOver = () => page.evaluate(() => globalThis.osmHandedOver);
  await seen(page, "hidden");
  const left = await handedOver();
  assert.ok(left > 4 * 60_000 && left <= 5 * 60_000, `${left}`);
  await seen(page, "visible");
  assert.equal(await handedOver(), null);
  // Hidden for four, it is still unlocked.
  await seen(page, "hidden");
  await page.clock.fastForward(4 * 60_000);
  assert.equal(await password.count(), 0);
  // Its timer runs out while hidden: locked.
  await page.clock.fastForward(61_000);
  await password.waitFor();
  await password.fill("any password, in the preview");
  await page.getByRole("button", { name: /Unlock/ }).click();
  await seen(page, "visible");
  await page.locator(".entry-row", { hasText: "Proton Mail" }).waitFor();

  // Shown again within the time, it is still unlocked, but being shown is
  // not input: the time still runs from the Unlock click.
  await seen(page, "hidden");
  await laterWithoutTimers(page, 4 * 60_000);
  await seen(page, "visible");
  assert.equal(await password.count(), 0);
  // Hidden past it while its timer was held back: coming back locks it.
  await seen(page, "hidden");
  await laterWithoutTimers(page, 2 * 60_000);
  assert.equal(await password.count(), 0);
  await seen(page, "visible");
  await password.waitFor();
  assert.deepEqual(await titles(page), []);
  assert.deepEqual(errors, []);
});

/** The shell's events, given to the preview as the shell gives them; with no way to call the shell, the window stays the preview. */
async function withShellEvents(page) {
  await page.addInitScript(() => {
    const listeners = {};
    globalThis.osmEmit = (event, payload) => { for (const handler of listeners[event] ?? []) handler({ payload }); };
    globalThis.__TAURI__ = { event: { listen: async (event, handler) => { (listeners[event] ??= []).push(handler); return () => {}; } } };
  });
}

test("the native side's lock for want of activity, while the window was hidden, shows it locked and says nothing", async () => {
  const { page, errors } = await window.open();
  await withShellEvents(page);
  await page.reload();
  await page.locator(".entry-row", { hasText: "Proton Mail" }).waitFor();
  await page.evaluate(() => globalThis.osmEmit("vault-locked", "idle"));
  await page.getByLabel("Vault password").waitFor();
  assert.deepEqual(await titles(page), []);
  assert.equal(await page.locator(".toast").count(), 0);
  assert.deepEqual(errors, []);
});

test("a browser's request to a hidden window whose time without activity ran out finds the vault locked", async () => {
  const { page, errors } = await window.open("?login-fill");
  await withShellEvents(page);
  await page.clock.install();
  await page.reload();
  await page.locator(".entry-row", { hasText: "Proton Mail" }).waitFor();
  await seen(page, "hidden");
  await laterWithoutTimers(page, 6 * 60_000);
  await page.evaluate(() => globalThis.osmEmit("fill-request"));
  await page.getByLabel("Vault password").waitFor();
  assert.deepEqual(await titles(page), []);
  assert.deepEqual(errors, []);
});

test("the settings change this device's password, given the current one", async () => {
  const { page, errors } = await window.open();
  await page.getByRole("button", { name: /Settings/ }).click();
  const current = page.getByLabel("Current device password");
  const next = page.getByLabel("New device password", { exact: true });
  const again = page.getByLabel("New device password again");
  const change = page.getByRole("button", { name: "Change this device's password" });
  await current.fill("the password of the preview");
  await next.fill("eleven char");
  await again.fill("eleven char");
  await change.click();
  await toast(page).filter({ hasText: "Use at least 12 characters for this device password" }).waitFor();
  await next.fill("a new password, long enough");
  await again.fill("a new password, long enouhg");
  await change.click();
  await toast(page).filter({ hasText: "The two passwords differ" }).waitFor();
  await again.fill("a new password, long enough");
  await change.click();
  await toast(page).filter({ hasText: "Password changed" }).waitFor();
  assert.deepEqual([await current.inputValue(), await next.inputValue(), await again.inputValue()], ["", "", ""]);
  // Locked, the settings say to unlock first.
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByTitle("Lock vault").click();
  await page.getByLabel("Vault password").waitFor();
  await page.getByRole("button", { name: /Settings/ }).click();
  await page.getByText("Unlock the vault to change this device's password.").waitFor();
  assert.equal(await current.count(), 0);
  assert.deepEqual(errors, []);
});

test("a vault without a recent backup says so in one quiet line", async () => {
  const { page, errors } = await window.open("?backup-due", SMALLEST_SIZE);
  const line = page.locator(".backup-reminder");
  await line.waitFor();
  assert.equal((await line.textContent()).trim(), "Last backup 45 days ago, from this computerBack up");
  // One line in the list's column, above the search.
  const drawn = await edges(line);
  const column = await edges(page.locator(".list-column"));
  const search = await edges(page.locator(".search-box"));
  assert.ok(drawn.bottom - drawn.top < 24, `${drawn.bottom - drawn.top} pixels high`);
  assert.ok(drawn.left >= column.left && drawn.right <= column.right, "outside the list's column");
  assert.ok(drawn.bottom <= search.top, "over the search");
  // Gone while locked.
  await page.getByTitle("Lock vault").click();
  await page.getByLabel("Vault password").waitFor();
  assert.equal(await line.count(), 0);
  assert.deepEqual(errors, []);

  // A vault never backed up says that instead.
  const none = await window.open("?no-backup", SMALLEST_SIZE);
  const first = none.page.locator(".backup-reminder");
  await first.waitFor();
  assert.equal((await first.textContent()).trim(), "No backup of this vault yetBack up");
  assert.deepEqual(none.errors, []);

  // A recent backup says nothing.
  const recent = await window.open();
  await recent.page.locator(".entry-row").first().waitFor();
  assert.equal(await recent.page.locator(".backup-reminder").count(), 0);
  assert.deepEqual(recent.errors, []);
});

test("locking hides the items until the vault is unlocked again", async () => {
  const { page, errors } = await window.open();
  await page.getByTitle("Lock vault").click();
  await page.getByLabel("Vault password").waitFor();
  assert.deepEqual(await titles(page), []);
  assert.equal(await page.getByRole("button", { name: /New item/ }).isDisabled(), true);
  await page.getByLabel("Vault password").fill("any password, in the preview");
  await page.getByRole("button", { name: /Unlock/ }).click();
  await page.locator(".entry-row", { hasText: "Proton Mail" }).waitFor();
  assert.equal((await titles(page)).length, 6);
  assert.deepEqual(errors, []);
});

test("a page's request offers the login saved for its address and sends the one chosen", async () => {
  const { page, errors } = await window.open("?login-fill");
  const dialog = page.getByRole("dialog", { name: "Fill a login" });
  const choice = dialog.locator(".fill-choice");
  await choice.first().waitFor();
  // The only login for the address is chosen already.
  assert.equal(await choice.count(), 1);
  assert.equal(await choice.getAttribute("aria-pressed"), "true");
  await choice.getByText("northstar-labs").waitFor();
  await dialog.getByRole("button", { name: "Fill GitHub" }).click();
  await dialog.waitFor({ state: "detached" });
  await toast(page).filter({ hasText: "GitHub was sent to the page · the form was not submitted" }).waitFor();
  assert.deepEqual(errors, []);
});

test("a card's fill says where each of its fields goes and sends the card chosen", async () => {
  const { page, errors } = await window.open("?card-fill");
  const dialog = page.getByRole("dialog", { name: "Fill a card" });
  await dialog.getByRole("heading", { name: "Fill a card into https://shop.example" }).waitFor();
  const documents = await dialog.locator(".card-document").allTextContents();
  assert.deepEqual(documents, [
    "The cardholder's name, the expiry month, and the expiry year go to https://shop.example, the page itself.",
    "The number and the security code go to https://pay.example.net, a frame in the page.",
  ]);
  // Every card, by its brand and the last four digits of its number; the
  // only one is chosen already.
  const choice = dialog.locator(".fill-choice");
  assert.equal(await choice.count(), 1);
  assert.equal(await choice.getAttribute("aria-pressed"), "true");
  await choice.getByText("Visa •••• 4242").waitFor();
  await dialog.getByRole("button", { name: "Fill Everyday card" }).click();
  await dialog.waitFor({ state: "detached" });
  await toast(page).filter({ hasText: "Everyday card was sent to the page · the form was not submitted" }).waitFor();
  assert.deepEqual(errors, []);
});

test("a page's new passkey is saved where the owner chooses, once the owner is verified", async () => {
  const { page, errors } = await window.open("?passkey-create", SMALLEST_SIZE);
  const dialog = page.getByRole("dialog", { name: "A passkey" });
  await dialog.getByRole("heading", { name: "Save a passkey for example.com" }).waitFor();
  assert.match(await dialog.textContent(), /The page https:\/\/login\.example\.com asks to make a passkey for example\.com, for the account hello@northstar\.dev \(Northstar\)\./);
  // A new login, unless the owner picks one of the site's.
  const choices = dialog.locator(".fill-choice");
  assert.deepEqual(await choices.allTextContents(), ["+A new login for example.comhello@northstar.dev", "PAdd to Proton Mailhello@northstar.dev"]);
  assert.equal(await choices.first().getAttribute("aria-pressed"), "true");
  await choices.nth(1).click();
  assert.equal(await choices.nth(1).getAttribute("aria-pressed"), "true");
  // The site asks to verify the owner: this Mac's check, or the password.
  assert.match(await dialog.textContent(), /The site asks to verify it is you\. This Mac checks it with Touch ID or its password when you go on/);
  await dialog.getByLabel("This device's password").fill("wrong");
  await dialog.getByRole("button", { name: "Save passkey" }).click();
  await toast(page).filter({ hasText: "That is not this device's password · nothing was sent" }).waitFor();
  await dialog.getByLabel("This device's password").fill("the right one");
  await dialog.getByRole("button", { name: "Save passkey" }).click();
  await dialog.waitFor({ state: "detached" });
  await toast(page).filter({ hasText: "A passkey for example.com was saved and sent to the page" }).waitFor();
  assert.deepEqual(errors, []);
});

test("a page's sign-in offers the site's passkeys, or the browser's own", async () => {
  const { page, errors } = await window.open("?passkey-get", SMALLEST_SIZE);
  const dialog = page.getByRole("dialog", { name: "A passkey" });
  await dialog.getByRole("heading", { name: "Sign in to example.com with a passkey" }).waitFor();
  // The only one is chosen; the site does not ask to verify the owner.
  const choice = dialog.locator(".fill-choice");
  assert.equal(await choice.count(), 1);
  assert.equal(await choice.getAttribute("aria-pressed"), "true");
  assert.equal(await choice.textContent(), "Gnorthstar-labs (Northstar Labs)On GitHub");
  assert.equal(await dialog.getByLabel("This device's password").count(), 0);
  // It fits the smallest window.
  const drawn = await edges(page.locator(".generator-modal"));
  assert.ok(drawn.top >= 0 && drawn.bottom <= SMALLEST_SIZE.height && drawn.right <= SMALLEST_SIZE.width, JSON.stringify(drawn));
  await dialog.getByRole("button", { name: "Use the browser's passkeys" }).click();
  await dialog.waitFor({ state: "detached" });
  await toast(page).filter({ hasText: "The browser's own passkeys answer the page instead" }).waitFor();

  const again = await window.open("?passkey-get");
  await again.page.getByRole("dialog", { name: "A passkey" }).getByRole("button", { name: "Sign in" }).click();
  await toast(again.page).filter({ hasText: "You were signed in to example.com with your passkey" }).waitFor();
  assert.deepEqual([...errors, ...again.errors], []);
});

