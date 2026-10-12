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
  assert.deepEqual(await titles(page), ["Proton Mail", "GitHub", "Banking — checking", "Recovery codes", "Studio Wi-Fi"]);
  await page.getByLabel("Search vault").fill("git");
  assert.deepEqual(await titles(page), ["GitHub"]);
  await page.getByLabel("Search vault").fill("nothing like it");
  await page.getByText("No matching items").waitFor();
  await page.getByLabel("Search vault").fill("");
  await page.getByRole("navigation", { name: "Vault filters" }).getByRole("button", { name: /Favorites/ }).click();
  assert.deepEqual(await titles(page), ["Proton Mail", "GitHub"]);
  await page.getByRole("navigation", { name: "Vault filters" }).getByRole("button", { name: /Secure notes/ }).click();
  assert.deepEqual(await titles(page), ["Recovery codes"]);
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

test("the generator makes a password of the length chosen", async () => {
  const { page, errors } = await window.open();
  await page.getByRole("button", { name: /Generator/ }).click();
  await page.locator(".generator input[type=range]").focus();
  await page.keyboard.press("End");
  await page.locator(".range-label", { hasText: "48" }).waitFor();
  await page.getByRole("button", { name: /Generate new password/ }).click();
  const value = await page.locator(".generated-value code").textContent();
  assert.equal(value.length, 48);
  assert.match(value, /^[A-Za-z0-9!@#$%]+$/);
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
  assert.equal((await titles(page)).length, 5);
  await page.getByRole("button", { name: "Add 2 items" }).click();
  await page.locator(".entry-row", { hasText: "Sample import two" }).waitFor();
  assert.equal((await titles(page)).length, 7);
  assert.deepEqual(errors, []);
});

test("the time after which the vault locks is kept", async () => {
  const { page, errors } = await window.open();
  await page.getByRole("button", { name: /Settings/ }).click();
  await page.getByLabel("Lock the vault after").selectOption("15");
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: /Settings/ }).click();
  assert.equal(await page.getByLabel("Lock the vault after").inputValue(), "15");
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
  assert.equal((await titles(page)).length, 5);
  assert.deepEqual(errors, []);
});
