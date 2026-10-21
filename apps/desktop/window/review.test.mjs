// What the owner decides in the window: changes held because a device
// outside the vault wrote them, and versions of an item changed on two
// devices at once. The preview has them when its address asks.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { start, titles } from "./harness.mjs";

let window;
before(async () => {
  window = await start();
});
after(async () => {
  await window?.stop();
});

test("held changes are listed without secrets, and each is kept or rejected", async () => {
  const { page, errors } = await window.open("?held");
  const banner = page.locator(".held-banner");
  await banner.getByText("2 changes are held for review").waitFor();
  await banner.getByRole("button", { name: "Review" }).click();

  const added = page.locator(".version-card", { hasText: "New item · Old router" });
  const edited = page.locator(".version-card", { hasText: "Changes Proton Mail" });
  await edited.getByText("password", { exact: true }).waitFor();
  assert.match(await added.textContent(), /From device 7c41d09e, which was removed from this vault/);

  await added.getByRole("button", { name: "Keep this change" }).click();
  await page.locator(".toast", { hasText: "Change kept" }).waitFor();
  await banner.getByText("1 change is held for review").waitFor();
  await page.locator(".entry-row", { hasText: "Old router" }).waitFor();

  await edited.getByRole("button", { name: "Reject" }).click();
  await page.locator(".toast", { hasText: "Change rejected" }).waitFor();
  await banner.waitFor({ state: "detached" });
  await page.locator(".generator-modal").waitFor({ state: "detached" });
  assert.deepEqual(errors, []);
});

test("an item changed on two devices shows both versions, and keeping one settles it", async () => {
  const { page, errors } = await window.open("?conflict");
  await page.locator(".entry-row", { hasText: "GitHub" }).click();
  await page.locator(".detail-column").getByRole("button", { name: "Review versions" }).click();

  const versions = page.locator(".version-card");
  await versions.nth(1).waitFor();
  assert.match(await versions.nth(0).textContent(), /This device.*northstar-labs/);
  assert.match(await versions.nth(1).textContent(), /Device 3f9a1c2e.*northstar-ops/);
  // What the fields shown do not tell is named, without its value.
  assert.match(await versions.nth(1).textContent(), /Differs inusername, password, passkeys/);
  // Keeping one version whole loses no passkey of the other.
  assert.match(await page.locator(".review-hint").textContent(), /The passkeys of every version are kept, whichever you keep/);
  await versions.nth(1).getByRole("button", { name: "Keep this version" }).click();
  await page.locator(".toast", { hasText: "Conflict resolved" }).waitFor();
  await page.locator(".entry-row", { hasText: "northstar-ops" }).waitFor();
  assert.equal(await page.locator(".detail-column").getByRole("button", { name: "Review versions" }).count(), 0);
  assert.ok((await titles(page)).includes("GitHub"));
  assert.deepEqual(errors, []);
});
