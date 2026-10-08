// Where things are drawn, at the window's first size and at its smallest:
// the cards shown after an unlock sit at the bottom right, inside the window
// and off the sidebar; every dialog fits the window; and nothing makes the
// page scroll sideways. Phase 10 found the card about records taken out of
// the file drawn over the sidebar, which only a look had caught.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { edges, FIRST_SIZE, scrollsSideways, SMALLEST_SIZE, start } from "./harness.mjs";

let window;
before(async () => {
  window = await start();
});
after(async () => {
  await window?.stop();
});

const SIZES = [FIRST_SIZE, SMALLEST_SIZE];

async function assertAtBottomRight(page, card, size) {
  const drawn = await edges(card);
  const sidebar = await edges(page.locator(".sidebar"));
  const what = `${await card.locator("strong").first().textContent()} at ${size.width}×${size.height}`;
  assert.ok(drawn.left >= sidebar.right, `${what}: over the sidebar (${drawn.left} < ${sidebar.right})`);
  assert.ok(drawn.right <= size.width && drawn.bottom <= size.height, `${what}: outside the window`);
  assert.ok(drawn.left > size.width / 2, `${what}: not at the right`);
  assert.ok(drawn.top > size.height / 2, `${what}: not at the bottom`);
}

for (const size of SIZES) {
  test(`at ${size.width}×${size.height}, the cards after an unlock sit at the bottom right, one at a time`, async () => {
    const { page, errors } = await window.open("?rows-changed&recovery-key", size);
    // Both are asked for at an unlock; the preview starts unlocked.
    await page.getByTitle("Lock vault").click();
    await page.getByLabel("Vault password").fill("any password, in the preview");
    await page.getByRole("button", { name: /Unlock/ }).click();
    const rows = page.locator(".rows-changed-card");
    await assertAtBottomRight(page, rows, size);
    // The warning comes first; the recovery key waits behind it.
    assert.equal(await page.locator(".recovery-card").count(), 1);
    await rows.getByRole("button", { name: "I understand" }).click();

    const key = page.locator(".recovery-card", { hasText: "Recovery key" });
    await assertAtBottomRight(page, key, size);
    await key.getByRole("button", { name: "I stored it" }).click();
    await key.waitFor({ state: "detached" });
    assert.equal(await scrollsSideways(page), false);
    assert.deepEqual(errors, []);
  });
}

/** Each dialog, as the owner opens it. */
const DIALOGS = [
  ["the generator", "", (page) => page.getByRole("button", { name: /Generator/ }).click()],
  ["a new item", "", (page) => page.getByRole("button", { name: /New item/ }).click()],
  ["an item's editor", "", async (page) => {
    await page.locator(".entry-row", { hasText: "Proton Mail" }).click();
    await page.getByRole("button", { name: /Edit$/ }).click();
  }],
  ["an item's history", "", async (page) => {
    await page.locator(".entry-row", { hasText: "Proton Mail" }).click();
    await page.getByRole("button", { name: /^History/ }).click();
  }],
  ["recently deleted", "", (page) => page.getByRole("button", { name: /Recently deleted/ }).click()],
  ["the settings", "", (page) => page.getByRole("button", { name: /Settings/ }).click()],
  ["an import's summary", "", async (page) => {
    await page.getByTitle("Import").click();
    await page.getByRole("button", { name: /Bitwarden/ }).click();
    await page.getByLabel("What the import adds").waitFor();
  }],
  ["the held changes", "?held", (page) => page.locator(".held-banner").getByRole("button", { name: "Review" }).click()],
  ["an item's versions in conflict", "?conflict", async (page) => {
    await page.locator(".entry-row", { hasText: "GitHub" }).click();
    await page.locator(".detail-column").getByRole("button", { name: "Review versions" }).click();
  }],
];

for (const size of SIZES) {
  test(`at ${size.width}×${size.height}, every dialog fits the window`, async () => {
    for (const [name, query, openDialog] of DIALOGS) {
      const { page, errors } = await window.open(query, size);
      await openDialog(page);
      const dialog = page.locator(".generator-modal");
      await dialog.waitFor();
      const drawn = await edges(dialog);
      assert.ok(drawn.left >= 0 && drawn.top >= 0 && drawn.right <= size.width && drawn.bottom <= size.height, `${name}: outside the window`);
      assert.equal(await scrollsSideways(page), false, `${name}: the page scrolls sideways`);
      await dialog.getByRole("button", { name: "Close" }).click();
      await dialog.waitFor({ state: "detached" });
      assert.deepEqual(errors, [], name);
      await page.close();
    }
  });
}

for (const size of SIZES) {
  test(`at ${size.width}×${size.height}, a dialog's controls are not covered by the cards after an unlock`, async () => {
    const { page, errors } = await window.open("?held&recovery-key", size);
    await page.getByTitle("Lock vault").click();
    await page.getByLabel("Vault password").fill("any password, in the preview");
    await page.getByRole("button", { name: /Unlock/ }).click();
    await page.locator(".recovery-card").waitFor();
    await page.locator(".held-banner").getByRole("button", { name: "Review" }).click();
    const dialog = page.locator(".generator-modal");
    await dialog.waitFor();
    // Each corner of each button the dialog shows must be the dialog's to click.
    for (const button of await dialog.getByRole("button").all()) {
      const drawn = await edges(button);
      const corners = [[drawn.left + 2, drawn.top + 2], [drawn.right - 2, drawn.top + 2], [drawn.left + 2, drawn.bottom - 2], [drawn.right - 2, drawn.bottom - 2]];
      for (const corner of corners) {
        const owner = await page.evaluate(([x, y]) => document.elementFromPoint(x, y)?.closest(".generator-modal, .recovery-overlay, .toast")?.className, corner);
        assert.match(owner ?? "", /generator-modal/, `${await button.textContent()} at ${corner}: covered by ${owner}`);
      }
    }
    assert.deepEqual(errors, []);
  });
}
