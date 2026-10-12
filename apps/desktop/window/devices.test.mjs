// The Devices panel, on the preview's sample vault of two devices
// (`?devices`): this computer, which votes, and a phone, which does not.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { start } from "./harness.mjs";

let window;
before(async () => {
  window = await start();
});
after(async () => {
  await window?.stop();
});

async function openDevices(page) {
  await page.locator(".footer-bar").getByRole("button", { name: /Devices/ }).click();
  const panel = page.locator(".generator-modal", { hasText: "Devices and sync" });
  await panel.waitFor();
  return panel;
}

test("the panel lists this device first and marks the phone that does not vote", async () => {
  const { page, errors } = await window.open("?devices");
  const panel = await openDevices(page);
  const rows = panel.locator(".peer-row");
  await rows.nth(1).waitFor();
  assert.equal(await rows.count(), 2);
  assert.match(await rows.nth(0).textContent(), /This device/);
  assert.doesNotMatch(await rows.nth(0).textContent(), /does not vote/);
  assert.match(await rows.nth(1).textContent(), /Device 9f8e7d6c.*192\.168\.1\.23:47820 · does not vote/);
  assert.deepEqual(errors, []);
});

test("an invitation says which kind of device it is for", async () => {
  const { page, errors } = await window.open("?devices");
  const panel = await openDevices(page);
  for (const [choice, said] of [
    ["A phone, or a computer often off · it does not vote", "For a phone, or a computer often off: it will not vote."],
    ["A computer that is usually on · it votes", "For a computer that is usually on: it will vote."],
  ]) {
    await panel.getByRole("button", { name: "Invite a device" }).click();
    await panel.getByRole("button", { name: choice }).click();
    await panel.getByText(said, { exact: false }).waitFor();
    await panel.getByText("OSM-PAIR1-PREVIEW-SAMPLE-NOT-AN-INVITATION").waitFor();
    // How long it stays unlocked meanwhile is the owner's setting, not a fixed time.
    await panel.getByText(/the time without activity set in Settings/).waitFor();
    await panel.getByRole("button", { name: "Cancel" }).click();
    await panel.getByRole("button", { name: "Invite a device" }).waitFor();
  }
  assert.deepEqual(errors, []);
});

test("when the system says the owner went away, the vault locks, says why, and ends a pairing", async () => {
  const { page, errors } = await window.open("?devices");
  // The shell's events, given to the preview as the shell gives them; with
  // no way to call the shell, the window stays the preview.
  await page.addInitScript(() => {
    const listeners = {};
    globalThis.osmEmit = (event, payload) => { for (const handler of listeners[event] ?? []) handler({ payload }); };
    globalThis.__TAURI__ = { event: { listen: async (event, handler) => { (listeners[event] ??= []).push(handler); return () => {}; } } };
  });
  await page.reload();
  const panel = await openDevices(page);
  await panel.getByRole("button", { name: "Invite a device" }).click();
  await panel.getByRole("button", { name: "A computer that is usually on · it votes" }).click();
  const invitation = panel.getByText("OSM-PAIR1-PREVIEW-SAMPLE-NOT-AN-INVITATION");
  await invitation.waitFor();

  await page.evaluate(() => globalThis.osmEmit("vault-locked", "screen_locked"));
  await page.locator(".toast", { hasText: "Vault locked because the screen locked · the pairing was cancelled" }).waitFor();
  await page.getByLabel("Vault password").waitFor();
  assert.equal(await invitation.count(), 0);
  // The notice goes in seconds, while the screen saver or another user may
  // have the screen; the locked screen still says why until the unlock.
  await page.locator(".toast").waitFor({ state: "detached" });
  assert.equal(await page.locator(".locked-reason").textContent(), "Locked because the screen locked");
  // The Devices panel works while locked, so it stays open; closed, the
  // vault unlocks as ever.
  await page.locator(".modal-head").getByRole("button", { name: "Close" }).click();
  await page.getByLabel("Vault password").fill("any password, in the preview");
  await page.locator(".unlock-form button").click();
  await page.getByLabel("Vault password").waitFor({ state: "detached" });
  await page.evaluate(() => globalThis.osmEmit("vault-locked", "screen_saver"));
  await page.locator(".locked-reason", { hasText: "Locked because the screen saver started" }).waitFor();
  assert.deepEqual(errors, []);
});
