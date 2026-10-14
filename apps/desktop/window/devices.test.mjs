// The Devices panel, on the preview's sample vault of two devices
// (`?devices`): this computer, which votes, and a phone, which does not;
// with `?without-vote`, this device is the one that does not vote.

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

const toast = (page) => page.locator(".toast");

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
  // Where else each is reached: the phone's VPN address, and the addresses
  // this computer tells the others.
  assert.match(await rows.nth(1).textContent(), /Also at 100\.101\.102\.103:47820/);
  assert.match(await rows.nth(0).textContent(), /Tells your other devices it is at 192\.168\.1\.10:47820, 100\.101\.102\.104:47820/);
  assert.equal(await rows.nth(1).getByRole("button", { name: "Remove…" }).count(), 1);
  assert.deepEqual(errors, []);
});

test("the only device that votes cannot be removed, and the panel says so", async () => {
  const { page, errors } = await window.open("?devices&without-vote");
  const panel = await openDevices(page);
  const rows = panel.locator(".peer-row");
  await rows.nth(1).waitFor();
  assert.match(await rows.nth(0).textContent(), /This device.* · does not vote/);
  assert.match(await rows.nth(1).textContent(), /Device 9f8e7d6c.* · the only device that votes/);
  assert.equal(await rows.nth(1).getByRole("button", { name: "Remove…" }).count(), 0);
  await panel.getByText(/It cannot itself be removed while it is the only one: invite a computer that votes first\./).waitFor();
  assert.deepEqual(errors, []);
});

test("an invitation says which kind of device it is for, and a phone's is also a QR code", async () => {
  const { page, errors } = await window.open("?devices");
  const panel = await openDevices(page);
  for (const [choice, said, scanned] of [
    ["A phone, or a computer often off · it does not vote", "For a phone, or a computer often off: it will not vote.", true],
    ["A computer that is usually on · it votes", "For a computer that is usually on: it will vote.", false],
  ]) {
    await panel.getByRole("button", { name: "Invite a device" }).click();
    await panel.getByRole("button", { name: choice }).click();
    await panel.getByText(said, { exact: false }).waitFor();
    await panel.getByText("OSM-PAIR1-PREVIEW-SAMPLE-NOT-AN-INVITATION").waitFor();
    const qr = panel.getByRole("img", { name: "QR code of the invitation" });
    if (scanned) {
      await panel.getByText("On a phone, choose Scan the QR code and point it here", { exact: false }).waitFor();
      // Large enough for a phone's camera, and inside the panel.
      const [drawn, around] = [await qr.boundingBox(), await panel.boundingBox()];
      assert.ok(drawn.width >= 250 && drawn.height === drawn.width, `${drawn.width}×${drawn.height}`);
      assert.ok(drawn.x >= around.x && drawn.x + drawn.width <= around.x + around.width);
      assert.ok(await qr.locator("path").getAttribute("d"));
    } else {
      assert.equal(await qr.count(), 0);
    }
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
  await panel.getByRole("button", { name: "A phone, or a computer often off · it does not vote" }).click();
  const invitation = panel.getByText("OSM-PAIR1-PREVIEW-SAMPLE-NOT-AN-INVITATION");
  const qr = panel.getByRole("img", { name: "QR code of the invitation" });
  await invitation.waitFor();
  await qr.waitFor();

  await page.evaluate(() => globalThis.osmEmit("vault-locked", "screen_locked"));
  await page.locator(".toast", { hasText: "Vault locked because the screen locked · the pairing was cancelled" }).waitFor();
  await page.getByLabel("Vault password").waitFor();
  assert.equal(await invitation.count(), 0);
  assert.equal(await qr.count(), 0);
  assert.deepEqual(errors, []);
});

test("a relay is set up from its code, said to be connected, and stopped", async () => {
  const { page, errors } = await window.open("?devices");
  const panel = await openDevices(page);
  await panel.getByRole("button", { name: /through a relay you run/ }).click();
  const field = panel.getByLabel("Relay code");
  await field.fill("not a code");
  await panel.getByRole("button", { name: "Use this relay" }).click();
  await toast(page).filter({ hasText: "That is not a relay code" }).waitFor();
  await field.fill("  OSM-RELAY1-PREVIEW-SAMPLE\n");
  await panel.getByRole("button", { name: "Use this relay" }).click();
  await toast(page).filter({ hasText: "Relay set · your other devices use it once they sync" }).waitFor();
  const row = panel.locator(".relay-row");
  assert.match(await row.textContent(), /Relay.*relay\.example:47830 · connected/);
  await row.getByRole("button", { name: "Stop using it…" }).click();
  await row.getByRole("button", { name: "Stop using it", exact: true }).click();
  await row.waitFor({ state: "detached" });
  await panel.getByRole("button", { name: /through a relay you run/ }).waitFor();
  assert.deepEqual(errors, []);
});
