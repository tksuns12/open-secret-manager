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

test("the panel lists this device and marks the phone that does not vote", async () => {
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
