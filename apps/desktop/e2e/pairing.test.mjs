// Two devices of one vault, in two instances of the real app: an
// invitation, the codes both show, the join, and a removal, after which the
// removed device puts its copy away and an item is copied back from it.

import assert from "node:assert/strict";
import { after, test } from "node:test";
import { addLogin, By, createVault, device, fill, openDevices, PATIENCE_MS, press, shows, textOf, titles, until } from "./harness.mjs";

const devices = [];
after(async () => {
  for (const each of devices) await each.quit();
});

const listed = (window, title) =>
  window.wait(until.elementLocated(By.xpath(`//*[contains(@class, "entry-row")]//strong[normalize-space(.) = "${title}"]`)), PATIENCE_MS);

test("a device joins through an invitation once both show the same code, and its copy is put away when it is removed", async () => {
  const first = await device("first");
  devices.push(first);
  await createVault(first.window, "first device password");
  await addLogin(first.window, "Shared login", "both", "a password both devices hold");

  await openDevices(first.window);
  await press(first.window, "Invite a device");
  await press(first.window, "A computer that is usually on · it votes");
  await shows(first.window, "For a computer that is usually on: it will vote.");
  const invitation = await textOf(first.window, ".generated-value code");
  assert.match(invitation, /^OSM-PAIR1-/);

  const second = await device("second");
  devices.push(second);
  await press(second.window, "Join a vault from another device instead");
  await fill(second.window, "Invitation", invitation);
  await press(second.window, "Continue");
  // Both show the code, which the owner compares before going on.
  const secondCode = await textOf(second.window, ".sas-code");
  const firstCode = await textOf(first.window, ".sas-code");
  assert.match(firstCode, /\S/);
  assert.equal(secondCode, firstCode);
  await fill(second.window, "New device password", "second device password");
  await press(second.window, "Codes match · join");
  await press(first.window, "Codes match");
  await listed(second.window, "Shared login");
  assert.deepEqual(await titles(second.window), ["Shared login"]);

  // Both list both devices once the join completes.
  await first.window.wait(async () => (await first.window.findElements(By.css(".peer-row"))).length === 2, PATIENCE_MS);
  // This device first, though the shell lists them by device ID.
  const rows = await first.window.findElements(By.css(".peer-row"));
  assert.match(await rows[0].getAttribute("textContent"), /This device/);
  assert.doesNotMatch(await rows[1].getAttribute("textContent"), /This device/);

  // Removed, the second device puts its copy away and has no vault.
  await press(first.window, "Remove…");
  await press(first.window, "Remove");
  await shows(second.window, "This device was removed from its vault");
  assert.match(await (await shows(second.window, "its copy was moved to")).getAttribute("textContent"), /archive-\d+/);

  // Given a new vault, it copies the shared login back from that copy.
  await createVault(second.window, "a new vault's password");
  assert.deepEqual(await titles(second.window), []);
  await press(second.window, "Archive");
  await press(second.window, "Open…");
  await fill(second.window, "Password of that copy", "second device password");
  await press(second.window, "Open");
  await shows(second.window, "Shared login");
  await press(second.window, "Copy into vault");
  await listed(second.window, "Shared login");
});
