// Two devices of one vault change the same login while apart, in two
// instances of the real app, each started alone to make its change.
// Together again, both find the login in conflict; the owner reviews the
// two versions on one and keeps the other's, which settles it on both. The
// second joined as a device that does not vote, which the first's Devices
// panel says.

import assert from "node:assert/strict";
import net from "node:net";
import { after, test } from "node:test";
import { addLogin, By, createVault, device, fill, fillIn, openDevices, press, row, shows, textOf, unlock, waitFor } from "./harness.mjs";

const running = new Set();
after(async () => {
  for (const each of running) await each.quit();
});

/** Where a device listens for its members when that port is free. */
const SYNC_PORT = 47_820;

/**
 * Keeps the sync port taken while `during` runs, so that a device started
 * then listens elsewhere, as it would beside another device on one
 * address.
 */
async function offTheSyncPort(during) {
  const holder = net.createServer((socket) => socket.destroy());
  await new Promise((resolve, reject) => holder.once("error", reject).listen(SYNC_PORT, "0.0.0.0", resolve));
  try {
    return await during();
  } finally {
    await new Promise((resolve) => holder.close(resolve));
  }
}

async function start(name) {
  const started = await device(name);
  running.add(started);
  return started;
}

async function stop(started) {
  await started.quit();
  running.delete(started);
}

/** Changes the username of the login titled `title` through its editor. */
async function changeUsername(window, title, username) {
  await (await row(window, title)).click();
  // The button reads "✎ Edit".
  await press(window, "Edit", { partly: true, within: '//div[contains(@class, "detail-actions")]' });
  await fillIn(window, "Username", username);
  await press(window, "Save changes");
  await shows(window, username);
}

/** Waits until the login titled `title` offers its versions for review, and opens them. */
async function reviewVersions(window, title) {
  const review = By.xpath('//div[contains(@class, "detail-column")]//button[normalize-space(.) = "Review versions"]');
  await waitFor(window, `offered ${title}'s versions for review`, async () => {
    // The detail follows the list, which a sync refreshes.
    await (await row(window, title)).click();
    return (await window.findElements(review)).length > 0;
  });
  await (await window.findElement(review)).click();
}

test("a login changed on two devices while apart is reviewed on one and settled on both", async () => {
  let first = await start("first");
  await createVault(first.window, "first device password");
  await addLogin(first.window, "Shared", "as made", "a password both devices hold");

  // The second joins as a device that does not vote.
  await openDevices(first.window);
  await press(first.window, "Invite a device");
  await press(first.window, "A phone, or a computer often off · it does not vote");
  const invitation = await textOf(first.window, ".generated-value code");
  let second = await start("second");
  await press(second.window, "Join a vault from another device instead");
  await fill(second.window, "Invitation", invitation);
  await press(second.window, "Continue");
  assert.equal(await textOf(second.window, ".sas-code"), await textOf(first.window, ".sas-code"));
  await fill(second.window, "New device password", "second device password");
  await press(second.window, "Codes match · join");
  await press(first.window, "Codes match");
  await row(second.window, "Shared");
  await waitFor(first.window, "listed both devices", async () => (await first.window.findElements(By.css(".peer-row"))).length === 2);
  // Listed by device ID, in either order: this device votes, the other does not.
  const rows = await first.window.findElements(By.css(".peer-row"));
  const [here, other] = (await Promise.all(rows.map((row) => row.getAttribute("textContent")))).sort((a, b) => /This device/.test(b) - /This device/.test(a));
  assert.match(here, /This device/);
  assert.doesNotMatch(here, /does not vote/);
  assert.match(other, /does not vote/);

  // Apart, each changes the login: the first alone, then the second. Both
  // have the container's one address, and a device listens on the sync
  // port whenever it is free: the first keeps it, and the second, started
  // alone, is kept off it, so it listens on a port the first has not seen.
  await stop(first);
  await stop(second);
  first = await start("first");
  await unlock(first.window, "first device password");
  await changeUsername(first.window, "Shared", "changed on the first");
  await stop(first);
  second = await offTheSyncPort(async () => {
    const started = await start("second");
    await unlock(started.window, "second device password");
    await changeUsername(started.window, "Shared", "changed on the second");
    return started;
  });

  // Together again: the second, told to sync, reaches the first on its
  // port, and so tells it where it listens. Both find the login in
  // conflict.
  first = await start("first");
  await unlock(first.window, "first device password");
  await openDevices(second.window);
  await press(second.window, "Sync now");
  await (await second.window.findElement(By.xpath('//div[contains(@class, "modal-head")]//button[@aria-label="Close"]'))).click();
  await reviewVersions(first.window, "Shared");
  await waitFor(first.window, "showed both versions", async () => (await first.window.findElements(By.css(".version-card"))).length === 2);
  const cards = await first.window.findElements(By.css(".version-card"));
  const texts = await Promise.all(cards.map((card) => card.getAttribute("textContent")));
  const mine = texts.findIndex((text) => /This device/.test(text));
  assert.match(texts[mine], /changed on the first/);
  assert.match(texts[1 - mine], /changed on the second/);
  assert.match(texts[1 - mine], /Differs in\s*username/);

  // Kept on the first, the second's version settles the login on both.
  await (await cards[1 - mine].findElement(By.xpath('.//button[normalize-space(.) = "Keep this version"]'))).click();
  await shows(first.window, "Conflict resolved");
  await reviewGone(first.window, "Shared");
  await reviewGone(second.window, "Shared");
  await (await row(second.window, "Shared")).click();
  await shows(second.window, "changed on the second");
});

/** Waits until the login titled `title` no longer offers versions to review. */
async function reviewGone(window, title) {
  const review = By.xpath('//div[contains(@class, "detail-column")]//button[normalize-space(.) = "Review versions"]');
  await waitFor(window, `settled ${title}`, async () => {
    await (await row(window, title)).click();
    return (await window.findElements(review)).length === 0;
  });
}
