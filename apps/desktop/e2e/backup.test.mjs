// A backup saved through the system's file dialog, and restored from it on
// another device that has no vault, as the owner would after losing every
// device: the real app, its real dialogs, its real files. Before it, the
// window reminds of a backup 30 days without one.

import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { after, test } from "node:test";
import { addLogin, answerFileDialog, By, createVault, device, fill, PATIENCE_MS, press, scratch, shows, textOf, titles, unlockAgain, until, vaultFolder } from "./harness.mjs";

const devices = [];
after(async () => {
  for (const each of devices) await each.quit();
});

test("a backup is saved through the system's dialog and restored on a device without a vault", async () => {
  const first = await device("first");
  devices.push(first);
  const recoveryKey = await createVault(first.window, "first device password");
  await addLogin(first.window, "Backed up", "someone", "a password kept in the backup");

  // The device began counting at the unlock, with no backup; set 31 days
  // back, the next unlock reminds of one, in one line.
  const record = path.join(vaultFolder(first), "backups.json");
  await first.window.wait(async () => existsSync(record), PATIENCE_MS);
  assert.equal((await first.window.findElements(By.css(".backup-reminder"))).length, 0);
  const counted = JSON.parse(readFileSync(record, "utf8"));
  assert.equal(counted.lastBackup, null);
  writeFileSync(record, JSON.stringify({ ...counted, since: counted.since - 31 * 86_400 }));
  await unlockAgain(first.window, "first device password");
  await shows(first.window, "No backup made on this computer yet");

  await press(first.window, "Back up", { within: '//div[contains(@class, "backup-reminder")]' });
  await press(first.window, "Choose where to save");
  const file = path.join(scratch, "vault.osmbackup");
  await answerFileDialog("Save a backup", file);
  await shows(first.window, "Saved and read back");
  const saved = await textOf(first.window, ".saved-banner");
  assert.match(saved, /vault\.osmbackup/);
  assert.match(saved, /1 item with 1 version/);
  // Its time is noted, and the reminder goes.
  await first.window.wait(async () => (await first.window.findElements(By.css(".backup-reminder"))).length === 0, PATIENCE_MS);
  assert.equal(typeof JSON.parse(readFileSync(record, "utf8")).lastBackup, "number");

  // Another device, with no vault: the backup becomes a new vault there.
  const second = await device("second");
  devices.push(second);
  await press(second.window, "Restore from a backup instead");
  await press(second.window, "Choose the backup file");
  await answerFileDialog("Choose a backup to restore", file);
  await press(second.window, "choose another", { partly: true });
  await fill(second.window, "Recovery key", recoveryKey);
  await fill(second.window, "New device password", "second device password");
  await press(second.window, "Restore");
  await second.window.wait(until.elementLocated(By.xpath('//*[contains(@class, "entry-row")]//strong[normalize-space(.) = "Backed up"]')), PATIENCE_MS);
  assert.deepEqual(await titles(second.window), ["Backed up"]);
  // A restored vault is a new one, with a recovery key of its own.
  const newKey = await textOf(second.window, ".recovery-card code");
  assert.notEqual(newKey, recoveryKey);
});
