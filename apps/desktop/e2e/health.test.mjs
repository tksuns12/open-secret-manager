// Which logins need attention, in the real app: its shell judges the
// passwords, and the window shows what it says (and never a password).

import assert from "node:assert/strict";
import { after, test } from "node:test";
import { addLogin, By, createVault, device, press, shows, textOf, titles, PATIENCE_MS, until } from "./harness.mjs";

const devices = [];
after(async () => {
  for (const each of devices) await each.quit();
});

test("logins that share a password or hold a weak one are marked, filtered, and told why", async () => {
  const first = await device("first");
  devices.push(first);
  await createVault(first.window, "first device password");
  await addLogin(first.window, "Mail", "anna", "Zq7!rT9#vLm2qXa");
  await addLogin(first.window, "Bank", "bert", "Zq7!rT9#vLm2qXa");
  await addLogin(first.window, "Wifi", "studio", "kjhdsfpq");
  await addLogin(first.window, "Fine", "carl", "Pn4#xK8!wQ2$mZ7");

  await first.window.wait(until.elementLocated(By.css(".entry-row .attention")), PATIENCE_MS);
  await press(first.window, "Needs attention", { partly: true });
  await first.window.wait(async () => (await titles(first.window)).length === 3, PATIENCE_MS);
  assert.deepEqual([...(await titles(first.window))].sort(), ["Bank", "Mail", "Wifi"]);

  await press(first.window, "Wifi", { within: '//div[contains(@class, "entry-list")]', partly: true });
  await shows(first.window, "Worth changing this password");
  assert.match(await textOf(first.window, ".attention-note"), /uses one kind of character/);

  await press(first.window, "Bank", { within: '//div[contains(@class, "entry-list")]', partly: true });
  await first.window.wait(async () => /also used by another login/.test(await textOf(first.window, ".attention-note").catch(() => "")), PATIENCE_MS);
});
