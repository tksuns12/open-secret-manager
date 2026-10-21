// A card's fill, the whole path in a real browser as for a login's
// (fill.test.mjs): the built extension, the real host, and the stand-in for
// the desktop app serving a real vault with a card in it.

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { BROWSER, start } from "./harness.mjs";

const VISA = ["Visa", "Owner", "4111 1111 1111 1111", "3", "2030", "123"];
const FILLED = { holder: "Owner", number: "4111111111111111", month: "03", year: "2030", code: "123" };

/** The card's request the stand-in shows next: the documents it names and the cards it offers. */
async function asked(browser) {
  const shown = await browser.app.expect("REQUEST");
  const [id, origin, kind, count, what, documents] = shown.split(" ");
  assert.equal(what, "card", shown);
  const frames = [];
  for (let index = 0; index < Number(documents); index += 1) {
    const [frame, frameOrigin, fields] = (await browser.app.expect("FRAME")).split(" ");
    frames.push({ page: frame === "0", origin: frameOrigin, fields: fields.split(",") });
  }
  const cards = [];
  for (let index = 0; index < Number(count || 0); index += 1) cards.push((await browser.app.expect("CARD")).split(" ")[0]);
  return { id, origin, kind, count, frames, cards };
}

describe(`a card's fill in ${BROWSER}`, () => {
  let browser;
  before(async () => {
    browser = await start({ logins: [["site", "https://login.test/login"]], cards: [VISA] });
  });
  after(() => browser?.close());

  test("a checkout page's card form is filled with the card chosen, but for a field the owner cannot see", async () => {
    const page = await browser.open("https://login.test/checkout");
    await browser.press(page);
    const request = await asked(browser);
    assert.deepEqual([request.origin, request.kind, request.cards], ["https://login.test", browser.kind, [browser.items.Visa]]);
    // The page itself, with the fields it shows; the one of no size is not named.
    assert.deepEqual(request.frames, [{ page: true, origin: "https://login.test", fields: ["number", "cardholder", "expiry_month", "expiry_year", "security_code"] }]);
    await browser.until(page, "…", { says: /Choose a card there/ });
    assert.equal((await page.card()).number, "");

    // A login is not a card.
    browser.app.say(`approve-card ${browser.items.site}`);
    assert.equal(await browser.app.expect("REFUSED"), "not-for-this-page");
    browser.app.say(`approve-card ${browser.items.Visa}`);
    assert.equal(await browser.app.expect("FILLED"), `${request.id} ${browser.items.Visa}`);
    await browser.until(page, "✓", { says: /Filled the card's number, cardholder's name, expiry month, expiry year, and security code\. The form was not submitted\./ });
    assert.deepEqual(await page.card(), { ...FILLED, hidden: "" });
    await page.close();
  });

  test("a card's number and code in a frame of the page's own origin go there, and the rest into the page", async () => {
    const page = await browser.open("https://login.test/checkout-framed");
    await browser.press(page);
    const request = await asked(browser);
    assert.equal(request.frames.length, 2);
    assert.deepEqual(request.frames[0], { page: true, origin: "https://login.test", fields: ["cardholder", "expiry_month", "expiry_year"] });
    assert.deepEqual({ ...request.frames[1] }, { page: false, origin: "https://login.test", fields: ["number", "security_code"] });
    browser.app.say(`approve-card ${browser.items.Visa}`);
    await browser.app.expect("FILLED");
    await browser.until(page, "✓");
    // The number over the frame's four fields of four digits.
    assert.deepEqual(await page.card(), { ...FILLED, hidden: null });
    await page.close();
  });

  test("a card's number in a frame of another site is not reached, and nothing is asked", async () => {
    const page = await browser.open("https://login.test/checkout-elsewhere");
    await browser.press(page);
    const status = await browser.until(page, "!");
    assert.match(status.title, /card number is in a frame of another site/);
    await browser.app.quiet();
    assert.equal((await page.card()).holder, "");
    await page.close();
  });

  test("a login form is still asked for a login", async () => {
    const page = await browser.open("https://login.test/login");
    await browser.press(page);
    const shown = await browser.app.expect("REQUEST");
    assert.equal(shown.split(" ").length, 4, shown);
    browser.app.say("deny");
    await browser.app.expect("DENIED");
    await browser.until(page, "!", { says: /You denied this request/ });
    await page.close();
  });
});
