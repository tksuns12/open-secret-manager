// The whole path in a real browser: the built extension in headless
// Chromium, the real native messaging host started by the browser, and the
// stand-in for the desktop app serving a real vault. The owner is played by
// commands to the stand-in; the toolbar button is pressed through the
// browser's debugging interface, which grants what a real press grants.

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { formOf, start } from "./harness.mjs";

const EMPTY = { username: "", password: "" };
const fields = ({ username, password }) => ({ username, password });
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The request the stand-in shows next, with the logins it offers. */
async function asked(browser) {
  const [id, origin, kind, count] = (await browser.app.expect("REQUEST")).split(" ");
  const logins = [];
  for (let offered = 0; offered < Number(count || 0); offered += 1) logins.push((await browser.app.expect("LOGIN")).split(" ")[0]);
  return { id, origin, kind, count, logins };
}

describe("with the desktop session and the real host", () => {
  let browser;
  before(async () => {
    browser = await start({
      logins: [
        ["site", "https://login.test/login"],
        ["framing", "https://framing.test/"],
      ],
    });
  });
  after(() => browser?.close());

  test("the owner's choice is filled into the page's own https form, which is not submitted", async () => {
    const page = await browser.open("https://login.test/login");
    assert.deepEqual(fields(await formOf(page)), EMPTY);
    await browser.press(page);

    const request = await asked(browser);
    assert.deepEqual([request.origin, request.kind, request.logins], ["https://login.test", "Chromium", [browser.items.site]]);
    const waiting = await browser.until(page, "…");
    assert.match(waiting.title, /Waiting for you in Open Secret Manager/);
    // Nothing reaches the page before the owner chooses.
    assert.deepEqual(fields(await formOf(page)), EMPTY);

    browser.app.say(`approve ${browser.items.site}`);
    assert.equal(await browser.app.expect("FILLED"), `${request.id} ${browser.items.site}`);
    const done = await browser.until(page, "✓");
    assert.match(done.title, /Filled the user name and password\. The form was not submitted\./);

    const form = await formOf(page);
    assert.deepEqual(fields(form), { username: "site@example.test", password: "site password" });
    // The page saw the values arrive as typing would deliver them, no key
    // presses, and no submission; it is still the same page.
    assert.deepEqual(form.events, ["input:username", "change:username", "input:password", "change:password"]);
    assert.equal(form.submitted, false);
    assert.equal(form.address, "https://login.test/login");
    await page.close();
  });

  test("a form that asks for the user name alone gets only that", async () => {
    const page = await browser.open("https://login.test/name-first");
    await browser.press(page);
    await asked(browser);
    browser.app.say(`approve ${browser.items.site}`);
    await browser.app.expect("FILLED");
    assert.match((await browser.until(page, "✓")).title, /Filled the user name\./);
    assert.equal(await page.inputValue("#username"), "site@example.test");
    assert.equal(await page.evaluate(() => window.seen.submitted), false);
    await page.close();
  });

  test("a page opened over http is refused by the extension itself", async () => {
    const page = await browser.open("http://plain.test/login");
    await browser.press(page);
    const status = await browser.until(page, "!");
    assert.match(status.title, /Only pages opened over https can be filled/);
    await browser.app.quiet();
    assert.deepEqual(fields(await formOf(page)), EMPTY);
    await page.close();
  });

  test("a subdomain and another port are other origins, with no login to offer", async () => {
    for (const [address, origin] of [
      ["https://www.login.test/login", "https://www.login.test"],
      ["https://login.test:8443/login", "https://login.test:8443"],
    ]) {
      const page = await browser.open(address);
      await browser.press(page);
      const request = await asked(browser);
      assert.deepEqual([request.origin, request.count], [origin, "0"], address);
      // The login for the site itself cannot be sent there even if the
      // owner names it.
      browser.app.say(`approve ${browser.items.site}`);
      assert.equal(await browser.app.expect("REFUSED"), "not-for-this-page");
      browser.app.say("deny");
      await browser.app.expect("DENIED");
      assert.match((await browser.until(page, "!")).title, /You denied this request/);
      assert.deepEqual(fields(await formOf(page)), EMPTY, address);
      await page.close();
    }
  });

  test("a form in a frame from another site is not filled, whatever the page around it", async () => {
    // The page has no form of its own: nothing is even asked.
    const framing = await browser.open("https://framing.test/framing");
    const inner = () => framing.frames().find((frame) => frame.url() === "https://login.test/login");
    await framing.waitForFunction(() => document.getElementById("inner") !== null);
    while (!inner()) await pause(50);
    await browser.press(framing);
    assert.match((await browser.until(framing, "!")).title, /No login form was found on this page/);
    await browser.app.quiet();
    assert.deepEqual(await inner().evaluate(() => [document.getElementById("username").value, document.getElementById("password").value]), ["", ""]);
    await framing.close();

    // The page has its own form: that one is filled, with the page's own
    // login, and the frame is left alone.
    const both = await browser.open("https://framing.test/both");
    const framed = () => both.frames().find((frame) => frame.url() === "https://login.test/login");
    while (!framed()) await pause(50);
    await browser.press(both);
    const request = await asked(browser);
    assert.deepEqual([request.origin, request.logins], ["https://framing.test", [browser.items.framing]]);
    browser.app.say(`approve ${browser.items.site}`);
    assert.equal(await browser.app.expect("REFUSED"), "not-for-this-page");
    browser.app.say(`approve ${browser.items.framing}`);
    await browser.app.expect("FILLED");
    await browser.until(both, "✓");
    assert.deepEqual(fields(await formOf(both)), { username: "framing@example.test", password: "framing password" });
    assert.deepEqual(await framed().evaluate(() => [document.getElementById("username").value, document.getElementById("password").value]), ["", ""]);
    await both.close();
  });

  test("a page that goes away takes its request with it", async () => {
    const leave = [
      // To another page of the same site, to another site, by reloading, and by closing the tab.
      ["a same-site navigation", (page) => page.goto("https://login.test/next")],
      ["a navigation elsewhere", (page) => page.goto("https://www.login.test/login")],
      ["a reload", (page) => page.reload()],
      ["closing the tab", (page) => page.close()],
    ];
    for (const [what, go] of leave) {
      const page = await browser.open("https://login.test/login");
      await browser.press(page);
      const request = await asked(browser);
      await go(page);
      assert.equal(await browser.app.expect("ENDED"), request.id, what);
      // The owner choosing now sends nothing anywhere.
      browser.app.say(`approve ${browser.items.site}`);
      assert.equal(await browser.app.expect("REFUSED"), "not-pending", what);
      if (!page.isClosed()) {
        await pause(300);
        assert.deepEqual(fields(await formOf(page)), EMPTY, what);
        assert.equal((await browser.status(page)).badge, "", what);
        await page.close();
      }
    }
  });

  test("a vault that locks before the owner's choice releases nothing", async () => {
    const page = await browser.open("https://login.test/login");
    await browser.press(page);
    await asked(browser);
    browser.app.say("lock");
    await browser.app.expect("LOCKED");
    assert.equal((await asked(browser)).count, "locked");
    browser.app.say(`approve ${browser.items.site}`);
    assert.equal(await browser.app.expect("REFUSED"), "locked");
    await pause(300);
    assert.deepEqual(fields(await formOf(page)), EMPTY);
    assert.equal((await browser.status(page)).badge, "…");

    // Unlocked again, a new choice is filled.
    browser.app.say("unlock");
    await browser.app.expect("UNLOCKED");
    await asked(browser);
    browser.app.say(`approve ${browser.items.site}`);
    await browser.app.expect("FILLED");
    await browser.until(page, "✓");
    assert.deepEqual(fields(await formOf(page)), { username: "site@example.test", password: "site password" });
    await page.close();
  });

  test("one request waits at a time, and pressing again does not make another", async () => {
    const first = await browser.open("https://login.test/login?tab=first");
    const second = await browser.open("https://login.test/login?tab=second");
    await browser.press(first);
    const request = await asked(browser);
    // The same tab again: still the one request.
    await browser.press(first);
    await browser.app.quiet();
    // Another tab: turned away, and told why.
    await browser.press(second);
    assert.match((await browser.until(second, "!")).title, /Another request is waiting in Open Secret Manager/);
    await browser.app.quiet();

    browser.app.say(`approve ${browser.items.site}`);
    assert.equal(await browser.app.expect("FILLED"), `${request.id} ${browser.items.site}`);
    await browser.until(first, "✓");
    assert.deepEqual(fields(await formOf(first)), { username: "site@example.test", password: "site password" });
    assert.deepEqual(fields(await formOf(second)), EMPTY);
    await first.close();
    await second.close();
  });
});

describe("when the request cannot be decided", () => {
  test("a request the owner leaves alone expires", async () => {
    const browser = await start({ logins: [["site", "https://login.test/login"]], standIn: ["ask", "within=2"] });
    try {
      const page = await browser.open("https://login.test/login");
      await browser.press(page);
      const request = await asked(browser);
      assert.equal(await browser.app.expect("ENDED"), request.id);
      assert.match((await browser.until(page, "!")).title, /ran out of time/);
      assert.deepEqual(fields(await formOf(page)), EMPTY);
    } finally { await browser.close(); }
  });

  test("without the desktop app nothing is filled", async () => {
    const browser = await start({ standIn: null });
    try {
      const page = await browser.open("https://login.test/login");
      await browser.press(page);
      assert.match((await browser.until(page, "!")).title, /Open Secret Manager is not running/);
      assert.deepEqual(fields(await formOf(page)), EMPTY);
    } finally { await browser.close(); }
  });

  test("a browser that was not connected cannot start the host", async () => {
    const browser = await start({ logins: [["site", "https://login.test/login"]], registerHost: false });
    try {
      const page = await browser.open("https://login.test/login");
      await browser.press(page);
      assert.match((await browser.until(page, "!")).title, /This browser is not connected to Open Secret Manager/);
      await browser.app.quiet();
      assert.deepEqual(fields(await formOf(page)), EMPTY);
    } finally { await browser.close(); }
  });

  test("another extension is not let through to the host", async () => {
    const browser = await start({ logins: [["site", "https://login.test/login"]], forged: true });
    try {
      assert.notEqual(browser.forgedId, null);
      const page = await browser.open("https://login.test/login");
      // The same code under another extension's identity: the browser
      // refuses to start the host for it.
      await browser.press(page, browser.forgedId);
      assert.match((await browser.until(page, "!", browser.forgedId)).title, /not connected to Open Secret Manager/);
      await browser.app.quiet();
      assert.deepEqual(fields(await formOf(page)), EMPTY);

      // The real one, in the same browser, still works.
      await browser.press(page);
      await asked(browser);
      browser.app.say(`approve ${browser.items.site}`);
      await browser.app.expect("FILLED");
      await browser.until(page, "✓");
      assert.deepEqual(fields(await formOf(page)), { username: "site@example.test", password: "site password" });
    } finally { await browser.close(); }
  });
});

describe("with a host that answers wrongly", () => {
  let browser;
  let tabs = 0;
  before(async () => { browser = await start({ fakeHost: true, standIn: null }); });
  after(() => browser?.close());

  /** Presses the button on a fresh page with the fake host told how to answer. */
  async function pressed(mode) {
    browser.plan(mode);
    tabs += 1;
    const page = await browser.open(`https://login.test/login?tab=${tabs}`);
    await browser.press(page);
    return page;
  }

  test("a right answer is filled once, however often it is repeated", async () => {
    const page = await pressed("twice");
    await browser.until(page, "✓");
    await pause(600);
    const form = await formOf(page);
    assert.deepEqual(fields(form), { username: "fake-user", password: "fake-password" });
    assert.deepEqual(form.events, ["input:username", "change:username", "input:password", "change:password"]);
    assert.equal(form.submitted, false);
    await page.close();
  });

  test("an answer for another tab, frame, document, or origin is not filled", async () => {
    for (const mode of ["other-tab", "other-frame", "other-document", "other-origin"]) {
      const page = await pressed(mode);
      assert.match((await browser.until(page, "!")).title, /was not for this page\. Nothing was filled/, mode);
      assert.deepEqual(fields(await formOf(page)), EMPTY, mode);
      await page.close();
    }
  });

  test("an answer to a request never made, and a message that is not an answer, are ignored", async () => {
    for (const mode of ["other-request", "extra-field", "missing-field", "wrong-kind", "unknown-type"]) {
      const page = await pressed(mode);
      // The request keeps waiting until the fake host turns it down.
      assert.match((await browser.until(page, "!")).title, /You denied this request/, mode);
      assert.deepEqual(fields(await formOf(page)), EMPTY, mode);
      await page.close();
    }
  });

  test("a host that ends without an answer, or sends bytes that are no message, fills nothing", async () => {
    const ended = await pressed("exit");
    assert.match((await browser.until(ended, "!")).title, /connection to Open Secret Manager was lost/);
    assert.deepEqual(fields(await formOf(ended)), EMPTY);
    await ended.close();

    // The browser drops what it cannot read as a message; the request
    // simply stays unanswered.
    const garbled = await pressed("garbage");
    await browser.until(garbled, "…");
    await pause(1000);
    assert.equal((await browser.status(garbled)).badge, "…");
    assert.deepEqual(fields(await formOf(garbled)), EMPTY);
    await garbled.close();
  });

  test("the extension asks for one page's origin, and withdraws when the page goes", async () => {
    const page = await pressed("silent");
    await browser.until(page, "…");
    const address = page.url();
    await page.goto("https://login.test/next");
    // What the host was sent for this page: the request, with nothing of
    // the vault and nothing chosen, and then the withdrawal.
    const sentForThisPage = () => {
      const messages = browser.hostLog().filter((line) => line !== "closed").map((line) => JSON.parse(line));
      const request = messages.filter((message) => message.type === "fill_request").at(-1);
      return { request, cancel: messages.find((message) => message.type === "cancel" && message.requestId === request?.requestId) };
    };
    const deadline = Date.now() + 10_000;
    while (!sentForThisPage().cancel && Date.now() < deadline) await pause(100);
    const { request, cancel } = sentForThisPage();
    assert.deepEqual(Object.keys(request).sort(), ["documentId", "frameId", "origin", "requestId", "tabId", "type", "version"]);
    assert.deepEqual([request.version, request.frameId, request.origin], [1, 0, new URL(address).origin]);
    assert.deepEqual(cancel, { type: "cancel", version: 1, requestId: request.requestId });
    await page.close();
  });
});
