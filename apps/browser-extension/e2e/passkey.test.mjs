// A site's passkeys, the whole path in a real browser as for a login's
// fill (fill.test.mjs): the built extension with access to all sites, the
// real host, the stand-in for the desktop app serving a real vault, and a
// site whose own server checks what it is sent, with @simplewebauthn/server.

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { BROWSER, start } from "./harness.mjs";

/** The passkey request the stand-in shows next: `[id, origin, ceremony, site, verification]`. */
async function asked(browser) {
  const shown = (await browser.app.expect("REQUEST")).split(" ");
  assert.equal(shown[4], "passkey", shown.join(" "));
  return { id: shown[0], origin: shown[1], ceremony: shown[5], site: shown[6], verification: shown[7] };
}

describe(`a site's passkeys in ${BROWSER}, once the extension has access to all sites`, () => {
  let browser;
  before(async () => {
    browser = await start({ logins: [["site", "https://login.test/login"]], access: true });
  });
  after(() => browser?.close());

  test("a passkey is made and signed in with from the app, and the site's server takes both", async () => {
    const page = await browser.open("https://login.test/passkeys");
    assert.equal(await page.run("window.nativeWebAuthn()"), false);
    await page.click("#register");
    const made = await asked(browser);
    assert.deepEqual([made.origin, made.ceremony, made.site, made.verification], ["https://login.test", "create", "login.test", "preferred"]);
    // The site's login is offered to hold it.
    assert.equal((await browser.app.expect("LOGIN")).split(" ")[0], browser.items.site);
    browser.app.say(`save-passkey ${browser.items.site}`);
    assert.equal(await browser.app.expect("PASSKEY-SENT"), made.id);
    assert.match(await page.result(), /^registered \S+ uv=true backed-up=true$/);
    assert.equal(browser.sitePasskeys().length, 1);

    // Signed in with it, the owner verified, and then not.
    for (const [verified, said] of [["", "uv=true"], [" unverified", "uv=false"]]) {
      await page.click("#sign-in");
      const signIn = await asked(browser);
      assert.equal(signIn.ceremony, "get");
      const [item, credential] = (await browser.app.expect("PASSKEY")).split(" ");
      assert.equal(item, browser.items.site);
      assert.equal(credential, browser.sitePasskeys()[0]);
      browser.app.say(`sign-in ${item} ${credential}${verified}`);
      await browser.app.expect("PASSKEY-SENT");
      assert.equal(await page.result(), `signed-in ${credential} ${said}`);
    }
    await page.close();
  });

  test("the owner's denial reaches the page, and the site's requests then go to the browser for a while", async () => {
    const page = await browser.open("https://login.test/passkeys?denied");
    await page.click("#sign-in");
    await asked(browser);
    browser.app.say("deny");
    await browser.app.expect("DENIED");
    assert.match(await page.result(), /^error NotAllowedError The request was turned down in Open Secret Manager\./);
    // Asked again at once: the app is not asked.
    await page.click("#sign-in");
    await browser.app.quiet(1_500);
    await page.close();
  });

  test("a request the app does not take is the browser's own: one on load, one a frame posts, and one for a page that went", async () => {
    // As the page loads, without the owner's activation.
    const loading = await browser.open("https://login.test/passkeys?on-load");
    await browser.app.quiet(1_500);
    // A message shaped as the page's script's, posted by the page itself
    // without activation, is answered with the browser's own.
    const answer = await loading.run(`new Promise((resolve) => {
      const id = crypto.randomUUID();
      addEventListener("message", (event) => { if (event.data?.type === "answer" && event.data.id === id) resolve(event.data.outcome); });
      postMessage({ channel: "osm-passkey", type: "ask", id, kind: "get", options: "{}", timeout: null }, location.origin);
    })`);
    assert.deepEqual(answer, { fallback: true, waitForFocus: false });
    await loading.close();

    // A frame of another site: no script of the extension in it, and what it
    // posts to the page is not taken.
    const framed = await browser.open("https://login.test/passkeys-framed");
    assert.equal(await framed.runInFrame("window.nativeWebAuthn()"), true);
    await framed.run(`(() => { window.answers = []; addEventListener("message", (event) => { if (event.data?.type === "answer") window.answers.push(event.data); }); return true; })()`);
    await framed.clickInFrame("#post");
    await browser.app.quiet(1_000);
    assert.deepEqual(await framed.run("window.answers"), []);
    await framed.close();

    // A page left while its request waits withdraws it. (Of another
    // origin under the site: the denial above paused login.test's.)
    const leaving = await browser.open("https://www.login.test/passkeys?leaving");
    await leaving.click("#register");
    const waiting = await asked(browser);
    await browser.app.expect("LOGIN");
    await leaving.goto("https://www.login.test/empty");
    assert.equal(await browser.app.expect("ENDED"), waiting.id);
    await leaving.close();
  });

  test("a card's number in another site's frame is reached", async () => {
    const page = await browser.open("https://login.test/checkout-elsewhere");
    await browser.press(page);
    const shown = (await browser.app.expect("REQUEST")).split(" ");
    assert.equal(shown[4], "card");
    assert.equal(shown[5], "2");
    const frames = [await browser.app.expect("FRAME"), await browser.app.expect("FRAME")].map((line) => line.split(" ").slice(1).join(" ")).sort();
    assert.deepEqual(frames, ["https://login.test cardholder,expiry_month,expiry_year", "https://other.test number,security_code"]);
    browser.app.say("deny");
    await browser.app.expect("DENIED");
    await page.close();
  });
});

describe(`a site's passkeys in ${BROWSER} without the extension's access to all sites`, () => {
  let browser;
  before(async () => {
    browser = await start({ logins: [["site", "https://login.test/login"]] });
  });
  after(() => browser?.close());

  test("nothing of the extension runs in pages, and the app hears nothing", async () => {
    const page = await browser.open("https://login.test/passkeys");
    assert.equal(await page.run("window.nativeWebAuthn()"), true);
    await page.click("#register");
    await browser.app.quiet(1_500);
    await page.close();
  });
});

describe(`the browser's own passkeys answer for the app in ${BROWSER}`, () => {
  let browser;
  before(async () => {
    browser = await start({ access: true });
  });
  after(() => browser?.close());

  // Firefox's own WebAuthn refuses a page whose certificate was accepted
  // only because the test told it to ("The operation is insecure"), as the
  // test site's is; a real site's is not.
  test("when the owner chooses them, and when the vault holds none for the site", { skip: BROWSER === "firefox" && "Firefox's own passkeys refuse the test site's certificate" }, async (context) => {
    const page = await browser.open("https://login.test/passkeys");
    try {
      await page.virtualAuthenticator();
    } catch (error) {
      context.skip(`no virtual authenticator here: ${error.message}`);
      return;
    }
    await page.click("#register");
    await asked(browser);
    browser.app.say("use-browser");
    await browser.app.expect("BROWSER");
    assert.match(await page.result(), /^registered \S+ uv=true/);
    // The vault holds no passkey for the site: answered without the app
    // asking the owner.
    await page.click("#sign-in");
    assert.match(await page.result(), /^signed-in \S+ uv=true$/);
    await browser.app.quiet(500);
    await page.close();
  });
});
