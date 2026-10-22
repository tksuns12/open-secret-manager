// A check by hand of the whole thing with the real desktop app: opens a
// headless Chromium with the built extension, registered with the real
// host, for the account the app is running for; opens a test login page at
// https://login.test/login; and presses the extension's button.
//
// The request then waits in the app. Put a login with the address
// https://login.test/login into the vault beforehand to have one to choose.
// This prints what the button says and what ended up in the page: the user
// name, and only the length of the password.
//
//   npm run build && node e2e/with-app.mjs
//   npm run build && node e2e/with-app.mjs passkey
//
// With `passkey`, the extension has access to all sites (in Chromium a copy
// that lists it as needed, in Firefox the switch on its options page, which
// Firefox asks about), and it opens a test site that signs in with
// passkeys, https://login.test/passkeys, and presses its Register button
// and then its Sign in button, each waiting for the decision in the app;
// it prints what the site's own server made of each. The passkey made is
// one for login.test, saved in the vault: remove it afterwards.
//
// `OSM_APP_HOME` names the home folder the app runs for, if it is not this
// account's own. With `OSM_BROWSER=firefox` the browser is Firefox, which
// has to be connected in the app's Browser panel beforehand; for Chromium
// the host is registered in the test browser's own scratch folder, and
// `OSM_HOST` names the host to register in place of the one the repository
// builds: the one inside a packaged app, to check that app as a whole.
import { start } from "./harness.mjs";

const passkey = process.argv[2] === "passkey";
const browser = await start({ appHome: process.env.OSM_APP_HOME ?? process.env.HOME, hostProgram: process.env.OSM_HOST || null, access: passkey });
try {
  if (passkey) {
    const page = await browser.open("https://login.test/passkeys");
    for (const [button, said] of [["#register", "Register"], ["#sign-in", "Sign in"]]) {
      await page.click(button);
      console.log(`Pressed ${said} on https://login.test/passkeys. Decide in Open Secret Manager.`);
      console.log(`page: ${await page.result()}`);
    }
    process.exit(0);
  }
  const page = await browser.open("https://login.test/login");
  await browser.press(page);
  console.log("Pressed the extension's button on https://login.test/login. Decide in Open Secret Manager.");
  let said = "";
  let begun = false;
  for (;;) {
    const status = await browser.status(page);
    const text = status.title.split("\n").slice(1).join(" ");
    const now = `${status.badge || "(no mark)"} ${text}`;
    // The mark and the words are set one after the other, so a mark
    // without words, or words without a mark, is not the end yet.
    if (status.badge && text && now !== said) {
      said = now;
      console.log(`button: ${now}`);
    }
    if (status.badge || text) begun = true;
    if ((status.badge === "✓" || status.badge === "!") && text) break;
    // Nothing on the button any more: the request was withdrawn.
    if (begun && !status.badge && !text) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  const form = await page.form();
  console.log(`page: user name ${JSON.stringify(form.username)}, password of ${form.password.length} characters, submitted: ${form.submitted}`);
} finally {
  await browser.close();
}
