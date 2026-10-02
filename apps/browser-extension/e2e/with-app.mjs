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
//
// `OSM_APP_HOME` names the home folder the app runs for, if it is not this
// account's own. With `OSM_BROWSER=firefox` the browser is Firefox, which
// has to be connected in the app's Browser panel beforehand; for Chromium
// the host is registered in the test browser's own scratch folder.
import { start } from "./harness.mjs";

const browser = await start({ appHome: process.env.OSM_APP_HOME ?? process.env.HOME });
try {
  const page = await browser.open("https://login.test/login");
  await browser.press(page);
  console.log("Pressed the extension's button on https://login.test/login. Decide in Open Secret Manager.");
  let said = "";
  for (;;) {
    const status = await browser.status(page);
    if (status.title !== said) {
      said = status.title;
      console.log(`button: ${status.badge || "(no mark)"} ${said.split("\n").slice(1).join(" ")}`);
    }
    if (status.badge !== "…") break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  const form = await page.form();
  console.log(`page: user name ${JSON.stringify(form.username)}, password of ${form.password.length} characters, submitted: ${form.submitted}`);
} finally {
  await browser.close();
}
