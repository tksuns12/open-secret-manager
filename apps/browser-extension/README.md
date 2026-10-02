# Browser extension

The extension puts a login you choose in the Open Secret Manager app into
the page you are on. It does one thing, and only when you press its toolbar
button:

1. It takes the tab's address from the browser. A page that was not opened
   over https is refused there and then.
2. It puts a small script into the page's own document, never into a frame
   inside the page, to find the login form. If there is none, it stops.
3. It asks the app, through the native messaging host, for a login for the
   page's origin. The request names the tab, the document, and the origin,
   and nothing else.
4. The app's window comes forward. You choose the login there, or deny.
5. When the answer comes back, the extension checks that it is for exactly
   that request, tab, document, and origin, asks the browser once more what
   the tab shows, and puts the user name and password into the form. It
   does not submit the form.

If the page goes away while the request waits (a navigation, a reload, the
tab closing), the request is withdrawn and a late answer is dropped.

The button shows how the request stands: `…` while the app waits for you,
`✓` after a fill, `!` with an explanation in its tooltip when nothing was
filled.

## What it can and cannot do

Its permissions are `activeTab`, `scripting`, and `nativeMessaging`. It has
no access to any page until you press the button on that page, and then
only to that tab. It runs nothing in pages otherwise, stores nothing, and
shows nothing inside a page. It never receives a list of what your vault
holds: the app shows the choices, and sends back only the one login you
picked.

It does not save logins, fill on its own, fill one-time codes, or fill
forms inside frames. A login is offered only for the exact origin of its
stored address; see [the format contract](../../docs/formats.md#implemented-fill-protocol-phase-5-stop-1).

## Building and loading

```text
npm install
npm run build        # dist/chromium and dist/firefox
```

In a Chromium browser, open `chrome://extensions`, turn on Developer mode,
choose Load unpacked, and pick `dist/chromium`. The `key` in the Chromium
manifest fixes the extension's ID, which is the one the native messaging
host allows. Then, in the desktop app, open Browser and connect that
browser, so that it knows where the host is.

In Firefox, open `about:debugging`, choose This Firefox, then Load
Temporary Add-on, and pick `dist/firefox/manifest.json`. A temporary add-on
is gone when Firefox quits; installing it for good needs it signed by
Mozilla, which has not been done. Then connect Firefox in the app's Browser
panel.

## Checks

```text
npm run typecheck
npm test             # the extension's own checks on addresses and answers
npm run test:e2e           # in headless Chromium, see below
npm run test:e2e:firefox   # the same tests in headless Firefox
```

`npm run test:e2e` needs the host and the stand-in for the app built first
(`cargo build -p osm-native-host -p osm-vault-browser` in the repository
root) and Playwright's Chromium (`npx playwright install chromium`). It
runs the built extension in headless Chromium against test pages served
over https under made-up `.test` names. The native messaging host is the
real binary, started by the browser; the app is played by `osm-fill`, which
runs the app's own session code on a real vault. A second set of tests puts
a host that answers wrongly on purpose in the real one's place.

In Chromium the toolbar button is pressed through the browser's debugging
interface, which grants the tab what a real press grants; nothing there
clicks a real toolbar.

`npm run test:e2e:firefox` runs the same tests in the Firefox installed on
this machine (`/Applications/Firefox.app`, or the program `OSM_FIREFOX`
names), headless, with a scratch home folder and profile, so that your own
Firefox and its settings are not touched. The extension is installed as a
temporary add-on and its toolbar button is clicked in Firefox's own
interface. The driver for Firefox is fetched on first use.

`node e2e/with-app.mjs` does the same against the desktop app itself, for a
check by hand: it presses the button on a test page and prints what the
button says and what ended up in the page, while you decide in the app.
With `OSM_BROWSER=firefox` it uses Firefox, which has to be connected in
the app's Browser panel first.
