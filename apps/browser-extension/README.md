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

A card goes the same way into a checkout form, the card's fields into the
page and into its frames of the same site; the app shows which field goes
where.

If the page goes away while the request waits (a navigation, a reload, the
tab closing), the request is withdrawn and a late answer is dropped.

The button shows how the request stands: `…` while the app waits for you,
`✓` after a fill, `!` with an explanation in its tooltip when nothing was
filled.

## What it can and cannot do

Its permissions are `activeTab`, `scripting`, and `nativeMessaging`, and
access to all sites only if you turn it on (below). Without that, it has
no access to a page until you press the button on that page, and then only
to that tab. It runs nothing in pages otherwise, stores nothing, and
shows nothing inside a page. It never receives a list of what your vault
holds: the app shows the choices, and sends back only the one login you
picked.

## Passkeys, and a payment provider's frames

On its options page (in the browser's list of extensions, Options) one
switch gives it access to all sites, which the browser asks you about.
With it on, it puts a small script into every https page, and a page's
request for a passkey goes to the app, which asks you what to do: save a
new passkey there, sign in with one, or leave the request to the
browser's own passkeys. A request the app does not answer, such as one
for a site whose passkeys your vault does not hold, or one made while the
app is not running, goes to the browser's own as if the extension were
not there. The access also lets a press fill a card's number into a
payment provider's frame, which is another site. With the switch off,
nothing of the extension runs in pages. Firefox 128 or later is needed.

It does not save logins or cards, fill on its own, or fill one-time codes,
and it fills a login only into the page itself, never into a frame. A
login is offered only for the exact origin of its stored address; see [the format contract](../../docs/formats.md#implemented-fill-protocol-phase-5-stop-1).

## Installing

From the stores once it is accepted there: Firefox's add-ons site
(addons.mozilla.org) and the Chrome Web Store. Then, in the desktop app,
open Browser and connect that browser, so that it knows where the native
messaging host is. The copy from the Chrome Web Store has an ID of its own,
which the desktop app accepts from version 0.1.1 on; a Chromium browser
connected with an earlier version is shown as connected to something else
until it is connected again.

## Building and loading

With Node 24 (the version the project builds with) and npm:

```text
npm ci
npm run build        # dist/chromium and dist/firefox
```

`scripts/package-extension.sh` makes what the stores take from a commit,
in `dist/extension/<commit>/`: the Firefox add-on, the Chromium extension
without the `key` (the Chrome Web Store sets the ID), and this folder's
source, from which `npm ci && npm run build` makes `dist/firefox` again.

In a Chromium browser, open `chrome://extensions`, turn on Developer mode,
choose Load unpacked, and pick `dist/chromium`. The `key` in the Chromium
manifest fixes the extension's ID, which is the one the native messaging
host allows. Then, in the desktop app, open Browser and connect that
browser, so that it knows where the host is.

In Firefox, open `about:debugging`, choose This Firefox, then Load
Temporary Add-on, and pick `dist/firefox/manifest.json`. A temporary add-on
is gone when Firefox quits; the copy on Firefox's add-ons site, signed by
Mozilla, stays. Then connect Firefox in the app's Browser panel.

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

On macOS the browser starts the host, and the fake host, from a copy in
`~/Library/Caches/OpenSecretManager-tests`, one per build, because a
browser there does not start a program kept on an external disk: the host
is left hanging before it runs, and every test waits at "Asking Open Secret
Manager…" until it fails after 90 seconds. A copy is made the first time a
build is tested and kept, so that macOS checks each build only once; the
copies of older builds are removed. `with-app.mjs`'s `OSM_HOST` is started
where it is.

`node e2e/with-app.mjs` does the same against the desktop app itself, for a
check by hand: it presses the button on a test page and prints what the
button says and what ended up in the page, while you decide in the app.
With `OSM_BROWSER=firefox` it uses Firefox, which has to be connected in
the app's Browser panel first.
With `OSM_HOST` naming the host inside a packaged app, the Chromium check
registers that host, which checks the package as a whole.

The icons in `icons/` are the project's icon at the sizes browsers ask for
(at 16 px, the shield and its keyhole alone), and `store/` holds the Chrome
Web Store's icon, tile, and screenshots. `node scripts/icons.mjs`, at the
repository's root, draws them again with every other size of the icon.
