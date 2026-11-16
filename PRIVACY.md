# Privacy

Open Secret Manager collects nothing about you. There is no account, no
server of the project's, no analytics, no crash reporting, and nothing the
apps or the browser extension send to the project or to anyone else.

## What stays where

- **Your vault** is a file on each of your devices, encrypted with a key
  only your password (or your recovery key) unlocks. The project never sees
  it.
- **Sync** goes directly between your own devices, over TLS with each
  device's certificate pinned, on your network, over your own VPN, or
  through a relay you run yourself. A relay passes the encrypted connection
  along and can read nothing of it.
- **Nothing is logged** to a file, and nothing is sent anywhere for
  diagnosis.

## The browser extension

The extension (for Chromium-based browsers and Firefox) only passes
requests between the page you are on and the Open Secret Manager desktop
app on the same computer, through the browser's native messaging. It makes
no network requests, keeps no data of its own, and never receives a list of
what your vault holds.

- When you press its button (or its keyboard shortcut), it reads the
  address of that tab and its login or card fields, asks the desktop app,
  and fills only what you choose there, into that page.
- If you turn on the option for passkeys and payment frames, the browser
  asks you to let it read and change https pages; it then puts a small
  script into each page, so that a site's request for a passkey goes to the
  desktop app, which asks you before anything is signed. With the option
  off, it reaches only the page you press its button on.

## The phone apps

The Android and iOS apps hold their own encrypted copy of your vault and
sync with your other devices as above. They fill logins into other apps and
pages only after you unlock and choose one. The camera is used only to scan
an invitation's QR code, and no picture is kept.

## Questions

Open an issue at <https://github.com/tksuns12/open-secret-manager/issues>.
To report a weakness privately, see [SECURITY.md](SECURITY.md).
