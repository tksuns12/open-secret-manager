# Open Secret Manager

Open Secret Manager is an owner-controlled, peer-to-peer password manager for
desktop platforms. Every device keeps its own encrypted vault. There is no
account, hosted synchronisation service, relay, or telemetry.

The repository is deliberately split at the security boundary:

- `crates/vault-core` owns the encrypted local vault, unlock state, revisions,
  imports (which the desktop app offers for Bitwarden, Chrome, and Firefox
  exports), backups, recovery, password generation, and TOTP.
- `crates/vault-sync` owns authenticated ciphertext transport primitives,
  invitations, locked receipt, and epoch key envelopes. It never receives a
  plaintext record. Direct TLS sockets and the OpenRaft adapter are explicit
  integration work, not hidden behind this crate.
- `crates/vault-peer` owns owner-confirmed pairing and the revision sync
  protocol as sans-IO steps over bounded frames, carried over TLS 1.3 with
  both device certificates pinned, couples each vault to the control
  plane (enrollment, removal with key rotation, reconciliation), and carries
  the control plane's own messages and sync between any two members over
  the same pinned TLS. The `osm-peer` binary is a development CLI that runs
  one device of a vault as a process.
- `crates/vault-membership` is the membership control plane on OpenRaft:
  signed enrollment and removal requests decided by a Raft majority, with
  SQLite-backed log and state. It also decides key epochs: a removal
  carries the next epoch key sealed to every remaining device, active only
  once the removal completes. Tests run it in-process, over TLS between
  listeners in one process, between separate device processes, and in the
  desktop shell.
- `crates/origin` is the one rule for which page a login may be filled
  into: HTTPS, the exact host, and the exact port.
- `crates/browser-link` defines what the browser extension, the native
  messaging host, and the desktop session say to each other. It cannot open
  a vault.
- `crates/vault-browser` is the desktop session's end of a browser fill: a
  request waits there until the owner picks a login for the page's exact
  origin or turns it down. The `osm-fill` binary is a development stand-in
  for the app.
- `apps/desktop` is a Tauri 2/React shell. Its native commands are the only
  route from the interface to the Rust core. While it is open it also
  listens for the native messaging host, shows each request from a browser
  for the owner to decide, and connects a browser by writing the host's
  manifest into that browser's folder. Its `session` crate is what it needs
  from macOS directly: notice of sleep, a screen lock, or a user switch, on
  which the app locks, and a clipboard entry that stays on this Mac and out
  of clipboard history.
- `apps/native-host` is the process a browser starts for the extension. It
  holds no vault and no key: it checks each request and passes it to the
  desktop session over a socket only the owner's account can reach.
- `apps/browser-extension` is one WebExtension source tree that builds for
  Chromium and for Firefox. On a press of its toolbar button it asks the
  app for a login for the page's origin and fills the one the owner chooses
  there. It has no access to pages otherwise and stores nothing. Its tests
  run it in headless Chromium and in headless Firefox.
- `crates/mobile` is the interface the phone apps use, through Kotlin and
  Swift bindings that UniFFI generates: one device of a vault, which joins
  from another device without a vote, unlocks, shows and copies what the
  vault holds, writes logins and notes, fills logins and saves those
  another app's form sent, and syncs while the app is open.
- `apps/mobile` holds the Android and iOS apps, which join a vault from a
  computer, unlock with their password or a fingerprint or face, show and
  copy what the vault holds, create and edit logins and notes, fill logins
  into other apps and into pages once the owner unlocks and chooses one,
  save a login another app or a page sent once the owner unlocks and
  chooses where, and sync while open.
  `scripts/test-mobile.sh` runs their tests on an emulator and in
  simulators; see `apps/mobile/README.md`.

The prototype is intentionally offline-first. Local vault use does not depend
on a peer or a network. Devices pair by invitation and a six-digit code the
owner compares on both screens; the vault's devices then agree, by majority,
to enroll the new one, and any device can later be removed, which moves the
others to a new key. The desktop app does this from its Devices panel and
syncs with every member automatically on the local network; a locked device
still takes part and stores what it receives until the next unlock. There is
no discovery beyond the address in the invitation. Each device is invited
either to vote or not: the devices that vote decide together, and a change
needs most of them reachable, so with two voters both must be. A device that
does not vote, such as a phone, holds the keys and syncs like the others and
never holds a change up; a vault of one voting computer can remove a lost
phone alone. When too many voting devices are lost to remove them, one device
can start over as a new vault with new keys from what it holds; the others
join it again. Three or more voting devices tolerate one being lost.

A backup is one encrypted file the app saves where you choose and reads back
at once; it opens with the vault's recovery key. If every device is lost, a
new computer restores it as a new vault, and the recovery key also replaces a
forgotten password. [Disaster recovery](docs/disaster-recovery.md) says what
to keep and what to do in each case.

## Development

The Rust workspace is the source of truth for security-sensitive behaviour.
Every check the project has runs from one script; there is no CI, so run it
before a commit:

```text
scripts/check.sh              # formatting, lints, all tests, both interfaces, licenses,
                              # and the desktop window in headless WebKit
scripts/check.sh --network    # also the advisory audits of every dependency
scripts/check.sh --browsers   # also the extension in headless Chromium and Firefox
scripts/check.sh --mobile     # also both phone apps, in a simulator and on an emulator
scripts/check.sh --linux      # also the desktop's Linux code and the real app end to end,
                              # in a Linux container
```

The window's tests need Playwright's WebKit once: `npx playwright install webkit`
in `apps/desktop`.

Every dependency has to come from the official registry under a license a
GPL-3.0 program may include (`dependency-policy.json`, checked by
`scripts/dependencies.mjs`). Advisories the audit reports and the project
accepts are listed with their reasons in `.cargo/audit.toml`; any other one,
a yanked crate included, fails the check.

The storage and wire formats are frozen: each crate's `fixtures/` folder holds
files written by the code, which the tests read with every build. Read
[the format contract](docs/formats.md#frozen-formats-phase-6-stop-1) before
changing what is stored or sent; a frozen file is never edited or made again.

The desktop shell is developed separately because Tauri bundles platform
toolchains and native WebView dependencies:

```text
cd apps/desktop
npm install
npm run tauri:dev
```

`npm run tauri:build` packages the app. It builds the native messaging host
from the Rust workspace and puts it inside the package, beside the app's own
program, which is where the app looks for it when you connect a browser in
its Browser panel. A development run finds the host where the workspace
builds it (`cargo build -p osm-native-host`).

The browser package uses the same TypeScript source for Chromium and Firefox:

```text
cd apps/browser-extension
npm install
npm run typecheck
npm run build
npm test
npm run test:e2e
npm run test:e2e:firefox
```

The last two run the built extension in headless Chromium and in headless
Firefox with the real native messaging host; see
`apps/browser-extension/README.md` for what they need.

Before a release, read [the threat model](docs/threat-model.md), [the format
contract](docs/formats.md), and [the implementation status](docs/implementation-status.md).
[Release](docs/release.md) states the supported configurations and the
remaining risks, and how a package is built, reproduced, and checked;
[the review packet](docs/review-packet.md) is the starting point for an
outside reviewer.
They distinguish implemented primitives from the integration and platform
review gates that remain for a public stable release.

## Security boundary

The delivered core protects vault records at rest and authenticates the bounded
sync envelopes it handles. It does not yet claim a complete network path, and
it does not protect a device while its vault is unlocked, a compromised owner
device, a malicious enrolled consensus participant, or secrets that were
already displayed or copied. Raft-style membership control handles crashes and
partitions; it is not Byzantine fault tolerance. A public stable release must
complete an independent security review.
