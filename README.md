# Open Secret Manager

Open Secret Manager is an owner-controlled, peer-to-peer password manager for
desktop platforms. Every device keeps its own encrypted vault. There is no
account, hosted synchronisation service, relay, or telemetry.

The repository is deliberately split at the security boundary:

- `crates/vault-core` owns the encrypted local vault, unlock state, revisions,
  imports, backups, recovery, password generation, and TOTP.
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
  manifest into that browser's folder.
- `apps/native-host` is the process a browser starts for the extension. It
  holds no vault and no key: it checks each request and passes it to the
  desktop session over a socket only the owner's account can reach.
- `apps/browser-extension` is one WebExtension source tree that builds for
  Chromium and for Firefox. On a press of its toolbar button it asks the
  app for a login for the page's origin and fills the one the owner chooses
  there. It has no access to pages otherwise and stores nothing. It runs in
  headless Chromium tests; Firefox has not been run.

The prototype is intentionally offline-first. Local vault use does not depend
on a peer or a network. Devices pair by invitation and a six-digit code the
owner compares on both screens; the vault's devices then agree, by majority,
to enroll the new one, and any device can later be removed, which moves the
others to a new key. The desktop app does this from its Devices panel and
syncs with every member automatically on the local network; a locked device
still takes part and stores what it receives until the next unlock. There is
no discovery beyond the address in the invitation. With two devices both must
be reachable for any change, so a lost device cannot be removed from a
two-device vault. For that case, and any other in which too many devices are
lost, one device can start over as a new vault with new keys from what it
holds; the others join it again. Three or more devices tolerate one being
lost.

## Development

The Rust workspace is the source of truth for security-sensitive behaviour:

```text
cargo test --workspace
cargo fmt --all -- --check
```

The desktop shell is developed separately because Tauri bundles platform
toolchains and native WebView dependencies:

```text
cd apps/desktop
npm install
npm run tauri:dev
```

The browser package uses the same TypeScript source for Chromium and Firefox:

```text
cd apps/browser-extension
npm install
npm run typecheck
npm run build
npm test
npm run test:e2e
```

`npm run test:e2e` runs the built extension in headless Chromium with the
real native messaging host; see `apps/browser-extension/README.md` for what
it needs.

Before a release, read [the threat model](docs/threat-model.md), [the format
contract](docs/formats.md), and [the implementation status](docs/implementation-status.md).
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
