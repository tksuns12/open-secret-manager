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
  both device certificates pinned, and couples each vault to the control
  plane (enrollment, removal with key rotation, reconciliation). The
  `osm-peer` binary is a development CLI for pairing and syncing two vaults
  from separate processes.
- `crates/vault-membership` is the membership control plane on OpenRaft:
  signed enrollment and removal requests decided by a Raft majority, with
  SQLite-backed log and state. It also decides key epochs: a removal
  carries the next epoch key sealed to every remaining device, active only
  once the removal completes. It runs in-process in tests; carrying its
  RPCs over pinned TLS and running it in the desktop app is the remaining
  Phase 4 work.
- `apps/desktop` is a Tauri 2/React shell. Its native commands are the only
  route from the interface to the Rust core.
- `apps/browser-extension` is one WebExtension source tree with Chromium and
  Firefox manifests. The extension asks for an explicit, origin-bound fill and
  never stores credentials; the shipped native host fails closed until the
  desktop session adapter is installed.

The prototype is intentionally offline-first. Local vault use does not depend
on a peer or a network. Two devices can pair and sync over pinned TLS; a
locked device stores what it receives and verifies it at the next unlock. The
desktop app pairs from its Devices panel (still the interim, owner-confirmed
path with one peer) and syncs automatically on the local network; there is no
discovery beyond the address in the invitation. In the libraries, pairing
instead proposes the new device to the control plane, so any number of
devices can join, and removing a device rotates the vault key; the desktop
app adopts this once the control plane runs over the network.

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
```

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
