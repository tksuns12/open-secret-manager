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
  both device certificates pinned. The `osm-peer` binary is a development
  CLI for pairing and syncing two vaults from separate processes.
- `apps/desktop` is a Tauri 2/React shell. Its native commands are the only
  route from the interface to the Rust core.
- `apps/browser-extension` is one WebExtension source tree with Chromium and
  Firefox manifests. The extension asks for an explicit, origin-bound fill and
  never stores credentials; the shipped native host fails closed until the
  desktop session adapter is installed.

The prototype is intentionally offline-first. Local vault use does not depend
on a peer or a network. Two devices can pair (owner-confirmed, one peer until
committed membership exists) and sync over pinned TLS while both are unlocked;
receiving while locked, discovery, and the desktop pairing interface are not
done. Membership changes and key rotation remain blocked at the OpenRaft
integration boundary until a committed majority adapter exists.

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
