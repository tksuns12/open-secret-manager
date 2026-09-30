# Implementation status and delivery plan

This document is for maintainers deciding what can be demonstrated, what remains blocked, and which checks permit the next phase. The repository began empty. The initial delivery is a development prototype; it must not be described as a production password manager, a completed P2P network, or an independently audited security product.

The [threat model](threat-model.md) defines required security boundaries. [Formats](formats.md) describes target storage and protocol contracts. Requirements in those documents are not automatically implementation claims.

## Evidence rules

Use these labels consistently:

- **Implemented:** code exists for a bounded behavior; mention its limits.
- **Verified:** a named check ran successfully against the delivered revision.
- **Scaffold:** an interface, UI, type, or fail-closed placeholder exists, but the full behavior does not.
- **Planned:** no completion claim; prerequisites and acceptance checks remain.
- **Blocked:** execution requires a named missing tool, platform, dependency, or decision.

A dependency in a manifest is not a running integration. A simulated vote function is not OpenRaft. A valid TLS configuration is not a mutually authenticated peer session. A browser extension that refuses requests is a useful safe scaffold, not working autofill. Desktop compilation is not a successful native interaction or platform packaging test.

## Delivery matrix

The following records evidence from the delivered prototype. The Rust rows were
verified with `cargo test --workspace --all-targets` and `cargo fmt --all --
--check` on the current source. Desktop and browser rows remain scaffold or
blocked where their native toolchains were not run; no test success is inferred
from a manifest or dependency declaration.

| Area | Current evidence | Required completion evidence |
| --- | --- | --- |
| Rust vault core | **Verified:** 10 unit tests cover lifecycle, cross-connection CAS revisions, wrong password, tamper, password change, recovery, backup, TOTP, generator, imports, and atomic oversized-import rollback | Add cross-process crash/recovery and fuzz/property coverage before alpha gate |
| Encrypted SQLite records | **Verified:** XChaCha20-Poly1305 records, immutable triggers, authenticated AAD, and plaintext-marker scan in the test database | Repeat scans over sidecar/WAL/journal files on each supported SQLite/platform combination |
| Recovery and encrypted backups | **Verified:** independent recovery unlock, authenticated backup restore to a new path, and tamper rejection | Define and test the post-quorum-loss new vault identity and re-enrollment flow |
| TOTP, generator, imports | **Verified:** RFC 6238 SHA-1 vectors, policy generation, bounded Bitwarden/Chrome/Firefox preview and confirmation | Add SHA-256/512 policy decision, parser fuzzing, and UI confirmation smoke tests |
| Local revisions and conflicts | **Verified:** immutable per-item revision DAG with sorted multi-parent revisions and a derived head set; concurrent edits exchanged in either order converge on the same heads; edit/delete races keep the edit visible; explicit resolution supersedes exactly the reviewed heads while a later head stays visible; missing parents are refused without side effects and retryable; cross-item, unsorted, and duplicate parents rejected; conflicts persist across restart; format 2 vaults migrate without changing signed bytes (5 unit tests) | Desktop conflict review is built but unexercised end to end because no sync path produces conflicts yet |
| Device-signed revisions | **Verified:** per-vault Ed25519 device identity wrapped by the master key; every revision signed and verified against a MAC-authenticated authorized-device table on write, apply, and read; forged, truncated, and relabeled revisions rejected; restore issues a new device identity; format 1 vaults migrate on first unlock with ancestry preserved (4 unit tests) | Authorize signers through committed membership instead of the local table; freeze signed-revision fixtures |
| Unknown-author quarantine | **Verified:** revisions from unauthorized devices are held with exact signed bytes and never merged (`Quarantined`); only vault-key ciphertext is held, bounded at 10,000; replays deduplicated; holds persist across restart and backup/restore; owner accept re-authors content as this device against the same parents (can become a conflict, never overrides local edits) and releases the hold atomically; discard; a later-authorized author's revision applies as-is and releases its hold (4 unit tests) | Desktop review UI once sync can deliver revisions; old-epoch quarantine once key epochs exist |
| Tauri 2 and React desktop | **Verified build:** `npm run typecheck && npm run build`; `cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml` passes; `npx tauri build --bundles app --no-sign` produces the macOS `.app` bundle. Shell exposes create/unlock/lock/list/generator/TOTP and entry create/get/update commands (the stored password and TOTP secret are write-only across the bridge; `cargo test` in `src-tauri` covers keep/replace/remove semantics) and a 5-minute/visibility lock UI | Native OS smoke interaction; package signing, Rust OS suspend/lock hooks, and clipboard behavior on each platform. The default DMG step is blocked by the environment's `bundle_dmg.sh` runtime and is not claimed as a release artifact |
| TLS and pairing | **Planned integration:** no direct TLS socket or discovery implementation is claimed | Real peers, bidirectional pin mismatch rejection, expiry/replay rejection, transcript binding |
| Locked ciphertext receive | **Verified primitive:** signed bounded frames and durable `LockedInbox` receipt/status/quarantine plus child-before-parent deferral tests | Connect inbox to authenticated direct transport and core apply in a two-process test |
| OpenRaft membership | **Implemented/verified boundary:** durable joint→uniform rotation state and position checks; no consensus algorithm is hidden here | Durable OpenRaft multi-process quorum, partition/restart/snapshot tests |
| Device removal and rotation | **Verified primitive:** HPKE recipient envelopes and activation gating tests | Couple activation to committed membership, prove removed recipients cannot decrypt new epochs, crash-test every boundary |
| Browser/native messaging | **Scaffold/verified fail-closed host:** framing, HTTPS origin checks, and unavailable-session responses have unit tests; extension typecheck passes and has no credential storage | Installed allowlist, session-bound desktop IPC, explicit exact-origin fill, navigation/replay/iframe tests in Chromium and Firefox |
| Android and iOS | Planned | Separate lifecycle, secure storage, autofill, background reachability, build/device spike evidence |
| Release security | Planned | Independent review, dependency/security checks, signed packages, upgrade/recovery test matrix |

The current local format and its exact limitations are described in [the prototype contract](formats.md#initial-local-prototype). In particular, a locally authorized signer is not a membership-authorized signer, expected-head rejection is not a multi-device conflict merge, and restoring the same vault identity is not live membership recovery.

## Architecture decisions

1. Keep the Rust vault core independent of UI and networking. Clients use narrow operations and cannot replace core lock or origin checks.
2. Encrypt sensitive record content before SQLite. Public replication metadata is an explicit privacy tradeoff.
3. Separate password-derived local wrappers from random vault epoch keys. Each enrolled device has its own password; recovery is independent.
4. Preserve immutable revision ancestry and visible conflicts. Offline record editing must not depend on an available consensus quorum.
5. Use durable OpenRaft consensus only for membership/control state. Membership changes, revocation, and key activation require quorum; two voters require both online.
6. Use authenticated pinned TLS for peer sessions and RFC HPKE for recipient key envelopes. Neither primitive alone provides enrollment authorization.
7. Keep locked ciphertext receipt separate from decryption, signing, and owner approval. Treat unvalidated ingress as bounded pending state.
8. Require explicit user selection and exact HTTPS origin for browser disclosure. Unavailable native integration fails closed.
9. Recover offline into a new destination first. A stale backup cannot silently replace live membership or clone an existing device writer.

## Phases and dependencies

### Phase 0 — Contracts and platform feasibility

Freeze threat boundaries, serialized fixtures, error taxonomy, and module ownership. Build minimal desktop shells on macOS, Windows, and Linux; separately investigate Android/iOS key storage, process suspension, local networking, and native autofill constraints. Record actual device/OS/toolchain and observed results. A desktop build does not substitute for these spikes.

Acceptance: contributors can identify which process holds every key; test fixtures define exact authenticated bytes; platform-specific unavailable behavior is explicit. Blocking decisions include supported operating systems, minimum versions, distribution/signing identities, and mobile enrollment UX.

### Phase 1 — Local vault vertical slice

Implement the independent core and encrypted SQLite persistence, then wire create/unlock/lock and record operations through Tauri. Add generator, TOTP, import preview, encrypted backup, and independent recovery. Complete a usable offline workflow before connecting remote inputs.

Acceptance: create a vault, save a credential, restart, unlock, edit, lock, reject read while locked, export an encrypted backup, and restore under a new password. Wrong-password/corruption checks and plaintext disk scans pass. Native idle/sleep locking and clipboard cleanup require operating-system smoke checks.

### Phase 2 — Revision integrity

Add device signing identity, immutable revisions, parent validation, tombstones, and conflict resolution. Define how unknown signers and stale epochs are quarantined before network exposure. Migration preserves all existing local records.

Acceptance: two copies independently edit the same ancestor; exchanging revisions in either order preserves both heads; an explicit resolution supersedes exactly those heads. Delete/edit races, invalid signatures, cross-record parents, duplicates, and restart persistence are tested.

### Phase 3 — Authenticated two-device replication

Implement one-use invitations, verified endpoint identities, pinned TLS, bounded framing, inventories, missing-parent retrieval, durable ingress, and resumption. Integrate recipient key envelopes without transferring another device's password wrapper. Initially require direct network reachability; discovery and NAT traversal are separate scope.

Acceptance: two actual processes pair, exchange ciphertext, disconnect/reconnect, and converge after unlock. A locked receiver stores data without decrypting. Wrong pins, invitation replay/expiry, oversized messages, unknown authors, and interrupted writes are rejected safely.

### Phase 4 — Durable membership and rotation

Implement OpenRaft storage/network/state-machine adapters and learner catch-up. Serialize enrollment/removal requests. Add persisted rotation preparation, committed membership reference, recipient envelopes, and epoch activation. Handle no-quorum errors in the UI without unsafe bypasses.

Acceptance: a three-voter test cluster continues with one crash but refuses unauthorized minority changes. Joint transitions survive crashes at each persistence boundary. Removed members cannot obtain the new epoch, retained members eventually can, and incomplete rotation never appears completed. Recovery from total quorum loss explicitly creates a new trust domain.

### Phase 5 — Browser disclosure

Integrate the extension, native host installation, and authenticated local desktop session. Add explicit selection/confirmation, exact HTTPS origin policy, and one-use request binding. Only then enable fill; leave unavailable flows visibly disabled beforehand.

Acceptance: fill a selected top-level HTTPS form without submission. Reject HTTP, subdomains, different ports, cross-origin iframes, stale navigation, replay, lock races, forged extension identity, malformed framing, and requests without an authenticated desktop session. Verify Chromium and Firefox separately if both are claimed.

### Phase 6 — Mobile and release hardening

Implement mobile adapters after the core and enrollment contracts stabilize. Mobile background restrictions must produce honest “last synced” state, not guaranteed always-on reachability. Complete package signing, updater trust, migrations, secure logging review, resource-limit/fuzz tests, and external security review.

Acceptance: reproducible platform packages and real-device lifecycle/autofill tests pass; a documented disaster-recovery exercise succeeds; remaining risks and supported configurations are published.

## Work that can proceed in parallel

Core persistence/cryptography, sync transport primitives, and frontend shell work can run independently after types and errors are agreed. The UI uses an explicit development adapter until the core bridge exists and labels any demonstration data. The sync layer accepts only encrypted envelopes and signed public control data. Browser filling depends on the desktop session and core origin policy; it cannot be made real by a standalone extension patch.

Integration order is core → desktop local workflow → authenticated revision ingress → two-device transport → durable control plane → browser disclosure. Mobile feasibility research may run early, but mobile implementation must reuse the same core contracts rather than fork cryptographic logic.

## Material risks and stopping conditions

| Risk | Consequence | Required response |
| --- | --- | --- |
| Broad initial scope | Security-looking UI can outpace working controls | Deliver verified slices and label missing integrations |
| Key/format changes | Existing vaults or backups become unreadable | Freeze fixtures and add migrations before stable release |
| Plaintext in logs or SQLite side files | Encryption-at-rest claim becomes false | Audit all persistence and test marker absence |
| Incomplete quorum/rotation coupling | Removed device retains future access or owner loses data | Persist transitions, crash-test boundaries, block activation on uncertainty |
| Offline old-epoch writes | Revoked signer can forge plausible past edits | Quarantine pending explicit policy/review |
| Native host without desktop authentication | Web-triggered disclosure bypasses owner intent | Fail closed until session-bound IPC exists |
| Missing platform runtime/toolchain | Build-only claims mistaken for user-visible evidence | Name the missing environment and leave gate open |
| Compromised enrolled device | Raft and signatures do not stop malicious authorized behavior | Disclose trust limit and support explicit removal/recovery |

No checklist entry should be marked verified from design prose, dependency presence, or a skipped check. Record the actual command or manual scenario, outcome, and material limits with the release evidence.
