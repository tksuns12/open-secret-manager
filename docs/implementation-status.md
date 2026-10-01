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
| Device-signed revisions | **Verified:** per-vault Ed25519 device identity wrapped by the master key; every revision signed and verified against a MAC-authenticated authorized-device table on write, apply, and read; forged, truncated, and relabeled revisions rejected; restore issues a new device identity; format 1 vaults migrate on first unlock with ancestry preserved (4 unit tests). **Phase 4 milestone 3:** under a control plane, reconciliation mirrors committed authors into the table and records removed devices in a MAC-authenticated revocation table (format 7) | The desktop app does not run the control plane yet, so its signers still come from interim pairing; freeze signed-revision fixtures |
| Unknown-author quarantine | **Verified:** revisions from unauthorized devices are held with exact signed bytes and never merged (`Quarantined`); only vault-key ciphertext is held, bounded at 10,000; replays deduplicated; holds persist across restart and backup/restore; owner accept re-authors content as this device against the same parents (can become a conflict, never overrides local edits) and releases the hold atomically; discard; a later-authorized author's revision applies as-is and releases its hold (4 unit tests). **Removed devices (Phase 4 milestone 3):** a removed device's revisions not yet accepted are held, unless an authorized device's revision builds on them (then accepted as-is with it); the remover endorses the removed device's last heads so later joiners keep them; held revisions are applied once their author is authorized; revocations survive restart and backup/restore (4 core tests, 2 control-plane tests) | Desktop review UI; a removed device can still get an edit accepted through a member that has not yet applied the removal and builds on it |
| Tauri 2 and React desktop | **Verified build:** `npm run typecheck && npm run build`; `cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml` passes; `npx tauri build --bundles app --no-sign` produces the macOS `.app` bundle. Shell exposes create/unlock/lock/list/generator/TOTP and entry create/get/update commands (the stored password and TOTP secret are write-only across the bridge; `cargo test` in `src-tauri` covers keep/replace/remove semantics) and a 5-minute/visibility lock UI. **Pairing and sync (Phase 3 milestone 4):** Devices panel to invite (invitation code, six-digit comparison, confirm or decline) and to sync now; empty-vault screen offers joining from another device; live sync status in the topbar and footer; a background sync listener on port 47820 (or any free port) while the app is open and paired, handshaking before it touches the vault; sync 2 seconds after an edit, at unlock (after staged revisions are verified), and on demand; vault access moved to an async mutex so network waits never block commands, and no lock is held while the owner compares codes. `cargo test` in `src-tauri` runs two mock-runtime shells through the real commands and events: invite, matching codes, confirm, join, first sync, automatic sync in both directions, and receiving while locked | Clicking through the native windows on two machines; Native OS smoke interaction; package signing, Rust OS suspend/lock hooks, and clipboard behavior on each platform. The default DMG step is blocked by the environment's `bundle_dmg.sh` runtime and is not claimed as a release artifact |
| Pairing and sync protocol | **Verified (Phase 3 milestones 1 and 2):** owner-confirmed pairing with one-use expiring invitations, signed transcript-bound request and grant, matching short codes, vault key delivered by HPKE envelope, `Vault::join` with the joiner's own password and identity, one-peer cap (interim path, still used by the desktop app); **Phase 4 milestone 3:** the control-plane path turns the owner's confirmation into an enrollment proposal and a signed enrollment grant, with no device cap; the joiner builds its vault from committed state once it is a voter holding every key; sans-IO sync with inventories, parent-first bounded batches, missing-parent requests, and bounded frames. 10 tests over an in-memory transport through the real frame codec: two-way convergence, conflicts via sync, interrupted-session resume, missing-parent retrieval, unknown-author quarantine, forged revision, vault mismatch, invitation expiry/replay/tampering, unconfirmed codes, oversized and malformed frames | A way to forget a paired device (a grant lost in transit currently leaves the single peer slot used) |
| TLS transport | **Verified (Phase 3 milestone 2):** tokio + rustls (ring) TLS 1.3 with mandatory client certificates, self-signed Ed25519 transport certificates pinned by SHA-256 in both directions, pins bound into the pairing transcript, resumption disabled, concurrent read/write, per-frame and handshake timeouts. 5 in-process tests (pair and sync both directions, unpaired client refused by server, impostor server refused by client, joiner refuses a mismatched inviter, oversized frame over TLS, junk connections ignored and owner decline) and 2 two-process tests with the `osm-peer` CLI (pair with real stdin confirmation, sync both directions over new connections with on-disk state, declined pairing leaves nothing) | Address discovery and NAT traversal; a long-running listener that serves repeated sessions; the TLS key is unencrypted at rest by design and should move to an OS keystore where one exists |
| Locked ciphertext receive | **Verified (Phase 3 milestone 3):** durable ingress queue in the vault file; staging works while locked and checks shape only; processing after unlock verifies and moves each revision into history or quarantine in one transaction, discards and reports forgeries, keeps children waiting for parents across restarts, and stops without discarding on storage failure; bounded at 100,000 revisions or 512 MiB; format 4 vaults gain the queue on open without the key; sync stages first, processes when unlocked, lists staged IDs in its inventory, and requests missing parents while locked; locked devices can also send. 5 core tests, 3 session tests, and a two-process step where the receiving process never has the password | Crash-injection and disk-full tests of processing; the older `vault-sync` `LockedInbox` and single-parent frame format are superseded and unused |
| OpenRaft membership | **Verified in-process (Phase 4 milestones 2 and 3):** OpenRaft 0.9 with SQLite log, vote, state-machine, and snapshot storage, each database bound to one vault; device IDs as node IDs with RPC sender pinning; signed, deduplicated, vault-bound control requests authorized against the committed membership at apply time; membership changes recorded as replicated intents and driven to completion by whichever node leads, with explicit learner catch-up before enrollment; unsigned completions so a locked leader can finish a change; genesis, enrollment cancellation, key grants, and request forwarding from followers. 11 cluster tests over an in-process network: three voters survive a leader crash and remove the lost device; an isolated leader cannot commit (`QuorumUnavailable`) while the majority proceeds and the old leader converges after healing; unauthorized, forged, other-vault, invalid, concurrent, duplicate, and premature requests are refused; nothing changes before genesis and genesis happens once; a crash after the proposal applies and after the joint and uniform entries are appended or applied is resumed by the next leader, for enrollment and for removal, with exactly one rotation; forged RPC identities are refused; the cluster resumes after every device restarts; an unreachable device never becomes a voter before catching up; the live leader can be removed; a stalled enrollment is cancelled and its learner removed | RPCs over the pinned TLS transport and multi-process tests (milestone 4); snapshot install exercised in tests |
| Key epochs and device roots | **Verified (Phase 4 milestone 1):** per-device root keys that never leave the device; epoch keys wrapped by the root; records under the current epoch with older epochs readable; generate/install/activate epoch; revisions under an unknown epoch wait in the ingress queue for the key; per-device optional recovery verified against a public recovery check; pairing sends every epoch key in its own HPKE envelope and never the root; backups carry epoch keys; format 5 vaults re-root at the next password unlock with revision rows unchanged. 6 core tests (including that a removed device's keys open neither a later epoch key in another device's file nor a newer backup) and a pairing test across two epochs; the desktop app prompts a joined device to enable recovery. **Phase 4 milestone 3:** a long-lived HPKE recipient key per device (format 7, derived from a root-wrapped secret); a write fence, raised while locked, that stops writes until the committed epoch is active; committed key checks for every epoch | Running it in the desktop app (milestone 4) |
| Device removal and rotation | **Verified in-process (Phase 4 milestone 3):** a removal carries the next epoch key sealed to exactly the remaining voters and checked by the state machine; the epoch becomes current only in the entry completing the removal; each remaining device installs and activates it on reconciliation (a locked device fences writes first); the removed device never receives it and cannot read later revisions, which wait in its queue; its later edits are held by the others; without a quorum the removal returns `QuorumUnavailable` and nothing changes, and while the change is pending no device activates the new epoch; a retry after an unknown outcome is recognized, not a second rotation; a later joiner receives every epoch and treats the removed device as removed. 6 core tests, 11 cluster tests, and 4 tests with real vaults on an in-process cluster (enrollment beyond two devices, removal with a locked member, quorum loss and a pending removal, cancelled enrollment) | Over the network and in the desktop app (milestone 4); a 2-device vault cannot remove a lost device and must recover into a new trust domain (milestone 4 UI) |
| Browser/native messaging | **Scaffold/verified fail-closed host:** framing, HTTPS origin checks, and unavailable-session responses have unit tests; extension typecheck passes and has no credential storage | Installed allowlist, session-bound desktop IPC, explicit exact-origin fill, navigation/replay/iframe tests in Chromium and Firefox |
| Android and iOS | Planned | Separate lifecycle, secure storage, autofill, background reachability, build/device spike evidence |
| Release security | Planned | Independent review, dependency/security checks, signed packages, upgrade/recovery test matrix |

The current local format and its exact limitations are described in [the prototype contract](formats.md#initial-local-prototype). In particular, a locally authorized signer is not a membership-authorized signer unless it was reconciled from committed state, expected-head rejection is not a multi-device conflict merge, and restoring the same vault identity is not live membership recovery.

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
