# For an outside reviewer

Open Secret Manager is a password manager in which each device keeps its own
encrypted vault and the devices sync with each other directly on a local
network, with no server. This packet says what to look at and in what order,
where the evidence is, and what we would most like a reviewer to answer. It
has not been reviewed by anyone outside the project; this is the request.

## Read first

1. [Threat model](threat-model.md): the attackers, the boundaries, and what
   is out of scope.
2. [Formats](formats.md): every stored and wire format, frozen since Phase
   6a, with the rules for changing one.
3. [Implementation status](implementation-status.md): the evidence for each
   part, labelled by how it was checked, and what each part still lacks.
4. [Release](release.md): the supported configurations, the remaining risks
   we publish, and how a package is built and checked.
5. [Disaster recovery](disaster-recovery.md): what the owner keeps and does
   when devices are lost.

## The code

About 67,000 lines of Rust, TypeScript, Kotlin, and Swift, tests included. Each part below counts the lines of the source files `git ls-files` lists in its folders (`.rs`, `.ts`, `.tsx`, `.mjs`, `.kt`, `.swift`), tests included, frozen fixtures and generated bindings left out, rounded to the hundred (Phase 15); `apps/desktop/src-tauri` is counted without its `session` folder, which has its own row.

| Part | Lines | What it does | Look at |
| --- | --- | --- | --- |
| `crates/vault-core` | 13,000 | The encrypted vault: keys, revisions, signatures, the history of each item, held revisions, backups, recovery, imports | `src/crypto.rs` (every primitive and each AAD); `src/storage.rs`: `verify_revision`, `validate_shape`, `is_active_author`, `apply_encrypted_revision`, `restore_backup`, `fork`, `reset_password` |
| `crates/vault-membership` | 5,100 | Which devices belong to a vault, decided by a Raft majority (OpenRaft 0.9) over signed requests | `src/state.rs`: `is_enrolled`, `complete`, and how keys and authority follow signed enrollment rather than Raft membership |
| `crates/vault-peer` | 11,800 | Pairing with a six-digit code the owner compares on both screens, sync, and the members' channel, over TLS 1.3 with pinned certificates; the relay (`osm-relay`) and a device's way through it | `src/pairing.rs`: `transcript`, `short_code`; `src/transport.rs`: frame limits before authentication, and `run_session` (it reads the peer's frames while it sends); `src/session/inventory.rs`: how two devices compare what they hold, and what a peer's IDs must be; `src/control.rs`: what a vault takes from committed membership; `src/members.rs`: `take_in` and `AddressBook::claim` (which addresses a roster may change, and whose); `src/relay.rs`: what the relay checks, and that a device registers only under its own certificate's pin |
| `crates/vault-sync` | 2,300 | Key envelopes (HPKE) and one-use invitation tokens | the envelope and token code and its fixtures |
| `crates/origin` | 280 | The one rule for which page a login may be filled into | all of it |
| `crates/browser-link`, `apps/native-host`, `crates/vault-browser` | 4,400 | The browser fill path: messages and frames, the host a browser starts (it holds no vault), and the desktop's end where a request waits for the owner | `crates/vault-browser/src/desk.rs`: `approve`; `apps/native-host/src/main.rs`: what it checks before passing a request on |
| `apps/desktop/src-tauri` | 9,800 | The desktop app's native side: commands, devices and sync, the browser socket, archives, backups, imports, settings, and the count in the keystore that finds the vault's file set back (`src/rows_seen.rs`) | `src/lib.rs` (which secrets cross to the window: the stored password, one-time secret, and other fields' values never do), `src/import.rs` (an export is read here and only counts reach the window), `src/browser.rs` (`approve_fill`), `src/network.rs` (`recover_vault`, `restore`) |
| `apps/desktop/src-tauri/session` | 1,100 | The only `unsafe` code in the project: registering for macOS notifications, to lock on sleep and screen lock | `src/macos.rs` |
| `apps/desktop/src`, `apps/browser-extension/src` | 3,200 | The window, and the extension | `apps/browser-extension/src/background.ts` (what a reply must match before it is filled) |
| `crates/mobile` | 3,700 | The phone apps' one interface to the shared code (UniFFI bindings for Kotlin and Swift): a device of a vault that joins without a vote, unlocks, reads, writes, fills, saves, and syncs while the app is open | `src/runtime.rs`: `logins_for_web`, `fill_for_web`, `fill_for_app`, `save_candidates`, `update_password`; `src/lib.rs`: what crosses into Kotlin and Swift |
| `apps/mobile/android` | 6,500 | The Android app and its autofill service | `app/.../autofill/Requester.kt` (when a page's domain is believed), `FillActivity.kt`, `SaveActivity.kt` and `PendingSave.kt` (what a save may change, and where the form's password waits), `BiometricUnlock.kt`, `VaultApp.kt` and `VaultSession.onBackground` (locking when the app is left, at once or after the time chosen), `VaultAutofillService.kt` (what the system's list and the keyboard's strip name while the vault is unlocked), `ScanInvitation.kt` (what a scanned QR code may be, and that no frame is kept) |
| `apps/mobile/ios` | 3,700 | The iOS app and its AutoFill extension | `Shared/FillRequester.swift` (who asks, from what iOS says), `AutoFill/FillModel.swift` (`fill`, `saveNew`, `update`), `Shared/BiometricUnlock.swift`, `App/VaultModel.swift` (`wentToBackground`), `App/ScanInvitation.swift` |

Everything else in the Rust workspaces forbids `unsafe`. Nothing writes a
log.

## Trust boundaries in one paragraph each

**Disk.** A vault file holds ciphertext, signed revision headers, and
wrapped keys. The password (Argon2id) or the recovery key unwraps a
per-device root key, which unwraps the rest. Since format 8 (Phase 10) a
seal under the root key covers which rows the file holds; rows a file
writer takes out or changes are reported at the next unlock. A file
writer can still roll the file back, whole or the sealed rows together with
their seal, without detection; that is a published risk.

**Devices.** Every revision is signed by its device and verified against
the vault's authorized authors before it joins the history; anything else
is held for the owner. Which devices are authors follows signed enrollment
and removal, committed by a majority of the devices. Raft itself is not
trusted for authority: its membership entries carry no signature.

**Network.** Members talk over TLS 1.3 with both certificates pinned in
committed membership. Before authentication, frames are limited to 64 KiB
and to a time limit. Pairing binds both sides to a transcript whose short
code the owner compares. Since Phase 16 a device keeps several addresses
for each other (its VPN's, IPv6), and may reach them through a relay the
owner runs (`osm-relay`), which joins two connections by one-use tickets
and passes the devices' pinned TLS along: it sees which pins talk, when,
and how much, and can drop connections, but not read or pass for a
device. Its code, with a token that only admits to it, is kept in the
vault and, unsealed, in each device's peer store.

**Browser.** The extension asks only when the owner presses its button; the
host relays and checks; the desktop app releases a login only when the
owner picks it in the app, for the page's exact origin, and only under the
unlock the choice was made in.

**Phones.** A phone runs the same shared code as a member without a vote,
locks when its app leaves the screen, and can keep its password behind the
phone's biometrics; on Android the owner can have it stay unlocked for 1,
5, or 15 minutes after the app is left (a minute unless changed), and the
screen turning off locks it at once. Its autofill fills only after the
owner unlocks and chooses on the app's own screen; on Android, while the
vault stays unlocked, the system's list under a field, or the keyboard's
strip, names the logins offered there, and choosing one fills it. On Android a page's domain is believed
only from a browser on Google's published list, checked by its signing
certificate, and Android does not say the page's port; any other app is
offered only logins the owner chose for it. On iOS the system says who
asks; an app it names by nothing gets a choice the owner makes after a
warning. A save of what another app's form sent can change only the
password of a login that form could be filled with; anything else is a new
login, and nothing is written before the owner unlocks and chooses.

## The evidence

- `scripts/check.sh --network --browsers` runs every check: formatting,
  lints with warnings as errors, 320 Rust tests (the vault, membership,
  pairing and sync in process, between processes, and in desktop shells),
  the extension's 19 tests in headless Chromium and Firefox, and the
  dependency policy and advisory audits. With `--mobile` it also runs the
  phone tests: the bindings in an iOS simulator and on an Android emulator,
  and the two apps' UI and autofill tests through the real shared code. With
  `--linux` it runs the desktop's Linux code in a container, and drives
  the real app there end to end (pairing, backup and restore, archive, a
  conflict settled through its review). The desktop window's own tests
  (`apps/desktop/window/`) run in headless WebKit on its browser preview
  every time, and the fuzz targets are linted and audited; with `--fuzz`
  they also run, five minutes each by default.
- Frozen formats: files every build reads, in each crate's `fixtures/`.
- Property tests on every parser that takes outside input, and crash tests
  that kill a process writing to a vault (Phase 6a stop 2); coverage-guided
  fuzzing of six of those parsers, `scripts/fuzz.sh` (Phase 13), with the
  inputs it has found kept in `fuzz/corpus/` (Phase 14).
- The release scripts and the reproducibility check: see
  [release.md](release.md).

## What we would most like answered

1. Is any secret disclosed to a party the threat model excludes: to a device
   that was removed, to a page other than the login's exact origin, or to
   the window of the desktop app?
2. Can a device that was never enrolled, or was removed, get its revisions
   accepted or be given a key, by any sequence of Raft entries, requests,
   or sync messages? (A property test found one such path in Phase 6a and
   it was fixed; see `is_enrolled`.)
3. Are the AAD and signature domains in `crypto.rs` enough to keep values
   from one place being accepted in another?
4. Is the pairing transcript and its six-digit code a sound way to bind the
   two devices, given that the owner compares it by eye?
5. Is anything in the frozen formats a mistake that will be costly to keep?
6. On the phones, is it sound to believe a page's domain from the browsers
   on Google's list, and to let the owner pick a login for an app that
   cannot be checked against its address?
7. Is the relay sound as a party that sees only TLS between devices: its
   tickets travel in the clear, its token lives in the vault and in each
   peer store, and a removed device keeps the token until the owner makes
   a new one?

## What is known to be missing

The full list is the right-hand column of the delivery matrix in
[implementation-status.md](implementation-status.md). In short: no outside
review until this one; packages signed with a developer identity and
notarized are waiting on that identity; coverage-guided fuzzing runs on
request, minutes per parser, not continuously; the native lifecycle locks
were tried for real on macOS for a screen lock and a sleep (Phase 14), and after a screen saver and a user switch the app was found locked without saying by what (Phase 15),
on Linux only in a container; the backup screens and the system's file dialogs
were driven in the real app only on Linux; the phone apps have run only on
an emulator and in a simulator, and are not signed for distribution; the iOS app's AutoFill tests pass on the iOS 26.5 simulator only with AutoFill turned on by the script, as neither 26.5 nor 27.0 simulators here show the system's prompts for it reliably.
