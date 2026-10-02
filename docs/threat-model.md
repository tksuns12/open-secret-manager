# Threat model

This document is for contributors deciding whether a change may handle real credentials. It describes the intended security boundary, the attacks that must be tested, and the limits the product must explain. It is a design contract, not evidence that every control exists. See [implementation status](implementation-status.md) for delivery gates and [formats](formats.md) for storage and protocol rules.

## Scope and ownership

The owner keeps an encrypted password vault on their devices. A Rust core owns cryptography and vault state; desktop, browser, and eventual mobile clients are adapters. No provider account, hosted control plane, or third-party recovery service is required. Directly reachable peers exchange ciphertext. Internet discovery, NAT traversal, a relay, and mobile background execution are separate features requiring their own evidence.

The owner controls enrollment and recovery. A device is an authorized replica, not a separate human principal. Consensus establishes one membership history; it does not establish that several humans approved an action.

The protected assets are passwords, usernames, notes, TOTP seeds, recovery material, private device keys, epoch keys, membership authority, and the integrity of revision history. Titles and origins are also sensitive and belong inside record ciphertext. Public routing metadata may reveal vault/device identifiers, revision relationships, approximate sizes, update frequency, and network addresses.

## Trust boundaries

| Boundary | Required behavior |
| --- | --- |
| Disk to unlocked core | Authenticate encrypted envelopes before accepting plaintext. Reject unsupported versions and bounded-but-invalid KDF settings before allocation. |
| Frontend to Rust | Treat every command argument as untrusted. Rust enforces lock state, origin policy, file limits, and authorization. |
| Network to receiver | Pin peer identity, authenticate the connection, bound frames and queues, and distinguish stored ciphertext from accepted history. |
| Received revision to materialized record | Validate signature, authorized author, vault, epoch, ancestry, and AEAD before exposing content. |
| Membership log to active key epoch | Activate a rotation only through committed state and durable envelopes. Resume or fail closed after a crash. |
| Browser page to extension | Page scripts cannot request arbitrary vault reads. User action, current frame identity, and exact HTTPS origin constrain disclosure. |
| Extension to native host | Accept only the installed extension identity and bounded protocol messages; use authenticated local IPC to the desktop session. |
| Recovery artifact to live membership | Restore offline first. A stale backup must not silently recreate an existing live device identity or override current membership. |

Tauri capabilities and a restrictive content security policy reduce frontend authority. They do not excuse missing authorization in Rust. Do not load remote application code, execute arbitrary shell commands, or expose generic filesystem and network commands to the webview. Tauri documents this boundary in its [IPC model](https://v2.tauri.app/concept/inter-process-communication/).

## What the design protects against

- A stolen locked database or encrypted backup must require the correct password or recovery secret to reveal record content.
- A network observer or unpaired machine must not obtain vault plaintext or enroll itself by guessing a device name or address.
- A peer that retransmits, truncates, rearranges, or modifies messages must not silently change an accepted record or membership transition.
- Concurrent offline edits and delete/edit races must remain visible until explicitly resolved; arrival time must not silently select a winner.
- A removed device must not receive future epoch keys after removal completes.
- A malicious web page must not cause automatic fill or obtain credentials for a different origin.

## Limits that must remain explicit

An administrator, debugger, injected process, compromised extension, or compromised operating system can observe secrets while a device is unlocked. Zeroization reduces residual exposure but cannot guarantee erasure of compiler copies, webview strings, swap, crash dumps, clipboard managers, or screenshots. JavaScript must retain revealed secrets only as long as the user action requires.

Encryption does not erase plaintext a peer previously learned. Removing a device cannot retract old epoch keys, old backups, or already copied passwords. Rotating a vault key also does not rotate passwords at external websites; the owner must change exposed credentials there.

Immutable signed revisions reveal tampering, but a completely rolled-back local database can still look internally valid. Without a fresh trusted peer or external checkpoint, the product cannot prove that an isolated snapshot is current. Backup restoration must display that limit.

Raft assumes crash faults, not Byzantine participants. A malicious enrolled voter is outside its consensus safety model. Signatures authenticate an author; they do not make an authorized compromised device honest. OpenRaft is the consensus implementation, not a substitute for application authorization.

A device takes part in Raft under its transport identity, whose key is stored unencrypted so that a locked device can receive. Whoever copies that key and the control-plane database from a device, locked or not, can act as that voter: vote, lead, and write unsigned membership entries. That can stall or corrupt the control plane for the other devices, and the remedy is then recovery into a new trust domain. It must not yield keys or authority, so both follow signed enrollment rather than Raft membership: only a voter whose enrollment a member signed can make a request or be given an epoch key, and a removal seals the next key to enrolled voters only.

Availability depends on device reachability. A single device can use its local vault offline. Membership changes need a majority of the configured voters; a two-voter vault needs both voters. Losing quorum must not enable an unauthenticated emergency removal. An explicit recovery fork creates a new trust domain.

The recovery fork is not a removal. It does not take anything back from a lost device, which keeps every key and record it already had, so the owner must change the passwords it could have seen. It protects what is written afterwards: the new vault has a new identity and new keys that no device of the old vault holds. It needs only one unlocked device and its password, so anyone who can unlock a device can start a new vault from it, but that vault is separate and the old one and its other devices are unaffected. The old vault's files stay on the device in an archive folder, still encrypted under the same password; deleting them is the owner's decision. Nothing tells the other devices that the vault was replaced, and no device's word is taken for it: on each one the owner has its copy put away, with that device's password, before it joins the new vault. That action changes nothing in the old vault's membership. Used on a device of a vault that is still in use, it leaves a member that never answers, which the remaining devices must remove, and with two devices they cannot; the app says so before it is confirmed. Earlier revision history and revisions held for review are not carried into the new vault.

A recovery key that the owner has not yet confirmed storing is kept in the vault, encrypted under the device's root key, so that it can be shown again if the app stops first. Until the owner confirms, anyone who can unlock that device can read the recovery key, and it opens every device of the vault that has recovery turned on, given that device's vault file. Unlocking the device already gives the vault's contents and keys; what the kept recovery key adds is the other devices' own identities. The exposure ends when the owner confirms, which the app asks for after every unlock.

## Local encryption and lock lifecycle

Use a randomly generated 256-bit vault/epoch key to encrypt records with XChaCha20-Poly1305. Bind record identity, vault identity, format version, key epoch, and revision metadata as authenticated additional data. Generate each 24-byte nonce from the operating system random source. Passwords wrap keys; they are not record-encryption keys.

Argon2id derives the local wrapping key using a random salt and persisted parameters. Parameters need upper and lower bounds and device-specific latency measurement. A sensible initial evaluation profile is 64 MiB, three iterations, four lanes; benchmark it on each supported device rather than treating it as a universal mobile setting. The memory-constrained recommendation and tuning rationale are in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).

Lock clears vault decryption keys, signing authority, decrypted record caches, visible secrets, pending fill grants, and sensitive clipboard ownership. A transport identity may remain available for locked ciphertext receipt, but it must be distinct from vault-decryption and membership-signing keys. Persist any transport key only through a documented restricted local credential store. Transport possession alone must never authorize record access, enrollment, removal, or key rotation.

Enforce inactivity and operating-system sleep/session-lock behavior in the native shell. Recheck lock state at the point of disclosure, including after an asynchronous confirmation. Password change atomically replaces the local wrapper; it must not alter a peer's independent unlock password or require plaintext re-encryption of every record.

## Revision integrity and conflicts

Each signed revision belongs to one vault and record and names its parent revisions. Accepted heads are revisions without an accepted descendant for that record. Two heads represent a conflict. A resolution creates a new signed revision naming all resolved heads; it must not delete the history or accidentally include unrelated parents.

Deletion is a revision containing an encrypted tombstone. Delete/edit races remain conflicts. The core rejects cross-record parents, self-parenting, duplicate parents, invalid signatures, impossible epochs, unsupported versions, and oversized payloads. Missing parents are pending dependencies, not permission to invent history.

Receipt may happen out of order. Deduplicate by a cryptographic revision identity, preserve exact signed bytes, and quarantine unsupported or unverifiable entries. Do not report a quarantined entry as successfully merged. An entry from a removed or unknown signer must not become authoritative because its timestamp looks old; timestamp alone does not prove pre-removal authorship.

## Pairing, transport, and locked receipt

An invitation contains a fresh high-entropy one-use secret, short expiry, inviter identity, and an authenticated pin or transcript binding. Verify the device identities through the transferred invitation or an explicit short-authentication-string comparison. Displaying a QR code is not by itself proof of endpoint authenticity. Never log invitations.

TLS must validate proof of possession and the expected peer pin in both directions. Disable broad “accept any certificate” paths. Address discovery is untrusted and cannot replace the identity check. Retry cannot downgrade authentication. Network parsers need size/time limits and rejection before expensive cryptography where possible.

Control-plane connections accept the certificates of the devices a node's own log names and refuse removed devices. A node whose log is behind, or a device still being enrolled, also accepts a certificate that a member vouched for: in the signed enrollment grant, or in the member list a device it already counts as a member sends when a connection opens. This adds no principal that could not already act: a device trusted to send Raft messages can already feed a lagging node a log of its choosing. It does mean a lagging node trusts whatever its last known members trust, including a member that has since been removed, until it catches up. A Raft message is attributed to the device whose certificate the connection presented, never to the sender it names. Revision sync is narrower than the control plane: each end requires the other to be an enrolled member by its own committed state, not removed and not being removed, so a device still being enrolled or merely vouched for exchanges no revisions. A removed device's connection is completed only to tell it that it was removed. It believes that from any member, and the desktop app then resets the device: its copy of the vault is moved to an archive folder beside it, not deleted, and the device is left without a vault until it joins again. A member can therefore make another device put its copy away, including edits that had not synced; they stay in the archive, which the app cannot open yet. This is within what members are already trusted with, since every member is one of the owner's devices and could already refuse the device, but it is the one place where a single device's word, rather than committed state the device has itself applied, changes what another device holds.

When locked, the receiver may store bounded encrypted envelopes and public signed control messages. It cannot decrypt, approve invitations, sign membership changes, or unwrap a new epoch. Verify everything possible with committed public membership, and defer remaining checks. Unlock processes the quarantine transactionally. A disk-full or malformed-message failure must leave existing vault state intact.

HPKE protects epoch material for an enrolled recipient; application signatures and committed membership authorize the sender and recipient. HPKE alone does not provide replay prevention or durable membership semantics, as explained in [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7).

## Membership, removal, and rotation

Keep record convergence separate from the membership control plane. Offline record edits are allowed with the last usable epoch, but enrollment, removal, and epoch activation require a committed control-plane decision. Serialize owner-initiated membership proposals and make retries idempotent.

Use OpenRaft's learner catch-up and joint membership transition. Persist votes, logs, applied state, snapshots, and membership with crash-safe ordering before acknowledging durability. A set of signatures, an in-memory vote count, or a local “majority” function is not a running Raft cluster. OpenRaft describes learner promotion and joint transitions in its [dynamic membership documentation](https://docs.rs/openraft/latest/openraft/docs/cluster_control/dynamic_membership/index.html).

Removal has an explicit pending state. Stage the new epoch and recipient-specific envelopes for retained members, commit the membership transition, and activate the associated epoch only through a durable state-machine decision referencing that transition. If any step is incomplete after a crash, resume it or block new current-epoch writes; never report a fully revoked device while continuing to issue future secrets under an exposed key.

Old-epoch edits may arrive after removal. A device that has learned of a removal holds the removed device's revisions it had not yet accepted for owner review. The owner keeps or rejects each one on any unlocked member: keeping it has that device write a revision with the same content on top of it under the current epoch, and rejecting it has that device write a revision on top of it that keeps the item as it was. Either way the removed device's revision enters each member's history as it was signed, already superseded, and the decision reaches the other members by sync, including one that had taken the revision in before it learned of the removal. The review shows what a held revision would change but never a password or one-time-code secret, only that it differs. This trades automatic convergence for an explicit boundary against a removed signer forging supposedly old edits. There is one causal exception: a held revision that a current member's revision names as a parent is accepted as-is with that child, because the member accepted it and its own history depends on it. So that devices which never saw the removed device's last accepted edits (later joiners in particular) need not review them, the device that made the removal writes, as itself, a revision on top of each of the removed device's remaining heads. The exception means a removed device can still get an edit accepted through a member that had not yet learned of the removal and then built on it; that window lasts until each member applies the committed removal.

## Browser disclosure

Fill requires an explicit user gesture and selection. Match normalized HTTPS scheme, host, and effective port exactly. Neither a registrable-domain match nor a suffix match is sufficient. A credential for `https://example.com` may match `https://example.com:443`; it must not match HTTP, a subdomain, a lookalike host, or port 8443.

The extension obtains the top-level URL and frame identity from browser APIs. The native host repeats origin validation. Bind a short-lived, single-use grant to request ID, tab, frame/document, origin, selected record, and unlocked session. Revalidate immediately before disclosure and immediately before insertion; navigation, lock, timeout, and replay cancel the grant. Initially support only the top-level frame and reject cross-origin iframes. Never auto-submit a form.

Native messaging permits a declared extension allowlist and framed JSON transport; neither feature alone authenticates a website or a desktop unlock session. Follow the browser's [native messaging protocol](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging), and test forged, truncated, and oversized input. A host with no authenticated desktop session must return unavailable, not read a plaintext export or unlock the vault itself.

## Recovery and imports

Generate recovery material from operating-system randomness and display it deliberately. An encrypted backup must carry enough versioned metadata and wrapped keys to restore without a provider. Restoration authenticates the whole archive before replacing anything and creates a separate destination by default. A recovery secret is as sensitive as the vault it can unlock.

Keep encrypted backup and plaintext export separate actions. Imports are bounded, parse without evaluating formulas or markup, report unsupported rows, and require an explicit preview/commit boundary. Do not log import content. Plaintext source files remain on the user's filesystem unless the user removes them; the application must not promise secure deletion on modern storage.

## Release acceptance

Before describing this as suitable for real credentials, require evidence for wrong-password and corruption rejection; authenticated metadata substitution tests; plaintext disk/WAL checks; revision conflict and tamper tests; restore round trips; RFC TOTP vectors; duplicate and out-of-order sync; locked receive; invitation replay; TLS pin mismatch; multi-process partition/restart tests; interrupted removal and rotation; browser navigation/replay/iframe tests; and native session-lock behavior. Dependency review, signed release provenance, platform packaging, and an independent security review remain release work even after unit tests pass.
