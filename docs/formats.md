# Storage and protocol contracts

This document is for engineers implementing compatible vault, sync, and client adapters. The project is an early implementation. A design described here is not a stable public file format until there are frozen fixtures, a migration policy, and interoperability tests. [Implementation status](implementation-status.md) separates code from planned contracts.

## Ownership and interfaces

| Component | Owns | Must not own |
| --- | --- | --- |
| Vault core | Lock state; encryption; records; revision validation; backup/recovery; TOTP; generators; import parsing | Webviews, browser permissions, network listeners |
| Sync service | Peer transport; pairing; ciphertext queues; anti-entropy; durable consensus adapters | Record plaintext or password-derived keys |
| Desktop adapter | Core session lifecycle; narrow commands; explicit confirmation; clipboard and operating-system events | Independent cryptographic or origin-policy implementations |
| Browser extension | Browser-derived tab/frame identity; explicit record selection and fill | Persistent vault keys, automatic fill, arbitrary vault enumeration |
| Native host | Bounded framing; extension allowlist; authenticated desktop IPC; origin/request binding | A second unlocked vault process or a plaintext credential cache |

The core exposes create/open/unlock/lock, record list/read/write/delete, conflict inspection/resolution, encrypted backup/restore, password change, generator, TOTP, and import preview/commit operations. Locked access returns an explicit locked error. A ciphertext ingress API has a separate result type: `stored_pending`, `accepted`, `duplicate`, or `rejected`; successful storage is not equivalent to successful validation.

Adapters translate errors to stable categories: locked, authentication failed, invalid input, unsupported format, conflict, not authorized, missing dependency, quorum unavailable, storage failure, and unavailable. Errors and logs must not embed submitted passwords, decrypted records, invitations, or private key bytes.

## Serialization rules

Every persisted envelope and network message has an explicit format version. Unknown versions fail closed. Cryptographic encodings must be deterministic and domain-separated; ordinary JSON object iteration order is not a canonical signature format. Do not sign a map in one language and reconstruct it with a different key order in another.

For the initial Rust implementation, freeze the exact serde struct serialization, field order, integer representation, optional-field behavior, and byte encoding in fixtures before promising portability. The next public wire format must choose one canonical encoding and reject duplicate fields, trailing data, invalid byte lengths, and out-of-range integers. API-facing JSON is distinct from the authenticated byte representation.

Domain separation distinguishes local wrappers, record AAD, revision signatures, revision IDs, invitations, membership commands, HPKE context, and backup authentication. All identities in authenticated headers are covered by the signature or AEAD, never merely copied from an unauthenticated SQL column.

## Initial local prototype

The initial core model uses an `Item` with `id`, `title`, `kind`, `username`, `password`, `url`, `notes`, `totp_secret`, `custom_fields`, `tags`, and `favorite`. `kind` serializes as `login`, `secure_note`, `identity`, or `card`; custom fields use an ordered string map. `VaultItem` pairs the decrypted item with its revision ID. List summaries expose title, username, URL, and favorite status only through the unlocked core API.

`RevisionInfo` contains `item_id`, `revision`, and the sorted `parents` it supersedes. Revisions form a per-item DAG: a revision names zero parents (new item), one (edit or delete), or up to 16 (conflict resolution). Parents must be stored before a child is accepted and must belong to the same item; a missing parent returns `MissingParent` with nothing written so the caller can retry, and a cross-item parent returns `InvalidParent`.

An item's heads are its revisions that no stored revision names as a parent. A new revision removes only the parents it names from the head set, so revisions exchanged in either order converge on the same heads, and a concurrent edit or delete becomes an additional head. More than one head is a conflict: `get` returns the live head with the greatest revision ID (deterministic across devices; a deletion never hides a live edit) with `conflict` set, `versions` returns every head, and `update`/`delete` fail with `Unresolved`. `resolve` writes one revision whose parents are exactly the heads the owner reviewed; a head that arrived after review stays visible. Local writes check their head-set precondition inside the same IMMEDIATE transaction that updates the heads.

A received revision whose author is not in the authorized-device table is quarantined, not merged: `apply_encrypted_revision` returns `Quarantined` and stores the exact signed revision in a separate table that never affects heads. Only a well-formed revision that decrypts with the vault key is held, since the author ID is bound into the AEAD and relabeling it fails decryption; at most 10,000 entries are held (`QuarantineFull`). The owner reviews held revisions with `quarantined`, then either discards one (`discard_quarantined`; if received again it is held again) or accepts it (`accept_quarantined`). Accepting never trusts the unauthorized signature: the content is re-authored and signed by this device against the same parents, so it may become a concurrent head for the owner to resolve, and the held entry is released in the same transaction. If the author is later authorized and the same signed revision arrives, it applies as-is and its held copy is released. Backups carry held revisions.

The signed revision envelope is version 2; the SQLite layout is version 4. Format 2 vaults (one head per item) are migrated by SQL on first unlock without touching signed bytes, and format 3 vaults gain the quarantine table. Backups are version 3; a backup without held revisions restores with none. Each vault holds one device signing identity: a random 16-byte device ID and an Ed25519 key pair. The 32-byte seed is encrypted with the master key under AAD `osm-device-signing-key-v1` plus NUL, the vault ID, device ID, and public key; it is only in memory while unlocked. A restored vault always generates a new device identity and never reuses the source device's key.

Record AAD is the ASCII domain `osm-item-revision-v2` plus a NUL byte, the 32-byte vault ID, length-prefixed UTF-8 item ID, one length-prefixed field holding the sorted parent revision IDs concatenated (each exactly 64 characters, so the field is unambiguous and zero or one parent encodes exactly as the earlier single-parent layout), an unsigned 64-bit key epoch (currently fixed at one), the 16-byte author device ID, and one tombstone byte. Length prefixes are unsigned 64-bit big-endian byte counts. The author signs `osm-revision-signature-v2` plus NUL, followed by length-prefixed AAD, nonce, and ciphertext. The revision ID is lowercase hex SHA-256 over `osm-revision-id-v2` plus NUL, followed by length-prefixed AAD, nonce, ciphertext, and signature, so it identifies the signed envelope.

A revision is accepted, and read, only after `verify_strict` succeeds against a public key in the local authorized-device table; a key carried by a revision is never trusted. Each authorized-device row carries HMAC-SHA256 over `osm-device-authorization-v1` plus NUL, vault ID, device ID, and public key, keyed by a subkey derived from the master key; unlock fails closed if any row does not verify. Initially the table holds only this device, plus the source authors when restored from a backup. It is a local stand-in until committed membership authorizes signers; there is no enrollment path outside tests.

Format 1 vaults (unsigned revisions, no author) are migrated in one transaction on first unlock: every revision is authenticated with the version 1 AAD and ID, then re-sealed and signed by the new local device identity, with parent links remapped. Format 1 backups are rejected with `UnsupportedVersion(1)`; unlock the source vault with a current build and export again.

The local wrapper AAD is `osm-key-wrap-v1` plus NUL, the 32-byte vault ID, and the wrapping-method bytes. The initial non-test Argon2id configuration is 65,536 KiB, three iterations, and one lane. Unit-test builds use a cheaper profile; they are not evidence for production unlock performance. The recovery string is `OSM-RK1-` followed by unpadded base64url encoding of 32 random bytes.

The backup is encrypted with the master key and carries a recovery-key wrapper for that key and the public identities of authorized authors. Restoration preserves the source vault identity while setting a new local password and a fresh device identity. This supports an offline local copy; it is not safe live device enrollment or a completed recovery fork. Before network integration, add explicit current-membership checks, or create a new trust domain on recovery. Sections below describing membership-authorized signers, epochs, author counters, or HPKE integration are target contracts beyond this local format.

## Local storage

SQLite is a transactional container for encrypted values, not an assertion of whole-file database encryption. Titles, usernames, passwords, notes, origins, and TOTP secrets belong inside record ciphertext. Public indexes may contain random identifiers, encrypted revision bytes, ancestry, epochs, and local sync progress. WAL, journal, temporary tables, error logs, and SQLite tracing must not contain plaintext secrets.

A vault header contains its format version, random vault identity, Argon2id salt/parameters, and an authenticated local key wrapper. The wrapper binds the vault identity, format, and KDF parameters. Use 16 or more random bytes for the salt, a 32-byte derived wrapping key, and a fresh 24-byte XChaCha20-Poly1305 nonce. Validate KDF resource bounds before deriving a key. Password changes create and authenticate a new wrapper in one transaction.

The unlocked key bundle contains the current epoch key and any retained historical keys needed to read existing revisions. Signing keys, recipient keys, and transport keys have separate roles. New devices receive their own independent local password wrapper. Copying another device's wrapper is backup replication, not a finished enrollment workflow.

Recommended logical tables are vault metadata, encrypted revisions, parent edges, materialized heads, pending ingress, committed public membership, recipient key envelopes, rotation progress, and sync cursors. Persistent Raft storage additionally needs votes, logs, applied state, and snapshots. These are logical requirements; exact SQL names remain implementation details.

## Immutable record revisions

The target authenticated revision header contains:

| Field | Rule |
| --- | --- |
| `format_version` | Explicit supported integer version |
| `vault_id` | Random stable vault identity; cross-vault copies rejected |
| `record_id` | Random stable record identity |
| `parents` | Sorted, unique revision IDs from the same record |
| `author_device_id` | Identifier resolved through authenticated membership |
| `membership_epoch` | Authorizing committed configuration |
| `key_epoch` | Encryption key selection, authenticated rather than guessed |
| `author_counter` | Durable per-author sequence; useful for replay/rollback diagnostics |
| `nonce` | 24 fresh random bytes for XChaCha20-Poly1305 |

Encrypt the serialized record or tombstone with the header as AAD. Sign a domain-separated encoding of the header and ciphertext with Ed25519. Define the revision ID as a domain-separated SHA-256 digest of the immutable signed envelope. If the prototype uses a random revision ID instead, signature coverage of that ID remains mandatory; a migration is required before substituting content addressing.

Signature validation uses a public key already authorized by membership. An attacker-supplied public key inside the revision is not sufficient. Parent existence and same-record ancestry are checked before acceptance. A missing parent delays materialization; it does not erase existing heads. Wall-clock timestamps are display metadata, not a total-order or revocation authority.

The materialized head set is derived, repairable state. A new revision supersedes only its named ancestors. An explicit conflict resolution names every head the owner resolved. A new concurrent head arriving later remains visible. Deletion is an encrypted tombstone with the same validation rules as an edit.

## HPKE key envelopes

Use an RFC 9180 implementation rather than a custom X25519 construction. The sync primitive currently uses DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM; record XChaCha20-Poly1305 and HPKE AES-256-GCM are different uses and have different nonce handling. Freeze this suite in fixtures before calling it a stable wire format. HPKE's suite identifiers and context handling follow [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).

An envelope binds the protocol version, vault, key epoch, recipient device/key identity, and authorizing membership transition. Its encrypted payload contains the epoch key and matching identifiers. Preserve the HPKE encapsulated key and ciphertext. Use a fixed domain label plus these identifiers as `info`/AAD. An authorized sender signs the envelope or includes it in authenticated committed control state. HPKE base mode alone does not authenticate that sender.

Unwrapping checks the recipient, vault, supported suite, epoch, and committed authorization before activation. Duplicate delivery is idempotent. Transport receipt while locked may store the envelope, but activation requires a later unlocked authorized step.

## Membership and rotation control plane

Record anti-entropy and membership consensus are separate protocols. The record plane exchanges immutable revisions and missing-parent requests. The control plane carries OpenRaft append/vote/snapshot messages plus application commands for enrollment and rotation. Pin authenticated device identity to the Raft node ID; an untrusted RPC field cannot choose another identity.

Application commands have a stable request ID for deduplication and a signed authorization context. Enrollment introduces a learner, verifies catch-up, transitions membership through OpenRaft, and only then makes the corresponding key grant active. Removal stages retained-recipient envelopes and has durable prepared, membership-committed, and epoch-active states. A retry after restart resumes the same request and cannot issue a conflicting epoch.

Do not expose a “force majority” input. Return quorum unavailable when the configured quorum cannot commit. A recovery fork has a new vault/control-plane identity and requires explicit re-enrollment.

## Pairing and sync messages

An invitation needs a version, invitation ID, random single-use secret, expiry, inviter identity/pin, vault identity, and candidate connection addresses. Address discovery is advisory. Invitation redemption persists the one-use decision before reporting success and binds both endpoint keys to the confirmed transcript.

Frame messages with an explicit bounded length and request ID. Negotiate only supported protocol versions without silently falling back to weaker authentication. Inventory, revision batches, missing-parent requests, and acknowledgments expose ciphertext metadata only. Acknowledgments distinguish durable receipt from validated acceptance. Limit message size, revisions per batch, total pending bytes, concurrent peers, and processing time.

The receiver deduplicates before enqueueing where safe, authenticates metadata before accepting it, and stores unknown ancestry or unavailable epochs as pending. Synchronization resumes from persisted state after a crash. Arrival order and duplicate batches must yield the same accepted heads.

### Implemented protocol (Phase 3, milestones 1 and 2)

`osm-vault-peer` implements pairing and sync as sans-IO steps and carries them over TLS 1.3 on TCP. There is no discovery or NAT traversal: the invitation names the inviter's address, and sync dials an address the caller supplies.

Pairing is owner-confirmed and is the interim enrollment authority until committed membership exists, so a vault may have one paired peer (`PeerStore`, `MAX_PEERS = 1`). The invitation text is `OSM-PAIR1-` plus base64url of a postcard body: version 1, vault ID, inviter device ID and Ed25519 public key, the inviter's TLS certificate pin, up to four advisory addresses, a 32-byte one-use token, and an expiry of at most 15 minutes. The token is stored only as a hash (`InvitationStore::issue_pairing`), binds to the first device that redeems it, and is consumed before the joiner is authorized.

The joiner creates its own device identity (`PendingDevice`) and an HPKE key pair, and sends a request signed with the new device key that also names its TLS certificate pin. Both sides hash a transcript: `osm-pairing-transcript-v1` plus NUL, vault ID, inviter device ID, key, and TLS pin, SHA-256 of `osm-pairing-token-v1` plus NUL and the token, joiner device ID, key, HPKE key, and TLS pin, so the short code also confirms both transport identities. The short code both screens show is the first four bytes of SHA-256 of `osm-pairing-sas-v1` plus NUL and the transcript, reduced modulo 1,000,000. The inviter checks the token without consuming it (`InvitationStore::check`) and the request signature before the owner is asked. After the owner confirms, the inviter builds a grant: the vault key sealed to the joiner's HPKE key (the existing epoch-key envelope, recipient = joiner signing key), the recovery wrapper, and the authorized-device list, signed with the inviter's device key. Pairing signatures prefix `osm-pairing-signature-v1` plus NUL so they cannot be confused with revision signatures. The joiner verifies the grant against the key from the invitation, requires the owner's confirmation, and calls `Vault::join`, which creates its vault with its own password and identity; the other device's password wrapper never leaves it.

Transport identity is separate from the revision signing key: each device has a self-signed Ed25519 certificate generated with rcgen and stored in its peer store, which is created with owner-only permissions. The TLS private key is not encrypted, because a locked device must still be able to receive ciphertext; revision authenticity never depends on it. Peers pin the SHA-256 of each other's certificate and ignore names, validity periods, and system roots; the handshake signature still proves possession of the pinned certificate's key. Only TLS 1.3 is offered, client certificates are mandatory, and session resumption is disabled so every connection checks both certificates. During pairing the inviter accepts any client certificate and then requires that the signed join request names exactly the certificate on the connection; the joiner pins the inviter from the invitation. Connections that fail before the owner is asked are dropped and the inviter keeps listening until the invitation window closes. Sync accepts only the paired device's certificate in both directions. Reads and writes run concurrently, each frame has a 60-second timeout, and connects and handshakes have 10-second timeouts.

Frames are a 4-byte big-endian length and a postcard body, at most 24 MiB; the declared length is checked before the body is buffered, and trailing bytes are rejected. A sync session opens with `Hello` (protocol version 1, vault ID) and an `Inventory` of every accepted revision ID. Each side answers the other's inventory with the revisions it lacks, parents first, in `Revisions` batches of at most 64 revisions or 8 MiB, then `Done`. Revisions are the core's signed `EncryptedRevision`s, applied through `apply_encrypted_revision`: unknown authors are quarantined, and any other invalid revision ends the session with nothing stored. A revision whose parent did not arrive is deferred; after `Done` the receiver sends `Need` for missing parents, for at most 8 rounds. `Finished` means a side needs nothing more. Sessions keep no state between runs: an interrupted session is resumed by starting another, since inventories recompute what is missing. Deferred revisions are not persisted yet.

## Backups and recovery

The public backup contract must freeze a magic value, format version, vault identity, cryptographic suite, KDF or recovery-wrapper descriptor, nonce, authenticated manifest, and encrypted payload. Authenticate the manifest and key wrappers. The payload contains a consistent database snapshot or equivalent complete encrypted records and required key material. Copying only the SQLite main file while a WAL transaction is outstanding is not a valid snapshot procedure.

Recovery uses a high-entropy secret independent of the local unlock password. A restore API authenticates before writing and takes a new destination and new local password. It must not overwrite an existing vault by default. Live rejoin creates a fresh device identity; restoring an old signing identity into two writers risks cloned identity and counter reuse.

Plaintext export is a separate deliberate format and action. Import accepts bounded input with a schema/version, produces row-level preview errors, and commits atomically or clearly reports partial behavior. Vendor adapters must map origin, username, password, note, and TOTP fields without silently discarding unknown material.

## TOTP and browser integration

TOTP stores the decoded secret, supported hash algorithm, digit count, and positive time step inside record ciphertext. Validate standard test vectors, explicit time input, and time-step boundaries according to [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). An `otpauth` import must reject malformed Base32 and unsupported parameters rather than guessing.

Native messaging uses browser-defined 32-bit native-endian length-prefixed UTF-8 JSON. The implementation may impose a smaller documented limit than the browser. Reserve stdout for framed protocol responses; diagnostics go to stderr without secrets. Extension identity is explicitly allowlisted during installation, as described by [Chrome's native messaging documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).

The target fill request is `{version, request_id, tab_id, frame_id, document_id, origin, record_id}`. The desktop produces a one-use grant only after explicit selection/confirmation in an unlocked session. The response is bound to the same request and normalized HTTPS origin. No protocol message accepts a master password from page content. A missing desktop session returns unavailable. Exact origin normalization is shared with core policy and tested for default ports, IDNs, trailing dots, userinfo, opaque origins, redirects, and subdomain mismatch.

## Compatibility gate

Before marking any format stable, add binary/JSON fixtures, tamper fixtures, unsupported-version tests, maximum-size tests, and a previous-version migration round trip. Update this document to match the actual serialized structs, including every authenticated field and domain label. Never silently change canonical bytes or interpret a failed authentication as an invitation to try legacy plaintext parsing.
