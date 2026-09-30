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

`RevisionInfo` contains `item_id`, `revision`, and one optional `parent_revision`. The core uses a transactional expected-head comparison to reject a stale write. It does not yet provide membership-authorized authors, multiple parents, replicated head sets, or explicit merging of concurrent peer revisions.

The local format is version 2. Each vault holds one device signing identity: a random 16-byte device ID and an Ed25519 key pair. The 32-byte seed is encrypted with the master key under AAD `osm-device-signing-key-v1` plus NUL, the vault ID, device ID, and public key; it is only in memory while unlocked. A restored vault always generates a new device identity and never reuses the source device's key.

Record AAD is the ASCII domain `osm-item-revision-v2` plus a NUL byte, the 32-byte vault ID, length-prefixed UTF-8 item ID, length-prefixed UTF-8 parent revision (empty for no parent), an unsigned 64-bit key epoch (currently fixed at one), the 16-byte author device ID, and one tombstone byte. Length prefixes are unsigned 64-bit big-endian byte counts. The author signs `osm-revision-signature-v2` plus NUL, followed by length-prefixed AAD, nonce, and ciphertext. The revision ID is lowercase hex SHA-256 over `osm-revision-id-v2` plus NUL, followed by length-prefixed AAD, nonce, ciphertext, and signature, so it identifies the signed envelope.

A revision is accepted, and read, only after `verify_strict` succeeds against a public key in the local authorized-device table; a key carried by a revision is never trusted, and an unknown author is rejected (`UnknownAuthor`), not quarantined. Each authorized-device row carries HMAC-SHA256 over `osm-device-authorization-v1` plus NUL, vault ID, device ID, and public key, keyed by a subkey derived from the master key; unlock fails closed if any row does not verify. Initially the table holds only this device, plus the source authors when restored from a backup. It is a local stand-in until committed membership authorizes signers; there is no enrollment path outside tests.

Format 1 vaults (unsigned revisions, no author) are migrated in one transaction on first unlock: every revision is authenticated with the version 1 AAD and ID, then re-sealed and signed by the new local device identity, with parent links remapped. Format 1 backups are rejected with `UnsupportedVersion(1)`; unlock the source vault with a current build and export again.

The local wrapper AAD is `osm-key-wrap-v1` plus NUL, the 32-byte vault ID, and the wrapping-method bytes. The initial non-test Argon2id configuration is 65,536 KiB, three iterations, and one lane. Unit-test builds use a cheaper profile; they are not evidence for production unlock performance. The recovery string is `OSM-RK1-` followed by unpadded base64url encoding of 32 random bytes.

The backup is encrypted with the master key and carries a recovery-key wrapper for that key and the public identities of authorized authors. Restoration preserves the source vault identity while setting a new local password and a fresh device identity. This supports an offline local copy; it is not safe live device enrollment or a completed recovery fork. Before network integration, add explicit current-membership checks, or create a new trust domain on recovery. Sections below describing membership-authorized signers, epochs, HPKE integration, or multi-parent revisions are target contracts beyond this local format.

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
