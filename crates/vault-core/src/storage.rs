use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        decrypt, derive_password_key, device_authorization, device_key_aad, device_revocation,
        encrypt, epoch_key_aad, key_wrap_aad, keys_equal, legacy_record_aad, legacy_revision_id,
        random_array, recipient_key_aad, record_aad, recovery_check, revision_id,
        revision_signature_message, row_mark, row_marks, row_seal_aad, row_seal_key,
        sealed_device_key_aad, verify_device_authorization, verify_device_revocation,
        verify_recovery_check, xor_into, KdfConfig, RowSets, SecretKey, DEVICE_ID_LEN, KEY_LEN,
        NONCE_LEN, PUBLIC_KEY_LEN, SALT_LEN, SIGNATURE_LEN,
    },
    BackupCheck, DeletedItem, Error, FillCredentials, ForkReport, HistoryVersion, IngressReport,
    Item, ItemKind, ItemSummary, ItemVersion, Origin, QuarantinedRevision, RecoveryKey, Result,
    RevisionInfo, StageOutcome, UnlockSession, VaultItem,
};

/// What a version holds: the item's fields as JSON, with `saved_at` (the
/// time it was saved, in seconds since 1970) beside them; a deletion holds
/// `saved_at` alone. Builds before Phase 15 wrote no time, and an empty
/// deletion.
#[derive(Serialize)]
struct Saved<'a> {
    #[serde(flatten)]
    item: &'a Item,
    saved_at: u64,
}

pub(crate) fn version_plaintext(
    item: Option<&Item>,
    saved_at: Option<u64>,
) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(match (item, saved_at) {
        (Some(item), Some(saved_at)) => serde_json::to_vec(&Saved { item, saved_at })?,
        (Some(item), None) => serde_json::to_vec(item)?,
        (None, Some(saved_at)) => format!("{{\"saved_at\":{saved_at}}}").into_bytes(),
        (None, None) => Vec::new(),
    }))
}

/// When a version says it was saved: `None` if it does not say, or says
/// it in any other way than one whole number of seconds.
pub(crate) fn saved_at(plaintext: &[u8]) -> Option<u64> {
    #[derive(Deserialize)]
    struct Time {
        saved_at: Option<u64>,
    }
    serde_json::from_slice::<Time>(plaintext).ok()?.saved_at
}

/// This device's clock, in seconds since 1970.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Storage layout: a per-device root key wraps the device key, the HPKE
/// recipient secret, the authorized-author and revocation MACs, and the
/// vault's epoch keys; a write fence holds writes until a committed epoch is
/// active; and a seal under the root key covers the rows that are never
/// changed or removed, so that one taken out shows.
const VAULT_FORMAT_VERSION: u32 = 8;
/// Format 8 without the row seal; sealed at the next unlock, which needs the
/// root key.
const MEMBERSHIP_FORMAT_VERSION: u32 = 7;
/// Per-device root keys without revocations, a recipient secret, or a write
/// fence; gains them when opened, without the key.
const ROOT_KEY_FORMAT_VERSION: u32 = 6;
/// One shared vault key for everything; re-rooted at the next password
/// unlock.
const SHARED_KEY_FORMAT_VERSION: u32 = 5;
/// Quarantine but no ingress queue; migrated without the key on open.
const QUARANTINE_FORMAT_VERSION: u32 = 4;
/// Multi-head layout without a quarantine table; migrated on first unlock.
const MULTI_HEAD_FORMAT_VERSION: u32 = 3;
/// Signed revisions with one head per item; migrated by SQL on first unlock.
const SINGLE_HEAD_FORMAT_VERSION: u32 = 2;
/// Unsigned revisions without an author; migrated on first unlock.
const LEGACY_FORMAT_VERSION: u32 = 1;
/// Signed revision envelope. Unchanged by the multi-head layout because a
/// single parent encodes identically.
const RECORD_FORMAT_VERSION: u32 = 2;
const BACKUP_FORMAT_VERSION: u32 = 4;
/// Upper bound on heads one revision may supersede.
const MAX_PARENTS: usize = 16;

/// The item ID under which a vault notes the backups its devices save
/// (since Phase 15): one deletion for each backup, which says when it was
/// saved, so that every device of the vault learns of it by syncing. No
/// item may take it, and it is never listed. Builds before Phase 15 list
/// neither it nor a deletion with nothing before it, and do not read a
/// deletion's content.
pub const BACKUPS_ID: &str = "osm-backups";

/// The item ID under which a vault keeps the code of the relay its devices
/// use (since Phase 16): one deletion for each time the owner set it or took
/// it away, whose content is `{"saved_at": <seconds>, "relay": <code or
/// null>}`; the latest is the vault's. Like [`BACKUPS_ID`], no item may take
/// it, and it is never listed.
pub const RELAY_ID: &str = "osm-relay";

/// The item IDs the vault keeps notes of its own under.
pub(crate) const RESERVED_IDS: [&str; 2] = [BACKUPS_ID, RELAY_ID];

/// A note of the vault's own, opened, and the device that wrote it.
type Note = (Zeroizing<Vec<u8>>, [u8; DEVICE_ID_LEN]);

/// Longest relay code the vault keeps.
const MAX_RELAY_CODE: usize = 1024;

/// What a note of the vault's relay holds.
#[derive(Serialize, Deserialize)]
struct RelaySetting {
    saved_at: u64,
    relay: Option<String>,
}
/// Upper bound on held revisions awaiting owner review.
const MAX_QUARANTINE: i64 = 10_000;
/// Bounds on received revisions awaiting processing.
const MAX_INGRESS: i64 = 100_000;
const MAX_INGRESS_BYTES: i64 = 512 * 1024 * 1024;
/// The epoch every vault starts in, and the only epoch older formats used.
const FIRST_EPOCH: u64 = 1;
/// Bounds on epochs, so a malformed revision or grant cannot name absurd
/// values.
const MAX_EPOCH: u64 = 1 << 32;
pub(crate) const MAX_EPOCHS: usize = 1024;
const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ITEM_BYTES: usize = 16 * 1024 * 1024;

/// `password_*` and `recovery_*` wrap this device's root key (format 6) or
/// the shared vault key (older formats). Recovery is optional per device;
/// `recovery_check` verifies a typed recovery key before it is enabled, and
/// `legacy_recovery_*` keeps a re-rooted vault's old recovery wrapper only
/// for that check.
const VAULT_META_TABLE: &str = r#"
CREATE TABLE vault_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    format_version INTEGER NOT NULL,
    vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
    kdf_memory_kib INTEGER NOT NULL,
    kdf_iterations INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    password_salt BLOB NOT NULL CHECK(length(password_salt) = 16),
    password_nonce BLOB NOT NULL CHECK(length(password_nonce) = 24),
    password_wrapped_key BLOB NOT NULL CHECK(length(password_wrapped_key) = 48),
    recovery_nonce BLOB CHECK(recovery_nonce IS NULL OR length(recovery_nonce) = 24),
    recovery_wrapped_key BLOB CHECK(recovery_wrapped_key IS NULL OR length(recovery_wrapped_key) = 48),
    recovery_check BLOB CHECK(recovery_check IS NULL OR length(recovery_check) = 32),
    legacy_recovery_nonce BLOB
        CHECK(legacy_recovery_nonce IS NULL OR length(legacy_recovery_nonce) = 24),
    legacy_recovery_wrapped_key BLOB
        CHECK(legacy_recovery_wrapped_key IS NULL OR length(legacy_recovery_wrapped_key) = 48),
    current_epoch INTEGER NOT NULL DEFAULT 1 CHECK(current_epoch >= 1),
    device_id BLOB NOT NULL CHECK(length(device_id) = 16),
    device_public_key BLOB NOT NULL CHECK(length(device_public_key) = 32),
    device_key_nonce BLOB NOT NULL CHECK(length(device_key_nonce) = 24),
    device_wrapped_signing_key BLOB NOT NULL CHECK(length(device_wrapped_signing_key) = 48),
    recipient_nonce BLOB CHECK(recipient_nonce IS NULL OR length(recipient_nonce) = 24),
    recipient_wrapped_secret BLOB
        CHECK(recipient_wrapped_secret IS NULL OR length(recipient_wrapped_secret) = 48),
    write_fence INTEGER NOT NULL DEFAULT 1 CHECK(write_fence >= 1),
    row_seal BLOB CHECK(row_seal IS NULL OR length(row_seal) = 72),
    rows_changed INTEGER NOT NULL DEFAULT 0 CHECK(rows_changed IN (0, 1))
) STRICT;
"#;

/// Format 7 columns, added to a format 6 `vault_meta` in place. The
/// recipient secret needs the root key, so it is filled at the next unlock.
const FORMAT_7_COLUMNS: &str = r#"
ALTER TABLE vault_meta ADD COLUMN recipient_nonce BLOB
    CHECK(recipient_nonce IS NULL OR length(recipient_nonce) = 24);
ALTER TABLE vault_meta ADD COLUMN recipient_wrapped_secret BLOB
    CHECK(recipient_wrapped_secret IS NULL OR length(recipient_wrapped_secret) = 48);
ALTER TABLE vault_meta ADD COLUMN write_fence INTEGER NOT NULL DEFAULT 1 CHECK(write_fence >= 1);
"#;

/// The connection's own record of the sealed rows it adds, so that each
/// write adds their marks to the seal without reading every row. These are
/// temporary: they live in the connection's memory, never in the file, and
/// a write that is rolled back takes its entries with it.
const SEAL_TRACKING: &str = r#"
CREATE TEMP TABLE IF NOT EXISTS sealed_rows_added(set_name TEXT NOT NULL, row_key ANY);
CREATE TEMP TRIGGER IF NOT EXISTS sealed_revision_added AFTER INSERT ON main.revisions
BEGIN INSERT INTO sealed_rows_added VALUES('revisions', CAST(NEW.revision AS BLOB)); END;
CREATE TEMP TRIGGER IF NOT EXISTS sealed_device_added AFTER INSERT ON main.devices
BEGIN INSERT INTO sealed_rows_added VALUES('devices', NEW.device_id); END;
CREATE TEMP TRIGGER IF NOT EXISTS sealed_revocation_added AFTER INSERT ON main.revoked_devices
BEGIN INSERT INTO sealed_rows_added VALUES('revoked_devices', NEW.device_id); END;
CREATE TEMP TRIGGER IF NOT EXISTS sealed_epoch_added AFTER INSERT ON main.epoch_keys
BEGIN INSERT INTO sealed_rows_added VALUES('epoch_keys', NEW.epoch); END;
"#;

/// Format 8 columns, added to a format 7 `vault_meta` at the unlock that
/// seals it: the seal, and whether an unlock found it broken and the owner
/// has not yet been told.
const FORMAT_8_COLUMNS: &str = r#"
ALTER TABLE vault_meta ADD COLUMN row_seal BLOB CHECK(row_seal IS NULL OR length(row_seal) = 72);
ALTER TABLE vault_meta ADD COLUMN rows_changed INTEGER NOT NULL DEFAULT 0 CHECK(rows_changed IN (0, 1));
"#;

/// Authorized devices that committed membership has removed. Their stored
/// revisions stay readable; a revision of theirs not yet accepted is held
/// for review unless an authorized device has built on it. Each row carries
/// a MAC keyed by a subkey of the root key; rows are never changed or
/// removed.
const REVOCATIONS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS revoked_devices (
    device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16) REFERENCES devices(device_id),
    revocation BLOB NOT NULL CHECK(length(revocation) = 32)
) STRICT;
CREATE TRIGGER IF NOT EXISTS revoked_devices_no_update BEFORE UPDATE ON revoked_devices
BEGIN SELECT RAISE(ABORT, 'revocations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS revoked_devices_no_delete BEFORE DELETE ON revoked_devices
BEGIN SELECT RAISE(ABORT, 'revocations are immutable'); END;
"#;

/// The vault's recovery key, wrapped by the root key, from when a vault is
/// made until the owner confirms having stored the key. The table is made
/// when a key is first kept and is absent from every other vault.
const UNCONFIRMED_RECOVERY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS unconfirmed_recovery (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    nonce BLOB NOT NULL CHECK(length(nonce) = 24),
    wrapped_key BLOB NOT NULL
) STRICT;
"#;

const DEVICES_TRIGGER: &str = r#"
CREATE TRIGGER devices_no_update BEFORE UPDATE ON devices
BEGIN SELECT RAISE(ABORT, 'device authorizations are immutable'); END;
"#;

const DEVICES_SCHEMA: &str = r#"
CREATE TABLE devices (
    device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
    public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
    authorization BLOB NOT NULL CHECK(length(authorization) = 32)
) STRICT;
"#;

/// Each epoch key wrapped by this device's root key. Rows are never changed
/// or removed: older epochs stay readable.
const EPOCH_KEYS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS epoch_keys (
    epoch INTEGER PRIMARY KEY CHECK(epoch >= 1),
    nonce BLOB NOT NULL CHECK(length(nonce) = 24),
    wrapped_key BLOB NOT NULL CHECK(length(wrapped_key) = 48)
) STRICT;
CREATE TRIGGER IF NOT EXISTS epoch_keys_no_update BEFORE UPDATE ON epoch_keys
BEGIN SELECT RAISE(ABORT, 'epoch keys are immutable'); END;
CREATE TRIGGER IF NOT EXISTS epoch_keys_no_delete BEFORE DELETE ON epoch_keys
BEGIN SELECT RAISE(ABORT, 'epoch keys are immutable'); END;
"#;

/// `parents` holds the sorted parent IDs concatenated (64 characters each).
/// `heads` holds every revision of an item that no stored revision names as
/// a parent; more than one row for an item is an unresolved conflict.
const RECORD_SCHEMA: &str = r#"
CREATE TABLE revisions (
    revision TEXT PRIMARY KEY CHECK(length(revision) = 64),
    format_version INTEGER NOT NULL CHECK(format_version = 2),
    vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
    item_id TEXT NOT NULL CHECK(length(item_id) BETWEEN 1 AND 128),
    parents TEXT NOT NULL CHECK(length(parents) % 64 = 0 AND length(parents) <= 1024),
    key_epoch INTEGER NOT NULL CHECK(key_epoch >= 1),
    author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 16) REFERENCES devices(device_id),
    nonce BLOB NOT NULL CHECK(length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 16777232),
    tombstone INTEGER NOT NULL CHECK(tombstone IN (0, 1)),
    signature BLOB NOT NULL CHECK(length(signature) = 64)
) STRICT;
CREATE INDEX revisions_item_id ON revisions(item_id);
CREATE TRIGGER revisions_no_update BEFORE UPDATE ON revisions
BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
CREATE TRIGGER revisions_no_delete BEFORE DELETE ON revisions
BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
CREATE TABLE heads (
    revision TEXT PRIMARY KEY REFERENCES revisions(revision),
    item_id TEXT NOT NULL CHECK(length(item_id) BETWEEN 1 AND 128),
    tombstone INTEGER NOT NULL CHECK(tombstone IN (0, 1))
) STRICT;
CREATE INDEX heads_item_id ON heads(item_id);
"#;

/// Revisions from devices outside the authorized set, with their exact
/// signed bytes. They are never materialized; the owner accepts (re-authors)
/// or discards each one.
const QUARANTINE_SCHEMA: &str = r#"
CREATE TABLE quarantine (
    revision TEXT PRIMARY KEY CHECK(length(revision) = 64),
    format_version INTEGER NOT NULL CHECK(format_version = 2),
    vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
    item_id TEXT NOT NULL CHECK(length(item_id) BETWEEN 1 AND 128),
    parents TEXT NOT NULL CHECK(length(parents) % 64 = 0 AND length(parents) <= 1024),
    key_epoch INTEGER NOT NULL CHECK(key_epoch >= 1),
    author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 16),
    nonce BLOB NOT NULL CHECK(length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 16777232),
    tombstone INTEGER NOT NULL CHECK(tombstone IN (0, 1)),
    signature BLOB NOT NULL CHECK(length(signature) = 64)
) STRICT;
CREATE TRIGGER quarantine_no_update BEFORE UPDATE ON quarantine
BEGIN SELECT RAISE(ABORT, 'quarantined revisions are immutable'); END;
"#;

/// Received revisions not yet processed, with their exact signed bytes:
/// staged while locked, or waiting for a parent. Nothing here has been
/// verified; processing moves each row into `revisions` or `quarantine` in
/// the same transaction that deletes it.
const INGRESS_SCHEMA: &str = r#"
CREATE TABLE ingress (
    revision TEXT PRIMARY KEY CHECK(length(revision) = 64),
    format_version INTEGER NOT NULL CHECK(format_version = 2),
    vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
    item_id TEXT NOT NULL CHECK(length(item_id) BETWEEN 1 AND 128),
    parents TEXT NOT NULL CHECK(length(parents) % 64 = 0 AND length(parents) <= 1024),
    key_epoch INTEGER NOT NULL CHECK(key_epoch >= 1),
    author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 16),
    nonce BLOB NOT NULL CHECK(length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 16777232),
    tombstone INTEGER NOT NULL CHECK(tombstone IN (0, 1)),
    signature BLOB NOT NULL CHECK(length(signature) = 64)
) STRICT;
CREATE TRIGGER ingress_no_update BEFORE UPDATE ON ingress
BEGIN SELECT RAISE(ABORT, 'staged revisions are immutable'); END;
"#;

const REVISION_COLUMNS: &str = "r.format_version,r.vault_id,r.item_id,r.parents,r.key_epoch,\
     r.author_device_id,r.nonce,r.ciphertext,r.tombstone,r.signature";

/// A sealed revision: ciphertext bound by AEAD to its header, signed by the
/// author device over that header and ciphertext.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRevision {
    pub format_version: u32,
    pub vault_id: [u8; 32],
    pub item_id: String,
    /// Sorted, unique revision IDs of the same item that this revision
    /// supersedes: none for a new item, one for an edit, several for a
    /// conflict resolution.
    pub parents: Vec<String>,
    pub key_epoch: u64,
    pub author_device_id: [u8; DEVICE_ID_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub tombstone: bool,
    /// Ed25519 signature (64 bytes) by `author_device_id`.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for EncryptedRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedRevision")
            .field("format_version", &self.format_version)
            .field("vault_id", &"[REDACTED]")
            .field("item_id", &self.item_id)
            .field("parents", &self.parents)
            .field("key_epoch", &self.key_epoch)
            .field("author_device_id", &self.author_device_id)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("tombstone", &self.tombstone)
            .finish()
    }
}

impl EncryptedRevision {
    pub fn revision_id(&self) -> String {
        revision_id(&self.aad(), &self.nonce, &self.ciphertext, &self.signature)
    }

    fn aad(&self) -> Vec<u8> {
        record_aad(
            &self.vault_id,
            &self.item_id,
            &self.parents,
            self.key_epoch,
            &self.author_device_id,
            self.tombstone,
        )
    }

    fn validate_shape(&self, expected_vault_id: &[u8; 32]) -> Result<()> {
        if self.format_version != RECORD_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(self.format_version));
        }
        if &self.vault_id != expected_vault_id
            || self.item_id.is_empty()
            || self.item_id.len() > 128
            || self.ciphertext.len() < 16
            || self.ciphertext.len() > MAX_ITEM_BYTES + 16
            || self.signature.len() != SIGNATURE_LEN
            || self.parents.len() > MAX_PARENTS
            || !self.parents.iter().all(|parent| is_revision_id(parent))
            // Strictly increasing: sorted and free of duplicates, so every
            // device derives the same AAD bytes for the same parent set.
            || self.parents.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Crypto);
        }
        if self.key_epoch == 0 || self.key_epoch > MAX_EPOCH {
            return Err(Error::Crypto);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Header {
    format_version: u32,
    vault_id: [u8; 32],
    kdf: KdfConfig,
    password_salt: [u8; SALT_LEN],
    password_nonce: [u8; NONCE_LEN],
    password_wrapped_key: Vec<u8>,
    /// `None` until recovery is enabled on this device.
    recovery: Option<KeyWrapper>,
    recovery_check: Option<[u8; 32]>,
    /// A re-rooted vault's old recovery wrapper, kept only to check a
    /// recovery key typed to re-enable recovery.
    legacy_recovery: Option<KeyWrapper>,
    current_epoch: u64,
    /// `None` only for a format 1 vault that has not been unlocked yet.
    device: Option<DeviceHeader>,
    /// This device's HPKE recipient secret, wrapped by the root key. `None`
    /// until a vault from before format 7 is unlocked.
    recipient: Option<KeyWrapper>,
    /// The earliest epoch new revisions may use. Raised, never lowered,
    /// when committed membership activates a later epoch; it works while
    /// locked, so writes stop until this device has that epoch's key.
    write_fence: u64,
    /// An unlock or a write found rows taken out of the file or changed in
    /// it, and the owner has not confirmed seeing it.
    rows_changed: bool,
}

#[derive(Clone)]
struct KeyWrapper {
    nonce: [u8; NONCE_LEN],
    wrapped_key: Vec<u8>,
}

#[derive(Clone)]
struct DeviceHeader {
    device_id: [u8; DEVICE_ID_LEN],
    public_key: [u8; PUBLIC_KEY_LEN],
    key_nonce: [u8; NONCE_LEN],
    wrapped_signing_key: Vec<u8>,
}

/// Public device identity carried in backups so restored revisions verify.
#[derive(Serialize, Deserialize)]
struct DeviceRecord {
    device_id: [u8; DEVICE_ID_LEN],
    public_key: [u8; PUBLIC_KEY_LEN],
}

pub struct Vault {
    path: PathBuf,
    connection: Connection,
    header: Header,
    /// This device's root key while unlocked. It never leaves the device.
    root_key: Option<SecretKey>,
    /// Every epoch key this device holds, while unlocked.
    epoch_keys: BTreeMap<u64, SecretKey>,
    signing_key: Option<SigningKey>,
    /// Authorized revision authors, loaded and authenticated at unlock.
    devices: BTreeMap<[u8; DEVICE_ID_LEN], VerifyingKey>,
    /// Authors removed by committed membership, loaded and authenticated at
    /// unlock.
    revoked: BTreeSet<[u8; DEVICE_ID_LEN]>,
    /// Secret behind this device's HPKE recipient key, while unlocked.
    recipient_secret: Option<SecretKey>,
    /// Names this unlock, while unlocked.
    session: Option<UnlockSession>,
}

/// Seals revisions for one author. Borrowing the keys separately from the
/// connection lets callers seal while holding a write transaction.
struct RevisionSigner<'a> {
    /// The key of `epoch`, which revisions are sealed under.
    key: &'a SecretKey,
    epoch: u64,
    signing_key: &'a SigningKey,
    vault_id: [u8; 32],
    author: [u8; DEVICE_ID_LEN],
}

impl RevisionSigner<'_> {
    fn seal(
        &self,
        item_id: &str,
        parents: Vec<String>,
        tombstone: bool,
        plaintext: &[u8],
    ) -> Result<EncryptedRevision> {
        let nonce = random_array::<NONCE_LEN>();
        let aad = record_aad(
            &self.vault_id,
            item_id,
            &parents,
            self.epoch,
            &self.author,
            tombstone,
        );
        let ciphertext = encrypt(self.key, &nonce, &aad, plaintext)?;
        let signature =
            self.signing_key
                .sign(&revision_signature_message(&aad, &nonce, &ciphertext));
        Ok(EncryptedRevision {
            format_version: RECORD_FORMAT_VERSION,
            vault_id: self.vault_id,
            item_id: item_id.to_owned(),
            parents,
            key_epoch: self.epoch,
            author_device_id: self.author,
            nonce,
            ciphertext,
            tombstone,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("vault_id", &"[REDACTED]")
            .field("unlocked", &self.root_key.is_some())
            .finish()
    }
}

impl Vault {
    pub fn create(path: impl AsRef<Path>, password: &str) -> Result<(Self, RecoveryKey)> {
        Self::build_new(path.as_ref(), |partial| {
            Self::initialize_created(partial, password)
        })
    }

    /// Makes a new vault file at `path` with `build`, which writes it, and
    /// unlocks it, at the path it is given. The file is written beside
    /// `path` and moved there only once it is complete, so a crash part way
    /// leaves nothing at `path` that would be taken for a vault; what it
    /// leaves beside it is replaced by the next attempt. A file already at
    /// `path` is never replaced.
    fn build_new<T>(
        path: &Path,
        build: impl FnOnce(&Path) -> Result<(Self, T)>,
    ) -> Result<(Self, T)> {
        if path.symlink_metadata().is_ok() {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        let partial = partial_path(path);
        match std::fs::remove_file(&partial) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        drop(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)?,
        );
        let (built, extra) = match build(&partial) {
            Ok(built) => built,
            Err(error) => {
                let _ = std::fs::remove_file(&partial);
                return Err(error);
            }
        };
        // Closed before it is moved: SQLite names its journal after the path
        // a file was opened at.
        let root_key = built.root_key.clone().ok_or(Error::Locked)?;
        drop(built);
        if let Err(error) = move_into_place(&partial, path) {
            let _ = std::fs::remove_file(&partial);
            return Err(error.into());
        }
        let connection = open_connection(path)?;
        let header = read_header(&connection)?;
        let mut vault = Self::from_parts(path, connection, header);
        vault.activate(root_key, None)?;
        Ok((vault, extra))
    }

    fn initialize_created(path: &Path, password: &str) -> Result<(Self, RecoveryKey)> {
        let connection = open_connection(path)?;
        create_schema(&connection)?;
        let vault_id = random_array::<32>();
        // The root key stays on this device; the epoch key is what other
        // devices receive. They are separate so a device that is later
        // removed never learns a key that wraps future epochs.
        let root_key = Zeroizing::new(random_array::<KEY_LEN>());
        let epoch_key = Zeroizing::new(random_array::<KEY_LEN>());
        let recovery = RecoveryKey::generate();
        let kdf = KdfConfig::default();
        let password_salt = random_array::<SALT_LEN>();
        let password = wrap_with_password(password, &password_salt, kdf, &vault_id, &root_key)?;
        let (device, _) = generate_device(&root_key, &vault_id, VAULT_FORMAT_VERSION)?;
        let recipient = wrap_recipient_secret(
            &root_key,
            &vault_id,
            &device.device_id,
            &random_array::<KEY_LEN>(),
        )?;
        let header = Header {
            format_version: VAULT_FORMAT_VERSION,
            vault_id,
            kdf,
            password_salt,
            password_nonce: password.nonce,
            password_wrapped_key: password.wrapped_key,
            recovery: Some(wrap_with_recovery(&recovery, &vault_id, &root_key)?),
            recovery_check: Some(recovery_check(recovery.expose(), &vault_id)?),
            legacy_recovery: None,
            current_epoch: FIRST_EPOCH,
            device: Some(device),
            recipient: Some(recipient),
            write_fence: FIRST_EPOCH,
            rows_changed: false,
        };
        insert_header(&connection, &header)?;
        insert_device_authorization(&connection, &root_key, &header, &header.device_record()?)?;
        store_epoch_key(&connection, &root_key, &vault_id, FIRST_EPOCH, &epoch_key)?;
        seal_rows(&connection, &root_key, &vault_id)?;
        let header = read_header(&connection)?;
        let mut vault = Self::from_parts(path, connection, header);
        vault.activate(root_key, None)?;
        Ok((vault, recovery))
    }

    fn from_parts(path: &Path, connection: Connection, header: Header) -> Self {
        Self {
            path: path.to_path_buf(),
            connection,
            header,
            root_key: None,
            epoch_keys: BTreeMap::new(),
            signing_key: None,
            devices: BTreeMap::new(),
            revoked: BTreeSet::new(),
            recipient_secret: None,
            session: None,
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let connection = open_connection(path)?;
        let header = read_header(&connection)?;
        let mut vault = Self::from_parts(path, connection, header);
        // Adding the ingress queue needs no key, so a locked vault can
        // receive as soon as it is opened.
        if vault.header.format_version == QUARANTINE_FORMAT_VERSION {
            vault.migrate_add_ingress()?;
        }
        // Likewise the write fence, so a locked device can stop writes as
        // soon as it learns of a new epoch.
        if vault.header.format_version == ROOT_KEY_FORMAT_VERSION {
            vault.migrate_add_membership()?;
        }
        Ok(vault)
    }

    pub fn vault_id(&self) -> [u8; 32] {
        self.header.vault_id
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn is_unlocked(&self) -> bool {
        self.root_key.is_some()
    }
    /// The epoch new revisions are written under.
    pub fn current_epoch(&self) -> u64 {
        self.header.current_epoch
    }
    pub fn recovery_enabled(&self) -> bool {
        self.header.recovery.is_some()
    }
    /// Lets another device verify the vault's recovery key; see
    /// [`Vault::enable_recovery`]. Public: it reveals nothing about the key.
    pub fn recovery_check(&self) -> Option<[u8; 32]> {
        self.header.recovery_check
    }
    /// This device's revision-signing identity. `None` until a format 1
    /// vault has been unlocked and migrated.
    pub fn device_id(&self) -> Option<[u8; DEVICE_ID_LEN]> {
        self.header.device.as_ref().map(|device| device.device_id)
    }
    pub fn device_public_key(&self) -> Option<[u8; PUBLIC_KEY_LEN]> {
        self.header.device.as_ref().map(|device| device.public_key)
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if self.is_unlocked() {
            return Err(Error::AlreadyUnlocked);
        }
        let wrapping_key =
            derive_password_key(password, &self.header.password_salt, self.header.kdf)?;
        let unwrapped = decrypt(
            &wrapping_key,
            &self.header.password_nonce,
            &key_wrap_aad(&self.header.vault_id, b"password"),
            &self.header.password_wrapped_key,
        )
        .map_err(|_| Error::InvalidCredentials)?;
        self.activate(to_key(&unwrapped)?, Some(&wrapping_key))
    }

    pub fn unlock_with_recovery(&mut self, recovery: &RecoveryKey) -> Result<()> {
        if self.is_unlocked() {
            return Err(Error::AlreadyUnlocked);
        }
        let wrapper = self
            .header
            .recovery
            .as_ref()
            .ok_or(Error::RecoveryNotEnabled)?;
        let unwrapped = decrypt(
            recovery.expose(),
            &wrapper.nonce,
            &key_wrap_aad(&self.header.vault_id, b"recovery"),
            &wrapper.wrapped_key,
        )
        .map_err(|_| Error::InvalidCredentials)?;
        // An older vault can only be re-rooted with the password.
        self.activate(to_key(&unwrapped)?, None)
    }

    pub fn lock(&mut self) {
        self.root_key = None;
        self.epoch_keys.clear();
        self.signing_key = None;
        self.devices.clear();
        self.revoked.clear();
        self.recipient_secret = None;
        self.session = None;
    }

    /// Names this unlock: `None` while locked, and different after every
    /// unlock.
    pub fn unlock_session(&self) -> Option<UnlockSession> {
        self.session.filter(|_| self.is_unlocked())
    }

    /// Completes an unlock: migrates an older vault, then loads the device
    /// signing key, the authenticated author set, and the epoch keys. The
    /// vault stays locked if any step fails.
    ///
    /// `unlocked` is what the password or recovery wrapper held: the root key
    /// in format 6, the shared vault key in older formats. Re-rooting an
    /// older vault needs `password_key` to rewrap the new root.
    fn activate(&mut self, unlocked: SecretKey, password_key: Option<&SecretKey>) -> Result<()> {
        let mut root_key = unlocked;
        let master_key = root_key.clone();
        if self.header.format_version == LEGACY_FORMAT_VERSION {
            self.migrate_legacy(&master_key)?;
        }
        if self.header.format_version == SINGLE_HEAD_FORMAT_VERSION {
            self.migrate_single_head()?;
        }
        if self.header.format_version == MULTI_HEAD_FORMAT_VERSION {
            self.migrate_add_quarantine()?;
        }
        if self.header.format_version == QUARANTINE_FORMAT_VERSION {
            self.migrate_add_ingress()?;
        }
        if self.header.format_version == SHARED_KEY_FORMAT_VERSION {
            let password_key = password_key.ok_or(Error::UpgradeRequiresPassword)?;
            root_key = self.migrate_root_key(&master_key, password_key)?;
        }
        if self.header.format_version == ROOT_KEY_FORMAT_VERSION {
            self.migrate_add_membership()?;
        }
        if self.header.format_version == MEMBERSHIP_FORMAT_VERSION {
            self.migrate_seal(&root_key)?;
        }
        let device = self.header.device.as_ref().ok_or(Error::Crypto)?;
        let seed = decrypt(
            &root_key,
            &device.key_nonce,
            &signing_key_aad(
                self.header.format_version,
                &self.header.vault_id,
                &device.device_id,
                &device.public_key,
            ),
            &device.wrapped_signing_key,
        )
        .map_err(|_| Error::Crypto)?;
        let seed = Zeroizing::new(array::<32>(&seed)?);
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().to_bytes() != device.public_key {
            return Err(Error::Crypto);
        }
        let devices = load_devices(&self.connection, &root_key, &self.header.vault_id)?;
        if devices.get(&device.device_id).map(VerifyingKey::to_bytes) != Some(device.public_key) {
            return Err(Error::Crypto);
        }
        let epoch_keys = load_epoch_keys(&self.connection, &root_key, &self.header.vault_id)?;
        if !epoch_keys.contains_key(&self.header.current_epoch) {
            return Err(Error::Crypto);
        }
        let revoked = load_revocations(&self.connection, &root_key, &self.header.vault_id)?;
        let recipient_secret = self.recipient_secret_or_create(&root_key)?;
        self.check_seal(&root_key)?;
        self.root_key = Some(root_key);
        self.epoch_keys = epoch_keys;
        self.signing_key = Some(signing_key);
        self.devices = devices;
        self.revoked = revoked;
        self.recipient_secret = Some(recipient_secret);
        self.session = Some(UnlockSession::new(random_array()));
        Ok(())
    }

    /// Seals a format 7 vault in one transaction: adds the format 8 columns,
    /// rewraps this device's signing key under the format 8 label, and seals
    /// the rows. Another connection may have done it since this one read
    /// the header.
    fn migrate_seal(&mut self, root_key: &SecretKey) -> Result<()> {
        let vault_id = self.header.vault_id;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = transaction.query_row(
            "SELECT format_version FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version == MEMBERSHIP_FORMAT_VERSION {
            let device = self.header.device.clone().ok_or(Error::Crypto)?;
            let seed = decrypt(
                root_key,
                &device.key_nonce,
                &device_key_aad(&vault_id, &device.device_id, &device.public_key),
                &device.wrapped_signing_key,
            )
            .map_err(|_| Error::Crypto)?;
            let key_nonce = random_array::<NONCE_LEN>();
            let wrapped_signing_key = encrypt(
                root_key,
                &key_nonce,
                &sealed_device_key_aad(&vault_id, &device.device_id, &device.public_key),
                &seed,
            )?;
            // A file written by this build's schema has them already.
            let has_columns: i64 = transaction.query_row(
                "SELECT count(*) FROM pragma_table_info('vault_meta') WHERE name='row_seal'",
                [],
                |row| row.get(0),
            )?;
            if has_columns == 0 {
                transaction.execute_batch(FORMAT_8_COLUMNS)?;
            }
            transaction.execute(
                "UPDATE vault_meta SET format_version=?, device_key_nonce=?, \
                 device_wrapped_signing_key=? WHERE singleton=1",
                params![
                    VAULT_FORMAT_VERSION,
                    key_nonce.as_slice(),
                    wrapped_signing_key
                ],
            )?;
            seal_rows(&transaction, root_key, &vault_id)?;
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    /// Checks, as the vault unlocks, that no row was taken out of its file
    /// or changed in it: the seal over the rows never changed or removed;
    /// each revision's columns against its ID, which covers them; and the
    /// heads against the revisions they follow from (an item's revisions
    /// that none of its others name as a parent). Anything found is recorded
    /// for the owner to be told; the heads are set again from the
    /// revisions, and the rows left sealed again, so later writes keep the
    /// seal. A revision that is missing comes back from the vault's other
    /// devices at the next sync, as anything this device lacks does.
    fn check_seal(&mut self, root_key: &SecretKey) -> Result<()> {
        let vault_id = self.header.vault_id;
        self.connection.execute_batch(SEAL_TRACKING)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<Vec<u8>> = transaction.query_row(
            "SELECT row_seal FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let marks = row_marks(&*row_seal_key(root_key)?, &row_sets(&transaction)?)?;
        let sealed = stored
            .and_then(|stored| open_row_seal(root_key, &vault_id, &stored))
            .is_some_and(|stored| keys_equal(&stored, &marks));

        let mut revisions_intact = true;
        let mut named = BTreeSet::new();
        let mut follows = BTreeMap::new();
        {
            let mut statement = transaction.prepare(&format!(
                "SELECT r.revision,{REVISION_COLUMNS} FROM revisions r"
            ))?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let revision = row_to_revision_at(row, 1)?;
                revisions_intact &= revision.revision_id() == id;
                named.extend(revision.parents);
                follows.insert(id, (revision.item_id, revision.tombstone));
            }
        }
        for parent in &named {
            follows.remove(parent);
        }
        let mut heads = BTreeMap::new();
        {
            let mut statement =
                transaction.prepare("SELECT revision, item_id, tombstone FROM heads")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                heads.insert(row.get::<_, String>(0)?, (row.get(1)?, row.get(2)?));
            }
        }
        let heads_intact = heads == follows;
        if !heads_intact {
            transaction.execute("DELETE FROM heads", [])?;
            for (revision, (item_id, tombstone)) in &follows {
                transaction.execute(
                    "INSERT INTO heads(revision,item_id,tombstone) VALUES(?,?,?)",
                    params![revision, item_id, tombstone],
                )?;
            }
        }
        if !(sealed && revisions_intact && heads_intact) {
            transaction.execute("UPDATE vault_meta SET rows_changed=1 WHERE singleton=1", [])?;
        }
        if sealed {
            forget_added_rows(&transaction)?;
        } else {
            store_row_seal(&transaction, root_key, &vault_id, &marks)?;
            forget_added_rows(&transaction)?;
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    /// Whether an unlock found rows taken out of the vault's file or changed
    /// in it, and the owner has not yet confirmed seeing it. Such rows are
    /// revisions and heads (an item, or an edit, hidden), authorized or
    /// removed devices, and epoch keys. Heads are set right at that unlock;
    /// what is missing comes back from the vault's other devices at the
    /// next sync.
    pub fn rows_changed(&self) -> bool {
        self.header.rows_changed
    }

    /// The owner has seen that rows were taken out: stop saying so.
    pub fn confirm_rows_changed(&mut self) -> Result<()> {
        self.key()?;
        self.connection
            .execute("UPDATE vault_meta SET rows_changed=0 WHERE singleton=1", [])?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    /// Unwraps this device's recipient secret, creating it for a vault from
    /// before format 7.
    fn recipient_secret_or_create(&mut self, root_key: &SecretKey) -> Result<SecretKey> {
        let vault_id = self.header.vault_id;
        let device_id = self.header.device.as_ref().ok_or(Error::Crypto)?.device_id;
        if let Some(wrapper) = &self.header.recipient {
            let secret = decrypt(
                root_key,
                &wrapper.nonce,
                &recipient_key_aad(&vault_id, &device_id),
                &wrapper.wrapped_key,
            )
            .map_err(|_| Error::Crypto)?;
            return to_key(&secret);
        }
        let secret = Zeroizing::new(random_array::<KEY_LEN>());
        let wrapper = wrap_recipient_secret(root_key, &vault_id, &device_id, &secret)?;
        // Only one connection may create it; another may have done so since
        // this one read the header.
        let changed = self.connection.execute(
            "UPDATE vault_meta SET recipient_nonce=?, recipient_wrapped_secret=? \
             WHERE singleton=1 AND recipient_nonce IS NULL",
            params![wrapper.nonce.as_slice(), wrapper.wrapped_key],
        )?;
        self.header = read_header(&self.connection)?;
        if changed == 0 {
            return self.recipient_secret_or_create(root_key);
        }
        Ok(secret)
    }

    /// Rewrites a format 1 vault as the current format in one transaction. Every
    /// revision is decrypted, re-sealed, and signed by a new identity for
    /// this device; parent links are remapped so each item's history is kept.
    fn migrate_legacy(&mut self, master_key: &SecretKey) -> Result<()> {
        let vault_id = self.header.vault_id;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Another connection may have migrated since this one read the header.
        let version: u32 = transaction.query_row(
            "SELECT format_version FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version == LEGACY_FORMAT_VERSION {
            let legacy = legacy_revisions(&transaction, &vault_id)?;
            let heads = {
                let mut statement =
                    transaction.prepare("SELECT item_id,revision,tombstone FROM heads")?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, bool>(2)?,
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                rows
            };
            let (device, signing_key) =
                generate_device(master_key, &vault_id, SHARED_KEY_FORMAT_VERSION)?;
            let mut header = self.header.clone();
            header.format_version = SHARED_KEY_FORMAT_VERSION;
            header.device = Some(device);

            transaction
                .execute_batch("DROP TABLE heads; DROP TABLE revisions; DROP TABLE vault_meta;")?;
            create_schema(&transaction)?;
            insert_header(&transaction, &header)?;
            let record = header.device_record()?;
            insert_device_authorization(&transaction, master_key, &header, &record)?;

            let signer = RevisionSigner {
                key: master_key,
                epoch: FIRST_EPOCH,
                signing_key: &signing_key,
                vault_id,
                author: record.device_id,
            };
            let mut renamed = BTreeMap::<String, String>::new();
            for old in legacy {
                let aad = legacy_record_aad(
                    &vault_id,
                    &old.item_id,
                    old.parent_revision.as_deref(),
                    old.key_epoch,
                    old.tombstone,
                );
                if legacy_revision_id(&aad, &old.nonce, &old.ciphertext) != old.revision {
                    return Err(Error::Crypto);
                }
                let plaintext = decrypt(master_key, &old.nonce, &aad, &old.ciphertext)
                    .map_err(|_| Error::Crypto)?;
                let parents = old
                    .parent_revision
                    .map(|parent| renamed.get(&parent).cloned().ok_or(Error::Crypto))
                    .transpose()?
                    .into_iter()
                    .collect();
                let revision = signer.seal(&old.item_id, parents, old.tombstone, &plaintext)?;
                let id = revision.revision_id();
                insert_revision(&transaction, "revisions", &revision, &id)?;
                renamed.insert(old.revision, id);
            }
            for (item_id, old_revision, tombstone) in heads {
                let revision = renamed.get(&old_revision).ok_or(Error::Crypto)?;
                transaction.execute(
                    "INSERT INTO heads(revision,item_id,tombstone) VALUES(?,?,?)",
                    params![revision, item_id, tombstone],
                )?;
            }
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    /// Converts the single-head format 2 layout to the multi-head layout in
    /// one transaction. Signed revision bytes are copied unchanged: one
    /// parent encodes identically in the parent list, so IDs and signatures
    /// stay valid.
    fn migrate_single_head(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = transaction.query_row(
            "SELECT format_version FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version == SINGLE_HEAD_FORMAT_VERSION {
            transaction.execute_batch(
                "DROP TRIGGER revisions_no_update; DROP TRIGGER revisions_no_delete;
                 DROP INDEX revisions_item_id;
                 ALTER TABLE heads RENAME TO single_heads;
                 ALTER TABLE revisions RENAME TO single_revisions;",
            )?;
            transaction.execute_batch(RECORD_SCHEMA)?;
            transaction.execute_batch(
                "INSERT INTO revisions(revision,format_version,vault_id,item_id,parents,key_epoch,
                     author_device_id,nonce,ciphertext,tombstone,signature)
                 SELECT revision,format_version,vault_id,item_id,COALESCE(parent_revision,''),
                     key_epoch,author_device_id,nonce,ciphertext,tombstone,signature
                 FROM single_revisions ORDER BY rowid;
                 INSERT INTO heads(revision,item_id,tombstone)
                 SELECT revision,item_id,tombstone FROM single_heads;
                 DROP TABLE single_heads;
                 DROP TABLE single_revisions;",
            )?;
            transaction.execute(
                "UPDATE vault_meta SET format_version=? WHERE singleton=1",
                [MULTI_HEAD_FORMAT_VERSION],
            )?;
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    /// Adds the quarantine table to a format 3 vault. Purely additive.
    fn migrate_add_quarantine(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = transaction.query_row(
            "SELECT format_version FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version == MULTI_HEAD_FORMAT_VERSION {
            transaction.execute_batch(QUARANTINE_SCHEMA)?;
            transaction.execute(
                "UPDATE vault_meta SET format_version=? WHERE singleton=1",
                [QUARANTINE_FORMAT_VERSION],
            )?;
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    /// Adds the ingress queue to a format 4 vault. Purely additive and
    /// keyless.
    fn migrate_add_ingress(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = transaction.query_row(
            "SELECT format_version FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version == QUARANTINE_FORMAT_VERSION {
            transaction.execute_batch(INGRESS_SCHEMA)?;
            transaction.execute(
                "UPDATE vault_meta SET format_version=? WHERE singleton=1",
                [SHARED_KEY_FORMAT_VERSION],
            )?;
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    /// Adds the format 7 columns and the revocation table to a format 6
    /// vault. Purely additive and keyless.
    fn migrate_add_membership(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = transaction.query_row(
            "SELECT format_version FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version == ROOT_KEY_FORMAT_VERSION {
            transaction.execute_batch(FORMAT_7_COLUMNS)?;
            transaction.execute_batch(REVOCATIONS_SCHEMA)?;
            transaction.execute(
                "UPDATE vault_meta SET format_version=? WHERE singleton=1",
                [MEMBERSHIP_FORMAT_VERSION],
            )?;
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    fn signer(&self) -> Result<RevisionSigner<'_>> {
        self.key()?;
        let epoch = self.header.current_epoch;
        // Committed membership has moved on: writing under this epoch could
        // reach a removed device.
        if epoch < self.header.write_fence {
            return Err(Error::EpochPending);
        }
        Ok(RevisionSigner {
            key: self.epoch_keys.get(&epoch).ok_or(Error::MissingEpochKey)?,
            epoch,
            signing_key: self.signing_key.as_ref().ok_or(Error::Locked)?,
            vault_id: self.header.vault_id,
            author: self.header.device.as_ref().ok_or(Error::Locked)?.device_id,
        })
    }

    /// Verifies the author's signature, then decrypts. The author must be in
    /// the authenticated device set; a key carried by the revision is never
    /// trusted.
    fn open_revision(&self, revision: &EncryptedRevision) -> Result<Zeroizing<Vec<u8>>> {
        let author = self
            .devices
            .get(&revision.author_device_id)
            .ok_or(Error::UnknownAuthor)?;
        let signature =
            Signature::from_slice(&revision.signature).map_err(|_| Error::InvalidSignature)?;
        let aad = revision.aad();
        author
            .verify_strict(
                &revision_signature_message(&aad, &revision.nonce, &revision.ciphertext),
                &signature,
            )
            .map_err(|_| Error::InvalidSignature)?;
        self.decrypt_unverified(revision)
    }

    /// AEAD decryption only. This proves the revision was produced by a
    /// holder of the vault key, not which device authored it.
    fn decrypt_unverified(&self, revision: &EncryptedRevision) -> Result<Zeroizing<Vec<u8>>> {
        self.key()?;
        let key = self
            .epoch_keys
            .get(&revision.key_epoch)
            .ok_or(Error::MissingEpochKey)?;
        decrypt(key, &revision.nonce, &revision.aad(), &revision.ciphertext)
            .map_err(|_| Error::Crypto)
    }

    fn open_item(&self, revision: &EncryptedRevision) -> Result<Item> {
        let plaintext = self.open_revision(revision)?;
        serde_json::from_slice(&plaintext).map_err(|_| Error::Crypto)
    }

    /// A version's item, `None` for a deletion, and when it says it was
    /// saved.
    fn open_version(&self, revision: &EncryptedRevision) -> Result<(Option<Item>, Option<u64>)> {
        let plaintext = self.open_revision(revision)?;
        let item = if revision.tombstone {
            None
        } else {
            Some(serde_json::from_slice(&plaintext).map_err(|_| Error::Crypto)?)
        };
        Ok((item, saved_at(&plaintext)))
    }

    /// Adds another device's signing key to the authorized author set.
    ///
    /// This is the interim enrollment authority: call it only after the
    /// owner has confirmed pairing with that device. Committed membership
    /// replaces it in Phase 4.
    pub fn authorize_device(
        &mut self,
        device_id: [u8; DEVICE_ID_LEN],
        public_key: [u8; PUBLIC_KEY_LEN],
    ) -> Result<()> {
        let key = self.key()?.clone();
        let verifying = VerifyingKey::from_bytes(&public_key).map_err(|_| Error::Crypto)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_device_authorization(
            &transaction,
            &key,
            &self.header,
            &DeviceRecord {
                device_id,
                public_key,
            },
        )?;
        reseal(&transaction, &key, &self.header.vault_id)?;
        transaction.commit()?;
        self.devices.insert(device_id, verifying);
        Ok(())
    }

    pub fn change_password(&mut self, current_password: &str, new_password: &str) -> Result<()> {
        let root_key = self.key()?.clone();
        let current_key = derive_password_key(
            current_password,
            &self.header.password_salt,
            self.header.kdf,
        )?;
        decrypt(
            &current_key,
            &self.header.password_nonce,
            &key_wrap_aad(&self.header.vault_id, b"password"),
            &self.header.password_wrapped_key,
        )
        .map_err(|_| Error::InvalidCredentials)?;
        self.store_password(new_password, &root_key)
    }

    /// For a forgotten password: unlocks the vault with the recovery key and
    /// makes `new_password` the one that unlocks it from now on. The old
    /// password no longer does. Nothing changes if the recovery key is
    /// wrong.
    pub fn reset_password(&mut self, recovery: &RecoveryKey, new_password: &str) -> Result<()> {
        self.unlock_with_recovery(recovery)?;
        let root_key = self.key()?.clone();
        if let Err(error) = self.store_password(new_password, &root_key) {
            self.lock();
            return Err(error);
        }
        Ok(())
    }

    /// Wraps the root key with a new password, under a new salt.
    fn store_password(&mut self, new_password: &str, root_key: &[u8; KEY_LEN]) -> Result<()> {
        let salt = random_array::<SALT_LEN>();
        let nonce = random_array::<NONCE_LEN>();
        let wrapping_key = derive_password_key(new_password, &salt, self.header.kdf)?;
        let wrapped = encrypt(
            &wrapping_key,
            &nonce,
            &key_wrap_aad(&self.header.vault_id, b"password"),
            root_key.as_ref(),
        )?;
        self.connection.execute(
            "UPDATE vault_meta SET password_salt=?, password_nonce=?, password_wrapped_key=? WHERE singleton=1",
            params![salt.as_slice(), nonce.as_slice(), wrapped],
        )?;
        self.header.password_salt = salt;
        self.header.password_nonce = nonce;
        self.header.password_wrapped_key = wrapped;
        Ok(())
    }

    /// Returns the item's current content. While heads conflict, this is the
    /// live head with the greatest revision ID, a deterministic choice so
    /// every device shows the same version, and `conflict` is set. A deletion
    /// never silently wins: the item stays visible until it is resolved.
    pub fn get(&self, item_id: &str) -> Result<VaultItem> {
        self.key()?;
        let heads = item_heads(&self.connection, item_id)?;
        let shown = heads
            .iter()
            .rev()
            .find(|revision| !revision.tombstone)
            .ok_or(Error::NotFound)?;
        Ok(VaultItem {
            item: self.open_item(shown)?,
            revision: shown.revision_id(),
            conflict: heads.len() > 1,
        })
    }

    /// Every current head of an item, ordered by revision ID, for reviewing
    /// a conflict. Each head is verified and decrypted.
    pub fn versions(&self, item_id: &str) -> Result<Vec<ItemVersion>> {
        self.key()?;
        let heads = item_heads(&self.connection, item_id)?;
        if heads.is_empty() {
            return Err(Error::NotFound);
        }
        heads
            .iter()
            .map(|revision| {
                let item = if revision.tombstone {
                    self.open_revision(revision)?;
                    None
                } else {
                    Some(self.open_item(revision)?)
                };
                Ok(ItemVersion {
                    revision: revision.revision_id(),
                    author_device_id: revision.author_device_id,
                    item,
                })
            })
            .collect()
    }

    /// Every stored version of an item, newest first: each verified and
    /// decrypted, with the versions it followed and whether it is current.
    /// The order is the order this device stored them in, in which a
    /// version always comes after those it followed.
    pub fn history(&self, item_id: &str) -> Result<Vec<HistoryVersion>> {
        self.key()?;
        let heads = head_ids(&self.connection, item_id)?;
        if heads.is_empty() {
            return Err(Error::NotFound);
        }
        let mut statement = self.connection.prepare(&format!(
            "SELECT {REVISION_COLUMNS} FROM revisions r WHERE r.item_id=? ORDER BY r.rowid DESC"
        ))?;
        let revisions = statement
            .query_map([item_id], row_to_revision)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut history = revisions
            .iter()
            .map(|revision| {
                let (item, saved_at) = self.open_version(revision)?;
                let id = revision.revision_id();
                Ok(HistoryVersion {
                    current: heads.contains(&id),
                    revision: id,
                    parents: revision.parents.clone(),
                    author_device_id: revision.author_device_id,
                    item,
                    changed: Vec::new(),
                    saved_at,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // A version with the time of one it followed, which another device
        // saved, was saved by a build that writes no time and kept the one
        // it found as a field it did not know: it has no time of its own.
        // (One device saving twice in a second gives both the same time.)
        let carried: Vec<bool> = history
            .iter()
            .map(|version| {
                version.saved_at.is_some()
                    && version.parents.iter().any(|parent| {
                        history.iter().any(|other| {
                            &other.revision == parent
                                && other.saved_at == version.saved_at
                                && other.author_device_id != version.author_device_id
                        })
                    })
            })
            .collect();
        for (version, carried) in history.iter_mut().zip(carried) {
            if carried {
                version.saved_at = None;
            }
        }
        // What each changed from the first version it followed that held
        // the item.
        let changed: Vec<Vec<&'static str>> = history
            .iter()
            .map(|version| {
                let before = version.parents.iter().find_map(|parent| {
                    history
                        .iter()
                        .find(|other| &other.revision == parent)
                        .and_then(|other| other.item.as_ref())
                });
                match (before, version.item.as_ref()) {
                    (Some(before), Some(item)) => item.changed_from(before),
                    _ => Vec::new(),
                }
            })
            .collect();
        for (version, changed) in history.iter_mut().zip(changed) {
            version.changed = changed;
        }
        Ok(history)
    }

    /// The items that every one of their current versions deletes, most
    /// recently deleted first, each with the version before its deletion.
    pub fn deleted_items(&self) -> Result<Vec<DeletedItem>> {
        self.key()?;
        let mut statement = self.connection.prepare(
            "SELECT h.item_id FROM heads h JOIN revisions r ON r.revision=h.revision \
             WHERE h.item_id NOT IN (?1, ?2) GROUP BY h.item_id HAVING MIN(h.tombstone)=1 \
             ORDER BY MAX(r.rowid) DESC",
        )?;
        let ids = statement
            .query_map(RESERVED_IDS, |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut deleted = Vec::with_capacity(ids.len());
        for item_id in ids {
            let heads = item_heads(&self.connection, &item_id)?;
            // The deletion stored last, then back through the versions the
            // deletions followed to the nearest that held the item.
            let newest = self.connection.query_row(
                &format!(
                    "SELECT {REVISION_COLUMNS} FROM heads h JOIN revisions r ON r.revision=h.revision \
                     WHERE h.item_id=? ORDER BY r.rowid DESC LIMIT 1"
                ),
                [&item_id],
                row_to_revision,
            )?;
            let mut waiting: Vec<String> = heads
                .iter()
                .flat_map(|head| head.parents.iter().cloned())
                .collect();
            let mut seen = BTreeSet::new();
            let mut last = None;
            while let Some(id) = waiting.pop() {
                if !seen.insert(id.clone()) {
                    continue;
                }
                let Some(revision) = revision_by_id(&self.connection, &id)? else {
                    continue;
                };
                if revision.tombstone {
                    waiting.extend(revision.parents.iter().cloned());
                    continue;
                }
                last = Some(revision);
                break;
            }
            // A deletion with nothing before it here cannot be brought back.
            let Some(last) = last else { continue };
            deleted.push(DeletedItem {
                last: ItemVersion {
                    revision: last.revision_id(),
                    author_device_id: last.author_device_id,
                    item: Some(self.open_item(&last)?),
                },
                heads: heads.iter().map(EncryptedRevision::revision_id).collect(),
                deleted_by: newest.author_device_id,
                deleted_at: self.open_version(&newest)?.1,
                item_id,
            });
        }
        Ok(deleted)
    }

    /// Brings back what the version `revision` of an item held as its
    /// newest version, following the current versions named in `heads`: an
    /// earlier version of an item, or an item as it was before it was
    /// deleted. A current version not named stays, as in a resolution.
    pub fn restore(
        &mut self,
        item_id: &str,
        revision: &str,
        heads: &[String],
    ) -> Result<RevisionInfo> {
        self.key()?;
        let stored = revision_by_id(&self.connection, revision)?.ok_or(Error::NotFound)?;
        if stored.item_id != item_id {
            return Err(Error::InvalidItem("that version is of another item".into()));
        }
        if stored.tombstone {
            return Err(Error::InvalidItem(
                "that version deletes the item: choose one before it".into(),
            ));
        }
        let item = self.open_item(&stored)?;
        self.resolve(item_id, Some(item), heads)
    }

    pub fn list(&self) -> Result<Vec<ItemSummary>> {
        self.key()?;
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT item_id FROM heads WHERE tombstone=0 AND item_id NOT IN (?1, ?2) \
             ORDER BY item_id",
        )?;
        let ids = statement
            .query_map(RESERVED_IDS, |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        ids.iter().map(|id| self.get(id).map(Into::into)).collect()
    }

    /// Notes in the vault that this device saved a backup now, for its other
    /// devices to learn when they sync (see [`BACKUPS_ID`]).
    pub fn note_backup(&mut self) -> Result<RevisionInfo> {
        let plaintext = version_plaintext(None, Some(now()))?;
        self.note(BACKUPS_ID, &plaintext)
    }

    /// When a device of this vault last saved a backup, by that device's
    /// clock, and which device: the latest the vault has noted.
    pub fn last_backup(&self) -> Result<Option<(u64, [u8; DEVICE_ID_LEN])>> {
        let mut latest = None;
        for (plaintext, author) in self.notes(BACKUPS_ID)? {
            if let Some(at) = saved_at(&plaintext) {
                // Of two noted in one second, the one stored last.
                if latest.is_none_or(|(last, _)| at >= last) {
                    latest = Some((at, author));
                }
            }
        }
        Ok(latest)
    }

    /// Keeps `code` in the vault as the code of the relay its devices use,
    /// or, with `None`, keeps that they use none (see [`RELAY_ID`]). The
    /// vault does not read the code: the devices do.
    pub fn set_relay(&mut self, code: Option<&str>) -> Result<RevisionInfo> {
        if code.is_some_and(|code| code.is_empty() || code.len() > MAX_RELAY_CODE) {
            return Err(Error::InvalidItem("that is not a relay code".into()));
        }
        let plaintext = Zeroizing::new(serde_json::to_vec(&RelaySetting {
            saved_at: now(),
            relay: code.map(str::to_owned),
        })?);
        self.note(RELAY_ID, &plaintext)
    }

    /// The code of the relay the vault's devices use, as last set on any of
    /// them by its clock; `None` if none was set, or it was taken away.
    pub fn relay(&self) -> Result<Option<Zeroizing<String>>> {
        let mut latest: Option<RelaySetting> = None;
        for (plaintext, _) in self.notes(RELAY_ID)? {
            let Ok(setting) = serde_json::from_slice::<RelaySetting>(&plaintext) else {
                continue;
            };
            // Of two set in one second, the one stored last.
            if latest
                .as_ref()
                .is_none_or(|last| setting.saved_at >= last.saved_at)
            {
                latest = Some(setting);
            }
        }
        Ok(latest.and_then(|setting| setting.relay).map(Zeroizing::new))
    }

    /// Writes a note of the vault's own under the reserved `id`: a deletion
    /// holding `plaintext`, following the notes there now.
    fn note(&mut self, id: &str, plaintext: &[u8]) -> Result<RevisionInfo> {
        self.key()?;
        let mut heads = head_ids(&self.connection, id)?;
        heads.truncate(MAX_PARENTS);
        let kind = if heads.is_empty() {
            LocalWrite::Create
        } else {
            LocalWrite::Resolve
        };
        let revision = self.signer()?.seal(id, heads, true, plaintext)?;
        self.commit_revision(revision, Some(kind), None)
    }

    /// Every note under the reserved `id`, verified and opened, in the order
    /// this device stored them, each with its author.
    fn notes(&self, id: &str) -> Result<Vec<Note>> {
        self.key()?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {REVISION_COLUMNS} FROM revisions r WHERE r.item_id=? AND r.tombstone=1 \
             ORDER BY r.rowid"
        ))?;
        let noted = statement
            .query_map([id], row_to_revision)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        noted
            .iter()
            .map(|revision| Ok((self.open_revision(revision)?, revision.author_device_id)))
            .collect()
    }

    pub fn search(&self, query: &str) -> Result<Vec<ItemSummary>> {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return self.list();
        }
        Ok(self
            .list()?
            .into_iter()
            .filter(|item| {
                item.title.to_lowercase().contains(&query)
                    || item.username.to_lowercase().contains(&query)
                    || item.url.to_lowercase().contains(&query)
            })
            .collect())
    }

    /// The logins that may be filled into a page of `origin`: those whose
    /// stored address has exactly that origin.
    pub fn logins_for_origin(&self, origin: &Origin) -> Result<Vec<ItemSummary>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|item| fills(item.kind, &item.url, origin))
            .collect())
    }

    /// The user name and password of a login, for filling into a page of
    /// `origin`. Refused unless the login's stored address has exactly that
    /// origin, whatever the caller was shown or chose.
    pub fn credentials_for_origin(
        &self,
        item_id: &str,
        origin: &Origin,
    ) -> Result<FillCredentials> {
        let item = self.get(item_id)?.item;
        if !fills(item.kind, &item.url, origin) {
            return Err(Error::OriginMismatch);
        }
        Ok(FillCredentials {
            username: item.username.clone(),
            password: item.password.clone(),
        })
    }

    pub fn put(&mut self, item: Item) -> Result<RevisionInfo> {
        item.validate()?;
        if !head_ids(&self.connection, &item.id)?.is_empty() {
            return Err(Error::AlreadyExists);
        }
        self.write_item(item, Vec::new(), false, LocalWrite::Create)
    }

    /// Commits an import as one SQLite transaction after validating every item.
    pub(crate) fn put_items_atomic(&mut self, items: Vec<Item>) -> Result<Vec<RevisionInfo>> {
        self.key()?;
        let saved = now();
        let mut ids = BTreeSet::new();
        for item in &items {
            item.validate()?;
            if version_plaintext(Some(item), Some(saved))?.len() > MAX_ITEM_BYTES {
                return Err(Error::InvalidItem("serialized item is too large".into()));
            }
            if !ids.insert(item.id.clone()) || !head_ids(&self.connection, &item.id)?.is_empty() {
                return Err(Error::AlreadyExists);
            }
        }

        let sealed = {
            let signer = self.signer()?;
            items
                .iter()
                .map(|item| {
                    let plaintext = version_plaintext(Some(item), Some(saved))?;
                    signer.seal(&item.id, Vec::new(), false, &plaintext)
                })
                .collect::<Result<Vec<_>>>()?
        };
        let (seal_key, seal_vault) = (self.key()?.clone(), self.header.vault_id);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut revisions = Vec::with_capacity(sealed.len());
        for revision in sealed {
            let revision_id = revision.revision_id();
            insert_revision(&transaction, "revisions", &revision, &revision_id)?;
            transaction.execute(
                "INSERT INTO heads(revision,item_id,tombstone) VALUES(?,?,0)",
                params![revision_id, revision.item_id],
            )?;
            revisions.push(RevisionInfo {
                item_id: revision.item_id,
                revision: revision_id,
                parents: Vec::new(),
            });
        }
        reseal(&transaction, &seal_key, &seal_vault)?;
        transaction.commit()?;
        Ok(revisions)
    }

    /// Starts a new trust domain from what this vault shows now, for when
    /// too many of its devices are lost for the rest to remove them.
    ///
    /// The new vault at `path` shares nothing with this one: it has a new
    /// vault ID, device identity, root key, first epoch key, and recovery
    /// key, and its only author is the new identity. Every live version of
    /// every item is written again as that author, without parents: an item
    /// with several versions stays a conflict for the owner to resolve.
    /// Earlier history, deletions, held revisions, and unverified received
    /// revisions are not carried, and an unresolved choice between an edit
    /// and a deletion keeps the edit. This vault is left as it is. No device
    /// of the old domain can read or write the new vault; each joins it
    /// again by pairing.
    pub fn fork(
        &self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<(Self, RecoveryKey, ForkReport)> {
        self.key()?;
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT item_id FROM heads WHERE tombstone=0 ORDER BY item_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut report = ForkReport::default();
        let mut versions = Vec::new();
        for id in &ids {
            let live: Vec<EncryptedRevision> = item_heads(&self.connection, id)?
                .into_iter()
                .filter(|revision| !revision.tombstone)
                .collect();
            report.items += 1;
            if live.len() > 1 {
                report.conflicts += 1;
            }
            for revision in &live {
                let (item, saved_at) = self.open_version(revision)?;
                versions.extend(item.map(|item| (item, saved_at)));
            }
        }
        let count = |table: &str| -> Result<usize> {
            let rows: i64 =
                self.connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
            Ok(rows as usize)
        };
        report.held_left_behind = count("quarantine")?;
        report.staged_left_behind = count("ingress")?;

        let (fork, recovery) = Self::build_new(path.as_ref(), |partial| {
            let (mut fork, recovery) = Self::initialize_created(partial, password)?;
            fork.seed(versions)?;
            Ok((fork, recovery))
        })?;
        Ok((fork, recovery, report))
    }

    /// Writes each item version as a revision of its own, without parents,
    /// in one transaction. Several versions of one item become concurrent
    /// heads.
    /// Each keeps the time it was saved, if it has one.
    fn seed(&mut self, versions: Vec<(Item, Option<u64>)>) -> Result<()> {
        let sealed = {
            let signer = self.signer()?;
            versions
                .iter()
                .map(|(item, saved_at)| {
                    item.validate()?;
                    let plaintext = version_plaintext(Some(item), *saved_at)?;
                    signer.seal(&item.id, Vec::new(), false, &plaintext)
                })
                .collect::<Result<Vec<_>>>()?
        };
        let (seal_key, seal_vault) = (self.key()?.clone(), self.header.vault_id);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for revision in sealed {
            let revision_id = revision.revision_id();
            insert_revision(&transaction, "revisions", &revision, &revision_id)?;
            transaction.execute(
                "INSERT INTO heads(revision,item_id,tombstone) VALUES(?,?,0)",
                params![revision_id, revision.item_id],
            )?;
        }
        reseal(&transaction, &seal_key, &seal_vault)?;
        transaction.commit()?;
        Ok(())
    }

    /// Edits an item with one head. Fails with `Unresolved` while the item
    /// has concurrent heads, and with `Conflict` if `expected_revision` is no
    /// longer the head.
    pub fn update(&mut self, item: Item, expected_revision: &str) -> Result<RevisionInfo> {
        item.validate()?;
        self.write_item(
            item,
            vec![expected_revision.to_owned()],
            false,
            LocalWrite::Edit,
        )
    }

    pub fn delete(&mut self, item_id: &str, expected_revision: &str) -> Result<RevisionInfo> {
        if item_id.is_empty() {
            return Err(Error::InvalidItem("id must not be empty".into()));
        }
        let mut item = Item::new("deleted");
        item.id = item_id.to_owned();
        self.write_item(
            item,
            vec![expected_revision.to_owned()],
            true,
            LocalWrite::Edit,
        )
    }

    /// Supersedes the named heads of an item with one revision: `Some` keeps
    /// that content and `None` deletes the item. Every named head must still
    /// be current. A head that arrived after the owner reviewed the conflict
    /// is not named, so it stays visible and the item stays in conflict.
    pub fn resolve(
        &mut self,
        item_id: &str,
        resolution: Option<Item>,
        heads: &[String],
    ) -> Result<RevisionInfo> {
        let mut parents = heads.to_vec();
        parents.sort();
        parents.dedup();
        if parents.is_empty() || parents.len() > MAX_PARENTS {
            return Err(Error::InvalidItem(format!(
                "a resolution must name between 1 and {MAX_PARENTS} heads"
            )));
        }
        let (item, tombstone) = match resolution {
            Some(item) => {
                item.validate()?;
                if item.id != item_id {
                    return Err(Error::InvalidItem("resolution is for another item".into()));
                }
                (item, false)
            }
            None => {
                let mut item = Item::new("deleted");
                item.id = item_id.to_owned();
                (item, true)
            }
        };
        self.write_item(item, parents, tombstone, LocalWrite::Resolve)
    }

    fn write_item(
        &mut self,
        item: Item,
        parents: Vec<String>,
        tombstone: bool,
        kind: LocalWrite,
    ) -> Result<RevisionInfo> {
        self.key()?;
        let plaintext = version_plaintext((!tombstone).then_some(&item), Some(now()))?;
        if plaintext.len() > MAX_ITEM_BYTES {
            return Err(Error::InvalidItem("serialized item is too large".into()));
        }
        let revision = self
            .signer()?
            .seal(&item.id, parents, tombstone, &plaintext)?;
        self.commit_revision(revision, Some(kind), None)
    }

    pub fn encrypted_revisions(&self) -> Result<Vec<EncryptedRevision>> {
        self.key()?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {REVISION_COLUMNS} FROM revisions r ORDER BY r.rowid"
        ))?;
        let revisions = statement
            .query_map([], row_to_revision)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into);
        revisions
    }

    /// Writes an encrypted backup that the recovery key opens. Requires
    /// recovery to be enabled on this device.
    pub fn export_backup(&self, path: impl AsRef<Path>) -> Result<()> {
        let key = self.key()?;
        let recovery = self
            .header
            .recovery
            .as_ref()
            .ok_or(Error::RecoveryNotEnabled)?;
        let payload = BackupPayload {
            current_epoch: self.header.current_epoch,
            epoch_keys: self
                .epoch_keys
                .iter()
                .map(|(epoch, key)| EpochKeyRecord {
                    epoch: *epoch,
                    key: **key,
                })
                .collect(),
            devices: self
                .devices
                .iter()
                .map(|(device_id, public_key)| DeviceRecord {
                    device_id: *device_id,
                    public_key: public_key.to_bytes(),
                })
                .collect(),
            revisions: self.encrypted_revisions()?,
            quarantine: quarantined_revisions(&self.connection)?,
            revoked: self.revoked.iter().copied().collect(),
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
        if plaintext.len() as u64 > MAX_BACKUP_BYTES {
            return Err(Error::InvalidBackup("backup is too large".into()));
        }
        let nonce = random_array::<NONCE_LEN>();
        let recovery_nonce = encode(&recovery.nonce);
        let recovery_wrapped_key = encode(&recovery.wrapped_key);
        let aad = backup_aad(
            &self.header.vault_id,
            &recovery_nonce,
            &recovery_wrapped_key,
        );
        let ciphertext = encrypt(key, &nonce, &aad, &plaintext)?;
        let envelope = BackupEnvelope {
            magic: "OSM-BACKUP".into(),
            format_version: BACKUP_FORMAT_VERSION,
            vault_id: encode(&self.header.vault_id),
            recovery_nonce,
            recovery_wrapped_key,
            nonce: encode(&nonce),
            ciphertext: encode(&ciphertext),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&envelope)?);
        if encoded.len() as u64 > MAX_BACKUP_BYTES {
            return Err(Error::InvalidBackup("backup is too large".into()));
        }
        // Written beside its place and moved there once complete, so a crash
        // never leaves a part of a backup that looks like one.
        let path = path.as_ref();
        if path.symlink_metadata().is_ok() {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        let partial = partial_path(path);
        match std::fs::remove_file(&partial) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .and_then(|mut file| file.write_all(&encoded).and_then(|_| file.sync_all()))
            .and_then(|()| move_into_place(&partial, path));
        if let Err(error) = written {
            let _ = std::fs::remove_file(&partial);
            return Err(error.into());
        }
        Ok(())
    }

    /// Reads back a backup this device wrote, with its own key: it must be
    /// whole, of this vault, and opened by this vault's recovery key. Says
    /// what it holds.
    pub fn check_backup(&self, path: impl AsRef<Path>) -> Result<BackupCheck> {
        let key = self.key()?;
        let recovery = self
            .header
            .recovery
            .as_ref()
            .ok_or(Error::RecoveryNotEnabled)?;
        let envelope = read_backup(path.as_ref())?;
        if envelope.magic != "OSM-BACKUP" {
            return Err(Error::InvalidBackup("invalid magic".into()));
        }
        if envelope.format_version != BACKUP_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(envelope.format_version));
        }
        if decode_array::<32>(&envelope.vault_id)? != self.header.vault_id {
            return Err(Error::InvalidBackup("a backup of another vault".into()));
        }
        if envelope.recovery_nonce != encode(&recovery.nonce)
            || envelope.recovery_wrapped_key != encode(&recovery.wrapped_key)
        {
            return Err(Error::InvalidBackup(
                "not opened by this vault's recovery key".into(),
            ));
        }
        let nonce = decode_array::<NONCE_LEN>(&envelope.nonce)?;
        let ciphertext = decode(&envelope.ciphertext)?;
        let aad = backup_aad(
            &self.header.vault_id,
            &envelope.recovery_nonce,
            &envelope.recovery_wrapped_key,
        );
        let plaintext = Zeroizing::new(
            decrypt(key, &nonce, &aad, &ciphertext)
                .map_err(|_| Error::InvalidBackup("authentication failed".into()))?,
        );
        let payload: BackupPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| Error::InvalidBackup("invalid payload".into()))?;
        // The backups the vault noted are not items.
        let revisions: Vec<&EncryptedRevision> = payload
            .revisions
            .iter()
            .filter(|revision| !RESERVED_IDS.contains(&revision.item_id.as_str()))
            .collect();
        let items: BTreeSet<&str> = revisions
            .iter()
            .map(|revision| revision.item_id.as_str())
            .collect();
        Ok(BackupCheck {
            items: items.len(),
            revisions: revisions.len(),
            held: payload.quarantine.len(),
        })
    }

    pub fn restore_backup(
        backup_path: impl AsRef<Path>,
        vault_path: impl AsRef<Path>,
        recovery: &RecoveryKey,
        new_password: &str,
    ) -> Result<Self> {
        let envelope = read_backup(backup_path.as_ref())?;
        if envelope.magic != "OSM-BACKUP" {
            return Err(Error::InvalidBackup("invalid magic".into()));
        }
        if envelope.format_version != BACKUP_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(envelope.format_version));
        }
        let vault_id = decode_array::<32>(&envelope.vault_id)?;
        let recovery_nonce = decode_array::<NONCE_LEN>(&envelope.recovery_nonce)?;
        let recovery_wrapped_key = decode(&envelope.recovery_wrapped_key)?;
        if recovery_wrapped_key.len() != KEY_LEN + 16 {
            return Err(Error::InvalidBackup(
                "invalid recovery wrapping length".into(),
            ));
        }
        let source_root = decrypt(
            recovery.expose(),
            &recovery_nonce,
            &key_wrap_aad(&vault_id, b"recovery"),
            &recovery_wrapped_key,
        )
        .map_err(|_| Error::InvalidCredentials)?;
        let source_root = to_key(&source_root)?;
        let nonce = decode_array::<NONCE_LEN>(&envelope.nonce)?;
        let ciphertext = decode(&envelope.ciphertext)?;
        let aad = backup_aad(
            &vault_id,
            &envelope.recovery_nonce,
            &envelope.recovery_wrapped_key,
        );
        let plaintext = decrypt(&source_root, &nonce, &aad, &ciphertext)
            .map_err(|_| Error::InvalidBackup("authentication failed".into()))?;
        let payload: BackupPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| Error::InvalidBackup("invalid payload".into()))?;
        if payload.revisions.len() > 1_000_000
            || payload.devices.len() > 10_000
            || payload.quarantine.len() as i64 > MAX_QUARANTINE
            || payload.epoch_keys.len() > MAX_EPOCHS
        {
            return Err(Error::InvalidBackup("too many revisions".into()));
        }
        if payload
            .revisions
            .iter()
            .any(|revision| revision.vault_id != vault_id)
        {
            return Err(Error::InvalidBackup("vault identity mismatch".into()));
        }

        Self::build_new(vault_path.as_ref(), |partial| {
            Self::initialize_restored(partial, new_password, vault_id, recovery, payload)
                .map(|vault| (vault, ()))
        })
        .map(|(vault, ())| vault)
    }

    fn initialize_restored(
        path: &Path,
        password: &str,
        vault_id: [u8; 32],
        recovery: &RecoveryKey,
        payload: BackupPayload,
    ) -> Result<Self> {
        let connection = open_connection(path)?;
        create_schema(&connection)?;
        // A restored vault is a new device: a fresh root key and signing
        // identity, never the source's. The source authors stay authorized
        // so their revisions in the backup still verify.
        let root_key = Zeroizing::new(random_array::<KEY_LEN>());
        let kdf = KdfConfig::default();
        let password_salt = random_array::<SALT_LEN>();
        let password = wrap_with_password(password, &password_salt, kdf, &vault_id, &root_key)?;
        let (device, _) = generate_device(&root_key, &vault_id, VAULT_FORMAT_VERSION)?;
        let recipient = wrap_recipient_secret(
            &root_key,
            &vault_id,
            &device.device_id,
            &random_array::<KEY_LEN>(),
        )?;
        let header = Header {
            format_version: VAULT_FORMAT_VERSION,
            vault_id,
            kdf,
            password_salt,
            password_nonce: password.nonce,
            password_wrapped_key: password.wrapped_key,
            recovery: Some(wrap_with_recovery(recovery, &vault_id, &root_key)?),
            recovery_check: Some(recovery_check(recovery.expose(), &vault_id)?),
            legacy_recovery: None,
            current_epoch: payload.current_epoch,
            device: Some(device),
            recipient: Some(recipient),
            write_fence: FIRST_EPOCH,
            rows_changed: false,
        };
        insert_header(&connection, &header)?;
        insert_device_authorization(&connection, &root_key, &header, &header.device_record()?)?;
        for record in &payload.devices {
            insert_device_authorization(&connection, &root_key, &header, record)?;
        }
        for record in &payload.epoch_keys {
            store_epoch_key(&connection, &root_key, &vault_id, record.epoch, &record.key)?;
        }
        seal_rows(&connection, &root_key, &vault_id)?;
        let header = read_header(&connection)?;
        let mut vault = Self::from_parts(path, connection, header);
        vault.activate(root_key, None)?;
        // Revisions are exported in insertion order, so parents precede
        // children and the head set is rebuilt exactly.
        for revision in payload.revisions {
            vault.apply_encrypted_revision(revision)?;
        }
        // Revoked after the accepted revisions, so those of a removed
        // device are restored as accepted, and before the held ones, so a
        // removed device's revision that was held stays held.
        for device_id in payload.revoked {
            vault.revoke_device(device_id)?;
        }
        for held in payload.quarantine {
            match vault.apply_encrypted_revision(held) {
                Ok(_) | Err(Error::Quarantined) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(vault)
    }

    /// Accepts a revision from another copy of the vault. It supersedes only
    /// the parents it names; a revision concurrent with the current heads
    /// becomes an additional head. Replaying a stored revision is a no-op.
    /// `MissingParent` means nothing was written and the caller should retry
    /// once the parent has been applied.
    ///
    /// A revision whose author is not an authorized device, or was removed
    /// by committed membership, is held in the quarantine and `Quarantined`
    /// is returned: it is not merged. Only a well-formed revision that
    /// decrypts with the vault key is held. A held revision by a known
    /// author is released as-is once an authorized revision names it as a
    /// parent: that device has vouched for it by building on it.
    pub fn apply_encrypted_revision(
        &mut self,
        revision: EncryptedRevision,
    ) -> Result<RevisionInfo> {
        self.key()?;
        revision.validate_shape(&self.header.vault_id)?;
        if !self.is_active_author(&revision.author_device_id) {
            // A removed device's revision already in the history was
            // accepted, by the owner or along with a revision that builds
            // on it. Receiving it again is a replay, not a new hold.
            let accepted = self.devices.contains_key(&revision.author_device_id)
                && revision_by_id(&self.connection, &revision.revision_id())?.is_some();
            if !accepted {
                self.quarantine(revision)?;
                return Err(Error::Quarantined);
            }
        }
        self.commit_revision(revision, None, None)
    }

    fn is_active_author(&self, device_id: &[u8; DEVICE_ID_LEN]) -> bool {
        self.devices.contains_key(device_id) && !self.revoked.contains(device_id)
    }

    /// Applies held revisions whose authors are now authorized and not
    /// revoked, as-is. Call after authorizing devices. A held revision still
    /// missing a parent, or that fails verification, stays held. Returns
    /// how many were applied.
    pub fn retry_quarantined(&mut self) -> Result<usize> {
        self.key()?;
        let mut applied = 0;
        loop {
            let mut progressed = false;
            for held in quarantined_revisions(&self.connection)? {
                if !self.is_active_author(&held.author_device_id) {
                    continue;
                }
                match self.commit_revision(held, None, None) {
                    Ok(_) => {
                        applied += 1;
                        progressed = true;
                    }
                    Err(error) if error_keeps_hold(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            if !progressed {
                return Ok(applied);
            }
        }
    }

    /// Writes, as this device, a revision with the same content as each
    /// head authored by `device_id` and that head as its only parent.
    ///
    /// After a device is removed, its revisions not yet accepted elsewhere
    /// are held for review; building on its current heads keeps its last
    /// accepted state visible on every device, because a held revision that
    /// an authorized revision names as a parent is released. Only the device
    /// that removed it should call this, so the heads are not endorsed twice.
    /// Endorsed heads stop being heads, so calling it again does nothing.
    pub fn endorse_heads_of(
        &mut self,
        device_id: [u8; DEVICE_ID_LEN],
    ) -> Result<Vec<RevisionInfo>> {
        self.key()?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT {REVISION_COLUMNS} FROM heads h JOIN revisions r ON r.revision=h.revision \
             WHERE r.author_device_id=? ORDER BY r.rowid"
        ))?;
        let heads = statement
            .query_map([device_id.as_slice()], row_to_revision)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut endorsed = Vec::new();
        for head in heads {
            let plaintext = self.open_revision(&head)?;
            let revision = self.signer()?.seal(
                &head.item_id,
                vec![head.revision_id()],
                head.tombstone,
                &plaintext,
            )?;
            endorsed.push(self.commit_revision(revision, None, None)?);
        }
        Ok(endorsed)
    }

    fn quarantine(&mut self, revision: EncryptedRevision) -> Result<()> {
        let plaintext = self.decrypt_unverified(&revision)?;
        if !revision.tombstone {
            let item: Item = serde_json::from_slice(&plaintext).map_err(|_| Error::Crypto)?;
            item.validate()?;
            if item.id != revision.item_id {
                return Err(Error::Crypto);
            }
        }
        let id = revision.revision_id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if quarantined_by_id(&transaction, &id)?.is_none() {
            let held: i64 =
                transaction.query_row("SELECT COUNT(*) FROM quarantine", [], |row| row.get(0))?;
            if held >= MAX_QUARANTINE {
                return Err(Error::QuarantineFull);
            }
            insert_revision(&transaction, "quarantine", &revision, &id)?;
        }
        transaction.execute("DELETE FROM ingress WHERE revision=?", [&id])?;
        transaction.commit()?;
        Ok(())
    }

    /// Revisions held for owner review, oldest first, decrypted.
    pub fn quarantined(&self) -> Result<Vec<QuarantinedRevision>> {
        self.key()?;
        quarantined_revisions(&self.connection)?
            .iter()
            .map(|revision| {
                let plaintext = self.decrypt_unverified(revision)?;
                let item = if revision.tombstone {
                    None
                } else {
                    Some(serde_json::from_slice(&plaintext).map_err(|_| Error::Crypto)?)
                };
                Ok(QuarantinedRevision {
                    revision: revision.revision_id(),
                    item_id: revision.item_id.clone(),
                    author_device_id: revision.author_device_id,
                    known_author: self.held_is_verifiable(revision),
                    parents: revision.parents.clone(),
                    item,
                })
            })
            .collect()
    }

    /// Whether a held revision can join the history as it was signed: its
    /// author is a device this vault knows, in practice one that was
    /// removed, and its signature and content verify.
    fn held_is_verifiable(&self, held: &EncryptedRevision) -> bool {
        self.devices.contains_key(&held.author_device_id) && self.verify_revision(held).is_ok()
    }

    /// Accepts a held revision. The result may be a concurrent head to
    /// resolve; it never overrides an edit made since. The held entry is
    /// released in the same transaction; on `MissingParent` it stays held.
    ///
    /// From a device this vault knows, this device writes a revision with
    /// the same content that names the held one as its parent. That vouches
    /// for it: it joins the history as it was signed, here and on every
    /// device the new revision reaches, including one that had accepted it
    /// before learning that its author was removed.
    ///
    /// From a device this vault does not know, the signature cannot be
    /// checked and is never trusted: the content is written again as this
    /// device against the same parents, and the held revision is dropped.
    pub fn accept_quarantined(&mut self, revision_id: &str) -> Result<RevisionInfo> {
        self.key()?;
        let held = quarantined_by_id(&self.connection, revision_id)?.ok_or(Error::NotFound)?;
        if self.held_is_verifiable(&held) {
            let plaintext = self.open_revision(&held)?;
            let revision = self.signer()?.seal(
                &held.item_id,
                vec![revision_id.to_owned()],
                held.tombstone,
                &plaintext,
            )?;
            return self.commit_revision(revision, None, None);
        }
        let plaintext = self.decrypt_unverified(&held)?;
        let revision = self.signer()?.seal(
            &held.item_id,
            held.parents.clone(),
            held.tombstone,
            &plaintext,
        )?;
        self.commit_revision(revision, None, Some(revision_id))
    }

    /// Rejects a held revision.
    ///
    /// From a device this vault knows, this device writes a revision that
    /// keeps the item as it is here now (deleted, if it is not here) and
    /// names the held revision as a parent, beside the item's current head.
    /// The held revision joins the history already superseded, so every
    /// device the new revision reaches ends at this device's version,
    /// including one that had accepted the held revision. Returns that
    /// revision. `Unresolved` if the item has conflicting versions here:
    /// there is no one version to keep until they are resolved. On
    /// `MissingParent` nothing changes.
    ///
    /// From a device this vault does not know, the held revision is dropped
    /// on this device only and `None` is returned. If it is received again
    /// it is held again rather than silently ignored.
    pub fn discard_quarantined(&mut self, revision_id: &str) -> Result<Option<RevisionInfo>> {
        self.key()?;
        let held = quarantined_by_id(&self.connection, revision_id)?.ok_or(Error::NotFound)?;
        if !self.held_is_verifiable(&held) {
            self.connection
                .execute("DELETE FROM quarantine WHERE revision=?", [revision_id])?;
            return Ok(None);
        }
        let mut heads = item_heads(&self.connection, &held.item_id)?;
        if heads.len() > 1 {
            return Err(Error::Unresolved);
        }
        let current = heads.pop();
        let (tombstone, plaintext) = match &current {
            Some(head) => (head.tombstone, self.open_revision(head)?),
            None => (true, Zeroizing::new(Vec::new())),
        };
        // A head the held revision already names is superseded by it.
        let mut parents: Vec<String> = current
            .map(|head| head.revision_id())
            .into_iter()
            .filter(|head| !held.parents.contains(head))
            .chain([revision_id.to_owned()])
            .collect();
        parents.sort();
        let revision = self
            .signer()?
            .seal(&held.item_id, parents, tombstone, &plaintext)?;
        self.commit_revision(revision, None, None).map(Some)
    }

    /// Verifies, stores, and materializes a revision. `local` carries the
    /// head-set precondition for writes made on this device; it is checked
    /// in the same IMMEDIATE transaction that updates the heads, so two
    /// processes editing one head cannot both succeed.
    /// `release` names a quarantined revision to remove in the same
    /// transaction, so accepting one cannot apply it twice.
    fn commit_revision(
        &mut self,
        revision: EncryptedRevision,
        local: Option<LocalWrite>,
        release: Option<&str>,
    ) -> Result<RevisionInfo> {
        self.key()?;
        self.verify_revision(&revision)?;
        let vouched = self.vouched_ancestors(&revision)?;

        let id = revision.revision_id();
        let info = RevisionInfo {
            item_id: revision.item_id.clone(),
            revision: id.clone(),
            parents: revision.parents.clone(),
        };
        let (seal_key, seal_vault) = (self.key()?.clone(), self.header.vault_id);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(stored) = revision_by_id(&transaction, &id)? {
            if stored != revision {
                return Err(Error::Crypto);
            }
            transaction.execute("DELETE FROM ingress WHERE revision=?", [&id])?;
            transaction.commit()?;
            return Ok(info);
        }
        // Held revisions this one builds on are accepted with it, parents
        // first, in the same transaction.
        for held in &vouched {
            let held_id = held.revision_id();
            if revision_by_id(&transaction, &held_id)?.is_some() {
                continue;
            }
            if quarantined_by_id(&transaction, &held_id)?.is_none() {
                return Err(Error::MissingParent);
            }
            check_parents(&transaction, held)?;
            insert_revision(&transaction, "revisions", held, &held_id)?;
            transaction.execute("DELETE FROM quarantine WHERE revision=?", [&held_id])?;
            replace_heads(&transaction, held, &held_id)?;
        }
        check_parents(&transaction, &revision)?;
        if let Some(kind) = local {
            kind.check(
                &head_ids(&transaction, &revision.item_id)?,
                &revision.parents,
            )?;
        }

        insert_revision(&transaction, "revisions", &revision, &id)?;
        // Release the entry being accepted, and the same signed revision if
        // it was held earlier while its author was not yet authorized.
        for held in release.into_iter().chain([id.as_str()]) {
            transaction.execute("DELETE FROM quarantine WHERE revision=?", [held])?;
        }
        // A staged copy is consumed by the same transaction that accepts it.
        transaction.execute("DELETE FROM ingress WHERE revision=?", [&id])?;
        replace_heads(&transaction, &revision, &id)?;
        reseal(&transaction, &seal_key, &seal_vault)?;
        transaction.commit()?;
        Ok(info)
    }

    /// Verifies the author's signature and decrypts; for an edit, also that
    /// the content is a valid item with the revision's item ID.
    fn verify_revision(&self, revision: &EncryptedRevision) -> Result<()> {
        revision.validate_shape(&self.header.vault_id)?;
        if revision.tombstone {
            self.open_revision(revision)?;
            return Ok(());
        }
        let item = self.open_item(revision)?;
        item.validate()?;
        if item.id != revision.item_id {
            return Err(Error::Crypto);
        }
        Ok(())
    }

    /// Held revisions that `revision` builds on, directly or through other
    /// held revisions, ordered parents first. Only revisions by a known
    /// author (authorized, possibly since revoked) that verify are included:
    /// a held revision from an unknown device cannot be checked, so a child
    /// of one keeps waiting. An authorized device that names a held revision
    /// as a parent has accepted it, which vouches for it.
    fn vouched_ancestors(&self, revision: &EncryptedRevision) -> Result<Vec<EncryptedRevision>> {
        let mut ordered = Vec::new();
        let mut seen = BTreeSet::new();
        let mut held_by_id = BTreeMap::new();
        // (revision ID, whether its parents have been visited)
        let mut stack: Vec<(String, bool)> = revision
            .parents
            .iter()
            .rev()
            .map(|parent| (parent.clone(), false))
            .collect();
        while let Some((id, visited)) = stack.pop() {
            if visited {
                ordered.extend(held_by_id.remove(&id));
                continue;
            }
            if seen.len() as i64 > MAX_QUARANTINE || !seen.insert(id.clone()) {
                continue;
            }
            if revision_by_id(&self.connection, &id)?.is_some() {
                continue;
            }
            let Some(held) = quarantined_by_id(&self.connection, &id)? else {
                continue;
            };
            if held.item_id != revision.item_id
                || !self.devices.contains_key(&held.author_device_id)
                || self.verify_revision(&held).is_err()
            {
                continue;
            }
            stack.push((id.clone(), true));
            stack.extend(
                held.parents
                    .iter()
                    .rev()
                    .map(|parent| (parent.clone(), false)),
            );
            held_by_id.insert(id, held);
        }
        Ok(ordered)
    }

    /// Lets the vault file grow by at most `pages` more pages through this
    /// vault's connection, as a full disk would, for tests.
    #[cfg(test)]
    pub(crate) fn limit_growth_for_tests(&self, pages: u32) {
        let count: u32 = self
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap();
        self.connection
            .pragma_update(None, "max_page_count", count + pages)
            .unwrap();
    }

    /// The content of every stored revision, verified, for tests that check
    /// that a damaged file never shows anything else.
    #[cfg(test)]
    pub(crate) fn history_for_tests(&self) -> Result<Vec<Option<Item>>> {
        self.encrypted_revisions()?
            .iter()
            .map(|revision| {
                if revision.tombstone {
                    self.open_revision(revision).map(|_| None)
                } else {
                    self.open_item(revision).map(Some)
                }
            })
            .collect()
    }

    /// Seals an arbitrary revision as this device, bypassing head checks, so
    /// tests can construct invalid ancestry.
    #[cfg(test)]
    pub(crate) fn seal_for_test(
        &self,
        item: &Item,
        parents: Vec<String>,
        tombstone: bool,
    ) -> Result<EncryptedRevision> {
        let plaintext = if tombstone {
            Vec::new()
        } else {
            serde_json::to_vec(item)?
        };
        self.signer()?
            .seal(&item.id, parents, tombstone, &plaintext)
    }

    /// Seals `plaintext` as it is, as a version of `item_id`: what another
    /// build might have written.
    #[cfg(test)]
    pub(crate) fn seal_plaintext_for_test(
        &self,
        item_id: &str,
        parents: Vec<String>,
        tombstone: bool,
        plaintext: &[u8],
    ) -> Result<EncryptedRevision> {
        self.signer()?.seal(item_id, parents, tombstone, plaintext)
    }
}

/// Head-set precondition for a write made on this device.
#[derive(Clone, Copy)]
enum LocalWrite {
    /// A new item: it must have no heads.
    Create,
    /// An ordinary edit or delete of the single named head.
    Edit,
    /// A conflict resolution: every named head must still be current.
    Resolve,
}

impl LocalWrite {
    fn check(self, heads: &[String], parents: &[String]) -> Result<()> {
        let describe = |heads: &[String]| {
            if heads.is_empty() {
                "<missing>".to_owned()
            } else {
                heads.join(",")
            }
        };
        match self {
            Self::Create if heads.is_empty() => Ok(()),
            Self::Create => Err(Error::AlreadyExists),
            Self::Edit if heads.len() > 1 => Err(Error::Unresolved),
            Self::Edit if heads == parents => Ok(()),
            Self::Edit => Err(Error::Conflict {
                expected: describe(parents),
                actual: describe(heads),
            }),
            Self::Resolve => match parents.iter().find(|parent| !heads.contains(parent)) {
                None => Ok(()),
                Some(stale) => Err(Error::Conflict {
                    expected: stale.clone(),
                    actual: describe(heads),
                }),
            },
        }
    }
}

/// Every parent must be stored and belong to the same item.
fn check_parents(connection: &Connection, revision: &EncryptedRevision) -> Result<()> {
    for parent in &revision.parents {
        match revision_by_id(connection, parent)? {
            None => return Err(Error::MissingParent),
            Some(stored) if stored.item_id != revision.item_id => return Err(Error::InvalidParent),
            Some(_) => {}
        }
    }
    Ok(())
}

/// A new revision supersedes exactly the parents it names. Parents always
/// arrive before children, so a new revision is never an ancestor of a
/// stored one, and removing only the named parents keeps every concurrent
/// head.
fn replace_heads(connection: &Connection, revision: &EncryptedRevision, id: &str) -> Result<()> {
    for parent in &revision.parents {
        connection.execute("DELETE FROM heads WHERE revision=?", [parent])?;
    }
    // A revision that arrives after one naming it, as one taken out of the
    // file and fetched again does, is not a head.
    let mut statement = connection.prepare("SELECT parents FROM revisions WHERE item_id=?")?;
    let mut rows = statement.query([&revision.item_id])?;
    while let Some(row) = rows.next()? {
        let parents = split_parents(&row.get::<_, String>(0)?).ok_or(Error::Crypto)?;
        if parents.iter().any(|parent| parent == id) {
            return Ok(());
        }
    }
    connection.execute(
        "INSERT INTO heads(revision,item_id,tombstone) VALUES(?,?,?)",
        params![id, revision.item_id, revision.tombstone],
    )?;
    Ok(())
}

/// Errors after which a held revision stays held: it cannot be applied yet,
/// or it does not verify, which is for the owner to review.
fn error_keeps_hold(error: &Error) -> bool {
    is_rejection(error) || matches!(error, Error::MissingParent | Error::MissingEpochKey)
}

fn is_revision_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(VAULT_META_TABLE)?;
    connection.execute_batch(DEVICES_SCHEMA)?;
    connection.execute_batch(DEVICES_TRIGGER)?;
    connection.execute_batch(REVOCATIONS_SCHEMA)?;
    connection.execute_batch(EPOCH_KEYS_SCHEMA)?;
    connection.execute_batch(RECORD_SCHEMA)?;
    connection.execute_batch(QUARANTINE_SCHEMA)?;
    connection.execute_batch(INGRESS_SCHEMA)?;
    Ok(())
}

fn quarantined_by_id(
    connection: &Connection,
    revision_id: &str,
) -> Result<Option<EncryptedRevision>> {
    connection
        .query_row(
            &format!("SELECT {REVISION_COLUMNS} FROM quarantine r WHERE r.revision=?"),
            [revision_id],
            row_to_revision,
        )
        .optional()
        .map_err(Into::into)
}

fn quarantined_revisions(connection: &Connection) -> Result<Vec<EncryptedRevision>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {REVISION_COLUMNS} FROM quarantine r ORDER BY r.rowid"
    ))?;
    let held = statement
        .query_map([], row_to_revision)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(held)
}

fn revision_by_id(connection: &Connection, revision_id: &str) -> Result<Option<EncryptedRevision>> {
    connection
        .query_row(
            &format!("SELECT {REVISION_COLUMNS} FROM revisions r WHERE r.revision=?"),
            [revision_id],
            row_to_revision,
        )
        .optional()
        .map_err(Into::into)
}

/// Current head IDs of an item, sorted.
fn head_ids(connection: &Connection, item_id: &str) -> Result<Vec<String>> {
    let mut statement =
        connection.prepare("SELECT revision FROM heads WHERE item_id=? ORDER BY revision")?;
    let ids = statement
        .query_map([item_id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(ids)
}

/// Current head revisions of an item, ordered by revision ID.
fn item_heads(connection: &Connection, item_id: &str) -> Result<Vec<EncryptedRevision>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {REVISION_COLUMNS} FROM heads h JOIN revisions r ON r.revision=h.revision \
         WHERE h.item_id=? ORDER BY h.revision"
    ))?;
    let heads = statement
        .query_map([item_id], row_to_revision)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(heads)
}

/// Whether an item of this kind and stored address is a login for `origin`.
fn fills(kind: ItemKind, address: &str, origin: &Origin) -> bool {
    kind == ItemKind::Login && Origin::of_url(address).as_ref() == Some(origin)
}

impl Vault {
    /// This device's root key; also the check that the vault is unlocked.
    fn key(&self) -> Result<&SecretKey> {
        self.root_key.as_ref().ok_or(Error::Locked)
    }
}

#[derive(Serialize, Deserialize)]
struct EpochKeyRecord {
    epoch: u64,
    key: [u8; KEY_LEN],
}

impl Drop for EpochKeyRecord {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    current_epoch: u64,
    epoch_keys: Vec<EpochKeyRecord>,
    devices: Vec<DeviceRecord>,
    revisions: Vec<EncryptedRevision>,
    /// Held revisions, so pending owner review survives a restore.
    #[serde(default)]
    quarantine: Vec<EncryptedRevision>,
    /// Authors removed by committed membership.
    #[serde(default)]
    revoked: Vec<[u8; DEVICE_ID_LEN]>,
}

#[derive(Serialize, Deserialize)]
struct BackupEnvelope {
    magic: String,
    format_version: u32,
    vault_id: String,
    recovery_nonce: String,
    recovery_wrapped_key: String,
    nonce: String,
    ciphertext: String,
}

fn read_backup(path: &Path) -> Result<BackupEnvelope> {
    let file = OpenOptions::new().read(true).open(path)?;
    if file.metadata()?.len() > MAX_BACKUP_BYTES {
        return Err(Error::InvalidBackup("backup is too large".into()));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_BACKUP_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BACKUP_BYTES {
        return Err(Error::InvalidBackup("backup is too large".into()));
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::InvalidBackup("invalid envelope".into()))
}

pub(crate) fn backup_aad(
    vault_id: &[u8; 32],
    recovery_nonce: &str,
    recovery_wrapped_key: &str,
) -> Vec<u8> {
    let mut aad = b"osm-portable-backup-v1\0".to_vec();
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&(recovery_nonce.len() as u64).to_be_bytes());
    aad.extend_from_slice(recovery_nonce.as_bytes());
    aad.extend_from_slice(&(recovery_wrapped_key.len() as u64).to_be_bytes());
    aad.extend_from_slice(recovery_wrapped_key.as_bytes());
    aad
}

fn encode(value: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(value)
}

fn decode(value: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(value).map_err(|_| Error::InvalidBackup("invalid base64".into()))
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let decoded = decode(value)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidBackup("invalid field length".into()))
}

/// Where a new file for `path` is written before it is moved there.
fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    path.with_file_name(name)
}

/// Moves a finished file to `to`, failing if something is there already,
/// and makes the move durable.
fn move_into_place(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => std::fs::remove_file(from)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Err(error),
        // A file system without hard links.
        Err(_) if to.symlink_metadata().is_err() => std::fs::rename(from, to)?,
        Err(error) => return Err(error),
    }
    if let Some(folder) = to.parent().filter(|folder| !folder.as_os_str().is_empty()) {
        // Not every system can sync a folder; the move itself is done.
        let _ = std::fs::File::open(folder).and_then(|folder| folder.sync_all());
    }
    Ok(())
}

fn open_connection(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY; PRAGMA journal_mode=DELETE;"
    )?;
    Ok(connection)
}

fn read_header(connection: &Connection) -> Result<Header> {
    let version: u32 = connection.query_row(
        "SELECT format_version FROM vault_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if !matches!(
        version,
        LEGACY_FORMAT_VERSION
            | SINGLE_HEAD_FORMAT_VERSION
            | MULTI_HEAD_FORMAT_VERSION
            | QUARANTINE_FORMAT_VERSION
            | SHARED_KEY_FORMAT_VERSION
            | ROOT_KEY_FORMAT_VERSION
            | MEMBERSHIP_FORMAT_VERSION
            | VAULT_FORMAT_VERSION
    ) {
        return Err(Error::UnsupportedVersion(version));
    }
    let device_columns = if version != LEGACY_FORMAT_VERSION {
        "device_id,device_public_key,device_key_nonce,device_wrapped_signing_key"
    } else {
        "NULL,NULL,NULL,NULL"
    };
    // Columns added by formats 6 and 7 do not exist in older files.
    let root_columns = if version >= ROOT_KEY_FORMAT_VERSION {
        "recovery_check,legacy_recovery_nonce,legacy_recovery_wrapped_key,current_epoch"
    } else {
        "NULL,NULL,NULL,1"
    };
    let membership_columns = if version >= MEMBERSHIP_FORMAT_VERSION {
        "recipient_nonce,recipient_wrapped_secret,write_fence"
    } else {
        "NULL,NULL,1"
    };
    let seal_columns = if version == VAULT_FORMAT_VERSION {
        "rows_changed"
    } else {
        "0"
    };
    let row = connection.query_row(
        &format!(
            "SELECT vault_id,kdf_memory_kib,kdf_iterations,kdf_parallelism,password_salt,\
             password_nonce,password_wrapped_key,recovery_nonce,recovery_wrapped_key,{device_columns},\
             {root_columns},{membership_columns},{seal_columns} FROM vault_meta WHERE singleton=1"
        ),
        [],
        |row| Ok((
            (
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?, row.get::<_, u32>(2)?, row.get::<_, u32>(3)?,
                row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?, row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?, row.get::<_, Option<Vec<u8>>>(8)?,
            ),
            (
                row.get::<_, Option<Vec<u8>>>(9)?, row.get::<_, Option<Vec<u8>>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?, row.get::<_, Option<Vec<u8>>>(12)?,
            ),
            (
                row.get::<_, Option<Vec<u8>>>(13)?, row.get::<_, Option<Vec<u8>>>(14)?,
                row.get::<_, Option<Vec<u8>>>(15)?, row.get::<_, i64>(16)?,
            ),
            (
                row.get::<_, Option<Vec<u8>>>(17)?, row.get::<_, Option<Vec<u8>>>(18)?,
                row.get::<_, i64>(19)?,
            ),
            row.get::<_, i64>(20)?,
        )),
    )?;
    let (base, device_row, root_row, membership_row, rows_changed) = row;
    let device = match device_row {
        (Some(device_id), Some(public_key), Some(key_nonce), Some(wrapped_signing_key)) => {
            Some(DeviceHeader {
                device_id: array(&device_id)?,
                public_key: array(&public_key)?,
                key_nonce: array(&key_nonce)?,
                wrapped_signing_key,
            })
        }
        (None, None, None, None) if version == LEGACY_FORMAT_VERSION => None,
        _ => return Err(Error::Crypto),
    };
    let recovery = key_wrapper(base.7, base.8)?;
    // Older formats always had a recovery wrapper.
    if version < ROOT_KEY_FORMAT_VERSION && recovery.is_none() {
        return Err(Error::Crypto);
    }
    let current_epoch = u64::try_from(root_row.3).map_err(|_| Error::Crypto)?;
    if current_epoch == 0 || current_epoch > MAX_EPOCH {
        return Err(Error::Crypto);
    }
    let write_fence = u64::try_from(membership_row.2).map_err(|_| Error::Crypto)?;
    if write_fence == 0 || write_fence > MAX_EPOCH {
        return Err(Error::Crypto);
    }
    Ok(Header {
        format_version: version,
        vault_id: array(&base.0)?,
        kdf: KdfConfig {
            memory_kib: base.1,
            iterations: base.2,
            parallelism: base.3,
        },
        password_salt: array(&base.4)?,
        password_nonce: array(&base.5)?,
        password_wrapped_key: base.6,
        recovery,
        recovery_check: root_row.0.map(|check| array(&check)).transpose()?,
        legacy_recovery: key_wrapper(root_row.1, root_row.2)?,
        current_epoch,
        device,
        recipient: key_wrapper(membership_row.0, membership_row.1)?,
        write_fence,
        rows_changed: rows_changed != 0,
    })
}

fn key_wrapper(nonce: Option<Vec<u8>>, wrapped_key: Option<Vec<u8>>) -> Result<Option<KeyWrapper>> {
    match (nonce, wrapped_key) {
        (Some(nonce), Some(wrapped_key)) if wrapped_key.len() == KEY_LEN + 16 => {
            Ok(Some(KeyWrapper {
                nonce: array(&nonce)?,
                wrapped_key,
            }))
        }
        (None, None) => Ok(None),
        _ => Err(Error::Crypto),
    }
}

fn insert_header(connection: &Connection, header: &Header) -> Result<()> {
    let device = header.device.as_ref().ok_or(Error::Crypto)?;
    connection.execute(
        "INSERT INTO vault_meta(singleton,format_version,vault_id,kdf_memory_kib,kdf_iterations,\
         kdf_parallelism,password_salt,password_nonce,password_wrapped_key,recovery_nonce,\
         recovery_wrapped_key,recovery_check,legacy_recovery_nonce,legacy_recovery_wrapped_key,\
         current_epoch,device_id,device_public_key,device_key_nonce,device_wrapped_signing_key,\
         recipient_nonce,recipient_wrapped_secret,write_fence) \
         VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            header.format_version,
            header.vault_id.as_slice(),
            header.kdf.memory_kib,
            header.kdf.iterations,
            header.kdf.parallelism,
            header.password_salt.as_slice(),
            header.password_nonce.as_slice(),
            header.password_wrapped_key,
            header
                .recovery
                .as_ref()
                .map(|wrapper| wrapper.nonce.to_vec()),
            header
                .recovery
                .as_ref()
                .map(|wrapper| wrapper.wrapped_key.clone()),
            header.recovery_check.map(|check| check.to_vec()),
            header
                .legacy_recovery
                .as_ref()
                .map(|wrapper| wrapper.nonce.to_vec()),
            header
                .legacy_recovery
                .as_ref()
                .map(|wrapper| wrapper.wrapped_key.clone()),
            i64::try_from(header.current_epoch).map_err(|_| Error::Crypto)?,
            device.device_id.as_slice(),
            device.public_key.as_slice(),
            device.key_nonce.as_slice(),
            device.wrapped_signing_key,
            header
                .recipient
                .as_ref()
                .map(|wrapper| wrapper.nonce.to_vec()),
            header
                .recipient
                .as_ref()
                .map(|wrapper| wrapper.wrapped_key.clone()),
            i64::try_from(header.write_fence).map_err(|_| Error::Crypto)?,
        ],
    )?;
    Ok(())
}

fn wrap_with_password(
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: KdfConfig,
    vault_id: &[u8; 32],
    root_key: &SecretKey,
) -> Result<KeyWrapper> {
    let wrapping_key = derive_password_key(password, salt, kdf)?;
    wrap_with(&wrapping_key, vault_id, b"password", root_key)
}

fn wrap_with_recovery(
    recovery: &RecoveryKey,
    vault_id: &[u8; 32],
    root_key: &SecretKey,
) -> Result<KeyWrapper> {
    wrap_with(recovery.expose(), vault_id, b"recovery", root_key)
}

fn wrap_with(
    wrapping_key: &[u8; KEY_LEN],
    vault_id: &[u8; 32],
    method: &[u8],
    root_key: &SecretKey,
) -> Result<KeyWrapper> {
    let nonce = random_array::<NONCE_LEN>();
    Ok(KeyWrapper {
        nonce,
        wrapped_key: encrypt(
            wrapping_key,
            &nonce,
            &key_wrap_aad(vault_id, method),
            root_key.as_ref(),
        )?,
    })
}

fn wrap_recipient_secret(
    root_key: &SecretKey,
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
    secret: &[u8; KEY_LEN],
) -> Result<KeyWrapper> {
    let nonce = random_array::<NONCE_LEN>();
    Ok(KeyWrapper {
        nonce,
        wrapped_key: encrypt(
            root_key,
            &nonce,
            &recipient_key_aad(vault_id, device_id),
            secret,
        )?,
    })
}

fn store_epoch_key(
    connection: &Connection,
    root_key: &SecretKey,
    vault_id: &[u8; 32],
    epoch: u64,
    key: &[u8; KEY_LEN],
) -> Result<()> {
    if epoch == 0 || epoch > MAX_EPOCH {
        return Err(Error::Crypto);
    }
    let nonce = random_array::<NONCE_LEN>();
    let wrapped = encrypt(root_key, &nonce, &epoch_key_aad(vault_id, epoch), key)?;
    connection.execute(
        "INSERT INTO epoch_keys(epoch,nonce,wrapped_key) VALUES(?,?,?)",
        params![
            i64::try_from(epoch).map_err(|_| Error::Crypto)?,
            nonce.as_slice(),
            wrapped
        ],
    )?;
    Ok(())
}

fn load_epoch_keys(
    connection: &Connection,
    root_key: &SecretKey,
    vault_id: &[u8; 32],
) -> Result<BTreeMap<u64, SecretKey>> {
    let mut statement = connection.prepare("SELECT epoch,nonce,wrapped_key FROM epoch_keys")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut keys = BTreeMap::new();
    for (epoch, nonce, wrapped) in rows {
        let epoch = u64::try_from(epoch).map_err(|_| Error::Crypto)?;
        let key = decrypt(
            root_key,
            &array(&nonce)?,
            &epoch_key_aad(vault_id, epoch),
            &wrapped,
        )
        .map_err(|_| Error::Crypto)?;
        keys.insert(epoch, to_key(&key)?);
    }
    Ok(keys)
}

impl Header {
    fn device_record(&self) -> Result<DeviceRecord> {
        let device = self.device.as_ref().ok_or(Error::Crypto)?;
        Ok(DeviceRecord {
            device_id: device.device_id,
            public_key: device.public_key,
        })
    }
}

/// The label a device signing key is wrapped under in a vault of `format`.
fn signing_key_aad(
    format: u32,
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Vec<u8> {
    if format >= VAULT_FORMAT_VERSION {
        sealed_device_key_aad(vault_id, device_id, public_key)
    } else {
        device_key_aad(vault_id, device_id, public_key)
    }
}

/// The keys of the rows the seal covers.
fn row_sets(connection: &Connection) -> Result<RowSets> {
    fn column<T: rusqlite::types::FromSql>(connection: &Connection, sql: &str) -> Result<Vec<T>> {
        let mut statement = connection.prepare(sql)?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    Ok(RowSets {
        revisions: column(
            connection,
            "SELECT revision FROM revisions ORDER BY revision",
        )?,
        devices: column(
            connection,
            "SELECT device_id FROM devices ORDER BY device_id",
        )?,
        revoked: column(
            connection,
            "SELECT device_id FROM revoked_devices ORDER BY device_id",
        )?,
        epochs: column::<i64>(connection, "SELECT epoch FROM epoch_keys ORDER BY epoch")?
            .into_iter()
            .map(|epoch| u64::try_from(epoch).map_err(|_| Error::Crypto))
            .collect::<Result<_>>()?,
    })
}

/// Seals the rows never changed or removed, from all of them: when a vault
/// is made or reaches format 8, and when an unlock finds the seal broken.
fn seal_rows(connection: &Connection, root_key: &SecretKey, vault_id: &[u8; 32]) -> Result<()> {
    let marks = row_marks(&*row_seal_key(root_key)?, &row_sets(connection)?)?;
    store_row_seal(connection, root_key, vault_id, &marks)?;
    forget_added_rows(connection)
}

/// Adds to the seal the rows added since it was last written, which the
/// connection's own triggers listed (`SEAL_TRACKING`). Called in the
/// transaction that adds them, so the seal always matches what that
/// transaction leaves, and costs the same however many rows there are. A
/// seal that no longer opens was broken since the unlock: the owner is told
/// at the next one, and the rows are sealed from all of them.
fn reseal(connection: &Connection, root_key: &SecretKey, vault_id: &[u8; 32]) -> Result<()> {
    let stored: Option<Vec<u8>> = connection.query_row(
        "SELECT row_seal FROM vault_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let Some(mut marks) = stored.and_then(|stored| open_row_seal(root_key, vault_id, &stored))
    else {
        connection.execute("UPDATE vault_meta SET rows_changed=1 WHERE singleton=1", [])?;
        return seal_rows(connection, root_key, vault_id);
    };
    let seal_key = row_seal_key(root_key)?;
    let mut statement =
        connection.prepare("SELECT set_name, row_key FROM temp.sealed_rows_added")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let table: String = row.get(0)?;
        let key: Vec<u8> = if table == "epoch_keys" {
            let epoch = u64::try_from(row.get::<_, i64>(1)?).map_err(|_| Error::Crypto)?;
            epoch.to_be_bytes().to_vec()
        } else {
            row.get(1)?
        };
        xor_into(&mut marks, &row_mark(&seal_key, &table, &key)?);
    }
    drop(rows);
    drop(statement);
    store_row_seal(connection, root_key, vault_id, &marks)?;
    forget_added_rows(connection)
}

fn store_row_seal(
    connection: &Connection,
    root_key: &SecretKey,
    vault_id: &[u8; 32],
    marks: &[u8; 32],
) -> Result<()> {
    let nonce = random_array::<NONCE_LEN>();
    let mut seal = nonce.to_vec();
    seal.extend_from_slice(&encrypt(root_key, &nonce, &row_seal_aad(vault_id), marks)?);
    connection.execute("UPDATE vault_meta SET row_seal=? WHERE singleton=1", [seal])?;
    Ok(())
}

/// The marks a stored seal holds, or nothing if it does not open.
fn open_row_seal(root_key: &SecretKey, vault_id: &[u8; 32], stored: &[u8]) -> Option<[u8; 32]> {
    let (nonce, sealed) = stored.split_first_chunk::<NONCE_LEN>()?;
    let marks = decrypt(root_key, nonce, &row_seal_aad(vault_id), sealed).ok()?;
    marks.as_slice().try_into().ok()
}

fn forget_added_rows(connection: &Connection) -> Result<()> {
    let tracking: bool = connection.query_row(
        "SELECT count(*) > 0 FROM sqlite_temp_master WHERE name='sealed_rows_added'",
        [],
        |row| row.get(0),
    )?;
    if tracking {
        connection.execute("DELETE FROM temp.sealed_rows_added", [])?;
    }
    Ok(())
}

/// Creates a random device identity whose signing key is wrapped by the
/// device's root key (the shared vault key in older formats), under the
/// label of the vault's `format`.
fn generate_device(
    master_key: &SecretKey,
    vault_id: &[u8; 32],
    format: u32,
) -> Result<(DeviceHeader, SigningKey)> {
    let seed = Zeroizing::new(random_array::<32>());
    let signing_key = SigningKey::from_bytes(&seed);
    let device_id = random_array::<DEVICE_ID_LEN>();
    let public_key = signing_key.verifying_key().to_bytes();
    let key_nonce = random_array::<NONCE_LEN>();
    let wrapped_signing_key = encrypt(
        master_key,
        &key_nonce,
        &signing_key_aad(format, vault_id, &device_id, &public_key),
        seed.as_ref(),
    )?;
    Ok((
        DeviceHeader {
            device_id,
            public_key,
            key_nonce,
            wrapped_signing_key,
        },
        signing_key,
    ))
}

fn insert_device_authorization(
    connection: &Connection,
    master_key: &SecretKey,
    header: &Header,
    record: &DeviceRecord,
) -> Result<()> {
    let authorization = device_authorization(
        master_key,
        &header.vault_id,
        &record.device_id,
        &record.public_key,
    )?;
    connection.execute(
        "INSERT INTO devices(device_id,public_key,authorization) VALUES(?,?,?)",
        params![
            record.device_id.as_slice(),
            record.public_key.as_slice(),
            authorization.as_slice(),
        ],
    )?;
    Ok(())
}

/// Loads the authorized author set, failing closed if any row was not
/// written by a holder of the master key.
fn load_devices(
    connection: &Connection,
    master_key: &SecretKey,
    vault_id: &[u8; 32],
) -> Result<BTreeMap<[u8; DEVICE_ID_LEN], VerifyingKey>> {
    let mut statement =
        connection.prepare("SELECT device_id,public_key,authorization FROM devices")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut devices = BTreeMap::new();
    for (device_id, public_key, authorization) in rows {
        let device_id = array::<DEVICE_ID_LEN>(&device_id)?;
        let public_key = array::<PUBLIC_KEY_LEN>(&public_key)?;
        verify_device_authorization(
            master_key,
            vault_id,
            &device_id,
            &public_key,
            &authorization,
        )?;
        let verifying = VerifyingKey::from_bytes(&public_key).map_err(|_| Error::Crypto)?;
        devices.insert(device_id, verifying);
    }
    Ok(devices)
}

/// Loads the revoked devices, failing closed if any row was not written by
/// a holder of the root key.
fn load_revocations(
    connection: &Connection,
    root_key: &SecretKey,
    vault_id: &[u8; 32],
) -> Result<BTreeSet<[u8; DEVICE_ID_LEN]>> {
    let mut statement = connection.prepare("SELECT device_id,revocation FROM revoked_devices")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut revoked = BTreeSet::new();
    for (device_id, revocation) in rows {
        let device_id = array::<DEVICE_ID_LEN>(&device_id)?;
        verify_device_revocation(root_key, vault_id, &device_id, &revocation)?;
        revoked.insert(device_id);
    }
    Ok(revoked)
}

fn insert_revocation(
    connection: &Connection,
    root_key: &SecretKey,
    vault_id: &[u8; 32],
    device_id: &[u8; DEVICE_ID_LEN],
) -> Result<()> {
    let revocation = device_revocation(root_key, vault_id, device_id)?;
    connection.execute(
        "INSERT OR IGNORE INTO revoked_devices(device_id,revocation) VALUES(?,?)",
        params![device_id.as_slice(), revocation.as_slice()],
    )?;
    Ok(())
}

/// A format 1 row, read only while migrating.
struct LegacyRevision {
    revision: String,
    item_id: String,
    parent_revision: Option<String>,
    key_epoch: u64,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    tombstone: bool,
}

/// Returns format 1 revisions in insertion order, so every parent precedes
/// its children.
fn legacy_revisions(connection: &Connection, vault_id: &[u8; 32]) -> Result<Vec<LegacyRevision>> {
    let mut statement = connection.prepare(
        "SELECT revision,format_version,vault_id,item_id,parent_revision,key_epoch,nonce,ciphertext,tombstone \
         FROM revisions ORDER BY rowid",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                LegacyRevision {
                    revision: String::new(),
                    item_id: row.get(3)?,
                    parent_revision: row.get(4)?,
                    key_epoch: u64::try_from(row.get::<_, i64>(5)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    nonce: row
                        .get::<_, Vec<u8>>(6)?
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ciphertext: row.get(7)?,
                    tombstone: row.get(8)?,
                },
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(revision, version, row_vault_id, mut legacy)| {
            if version != LEGACY_FORMAT_VERSION
                || row_vault_id.as_slice() != vault_id.as_slice()
                || legacy.key_epoch != FIRST_EPOCH
            {
                return Err(Error::Crypto);
            }
            legacy.revision = revision;
            Ok(legacy)
        })
        .collect()
}

fn row_to_revision(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedRevision> {
    row_to_revision_at(row, 0)
}

/// Reads `REVISION_COLUMNS` starting at column `at`.
fn row_to_revision_at(row: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<EncryptedRevision> {
    let vault_id: Vec<u8> = row.get(at + 1)?;
    let author_device_id: Vec<u8> = row.get(at + 5)?;
    let nonce: Vec<u8> = row.get(at + 6)?;
    Ok(EncryptedRevision {
        format_version: row.get(at)?,
        vault_id: vault_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        item_id: row.get(at + 2)?,
        parents: split_parents(&row.get::<_, String>(at + 3)?)
            .ok_or(rusqlite::Error::InvalidQuery)?,
        key_epoch: u64::try_from(row.get::<_, i64>(at + 4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        author_device_id: author_device_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        nonce: nonce
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ciphertext: row.get(at + 7)?,
        tombstone: row.get(at + 8)?,
        signature: row.get(at + 9)?,
    })
}

fn split_parents(joined: &str) -> Option<Vec<String>> {
    let (chunks, rest) = joined.as_bytes().as_chunks::<64>();
    if !rest.is_empty() || !joined.is_ascii() {
        return None;
    }
    Some(
        chunks
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect(),
    )
}

/// `table` is `revisions` or `quarantine`; both hold the same columns.
fn insert_revision(
    connection: &Connection,
    table: &'static str,
    revision: &EncryptedRevision,
    id: &str,
) -> Result<()> {
    connection.execute(
        &format!(
            "INSERT INTO {table}(revision,format_version,vault_id,item_id,parents,key_epoch,\
             author_device_id,nonce,ciphertext,tombstone,signature) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
        ),
        params![
            id,
            revision.format_version,
            revision.vault_id.as_slice(),
            revision.item_id,
            revision.parents.concat(),
            i64::try_from(revision.key_epoch).map_err(|_| Error::Crypto)?,
            revision.author_device_id.as_slice(),
            revision.nonce.as_slice(),
            revision.ciphertext,
            revision.tombstone,
            revision.signature,
        ],
    )?;
    Ok(())
}

fn array<const N: usize>(value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| Error::Crypto)
}

fn to_key(value: &[u8]) -> Result<SecretKey> {
    Ok(Zeroizing::new(array(value)?))
}

/// Prepended to every pairing signature so one can never be mistaken for a
/// revision signature made with the same device key.
pub const PAIRING_SIGNATURE_DOMAIN: &[u8] = b"osm-pairing-signature-v1\0";

/// Prepended to every membership control signature; see
/// [`Vault::sign_control`].
pub const CONTROL_SIGNATURE_DOMAIN: &[u8] = b"osm-control-signature-v1\0";

fn pairing_signature(key: &SigningKey, message: &[u8]) -> [u8; SIGNATURE_LEN] {
    let mut signed = PAIRING_SIGNATURE_DOMAIN.to_vec();
    signed.extend_from_slice(message);
    key.sign(&signed).to_bytes()
}

/// Verifies a signature from `Vault::sign_pairing` or
/// `PendingDevice::sign_pairing`.
pub fn verify_pairing_signature(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
    let mut signed = PAIRING_SIGNATURE_DOMAIN.to_vec();
    signed.extend_from_slice(message);
    key.verify_strict(&signed, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// A device identity created before the device holds the vault key. Its
/// signing key is wrapped by the master key only when `Vault::join` runs.
pub struct PendingDevice {
    device_id: [u8; DEVICE_ID_LEN],
    seed: Zeroizing<[u8; 32]>,
    /// Secret behind the device's HPKE recipient key; `Vault::join` wraps
    /// it under the new root key.
    recipient: SecretKey,
}

impl PendingDevice {
    pub fn generate() -> Self {
        Self {
            device_id: random_array(),
            seed: Zeroizing::new(random_array()),
            recipient: Zeroizing::new(random_array()),
        }
    }

    pub fn device_id(&self) -> [u8; DEVICE_ID_LEN] {
        self.device_id
    }

    /// The secret the device's HPKE recipient key pair is derived from.
    /// Epoch keys are sealed to that key; keep the secret in memory only.
    pub fn recipient_secret(&self) -> SecretKey {
        self.recipient.clone()
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    /// Signs a pairing message; `PAIRING_SIGNATURE_DOMAIN` is prepended.
    pub fn sign_pairing(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        pairing_signature(&SigningKey::from_bytes(&self.seed), message)
    }
}

impl std::fmt::Debug for PendingDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingDevice")
            .field("device_id", &self.device_id)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

/// What a newly paired device needs to open this vault besides its own
/// password. It carries epoch keys, never the root key, so the joiner wraps
/// them under a root key of its own.
pub struct EnrollmentMaterial {
    pub vault_id: [u8; 32],
    pub current_epoch: u64,
    /// Every epoch key this device holds. Each must leave this process only
    /// sealed to the joiner.
    pub epoch_keys: Vec<(u64, SecretKey)>,
    /// Lets the joiner verify the recovery key before enabling recovery.
    pub recovery_check: Option<[u8; 32]>,
    /// Authorized authors as (device ID, public key), including this device.
    pub devices: Vec<([u8; DEVICE_ID_LEN], [u8; PUBLIC_KEY_LEN])>,
    /// Authors among `devices` that committed membership has removed.
    pub revoked: Vec<[u8; DEVICE_ID_LEN]>,
}

impl std::fmt::Debug for EnrollmentMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentMaterial")
            .field("current_epoch", &self.current_epoch)
            .field("epoch_keys", &self.epoch_keys.len())
            .field("devices", &self.devices.len())
            .finish_non_exhaustive()
    }
}

/// Record tables accept any epoch from format 6 on. Re-rooting renames the
/// format 5 tables so they can be recreated and every row copied unchanged.
const SET_ASIDE_RECORD_TABLES: &str = r#"
DROP TRIGGER revisions_no_update;
DROP TRIGGER revisions_no_delete;
DROP INDEX revisions_item_id;
DROP INDEX heads_item_id;
ALTER TABLE heads RENAME TO heads_old;
ALTER TABLE revisions RENAME TO revisions_old;
DROP TRIGGER quarantine_no_update;
ALTER TABLE quarantine RENAME TO quarantine_old;
DROP TRIGGER ingress_no_update;
ALTER TABLE ingress RENAME TO ingress_old;
"#;

const COPY_RECORD_TABLES: &str = r#"
INSERT INTO revisions(revision,format_version,vault_id,item_id,parents,key_epoch,
    author_device_id,nonce,ciphertext,tombstone,signature)
SELECT revision,format_version,vault_id,item_id,parents,key_epoch,
    author_device_id,nonce,ciphertext,tombstone,signature
FROM revisions_old ORDER BY rowid;
INSERT INTO heads(revision,item_id,tombstone) SELECT revision,item_id,tombstone FROM heads_old;
INSERT INTO quarantine(revision,format_version,vault_id,item_id,parents,key_epoch,
    author_device_id,nonce,ciphertext,tombstone,signature)
SELECT revision,format_version,vault_id,item_id,parents,key_epoch,
    author_device_id,nonce,ciphertext,tombstone,signature
FROM quarantine_old ORDER BY rowid;
INSERT INTO ingress(revision,format_version,vault_id,item_id,parents,key_epoch,
    author_device_id,nonce,ciphertext,tombstone,signature)
SELECT revision,format_version,vault_id,item_id,parents,key_epoch,
    author_device_id,nonce,ciphertext,tombstone,signature
FROM ingress_old ORDER BY rowid;
DROP TABLE heads_old;
DROP TABLE revisions_old;
DROP TABLE quarantine_old;
DROP TABLE ingress_old;
"#;

impl Vault {
    /// Signs a pairing message with this device's key;
    /// `PAIRING_SIGNATURE_DOMAIN` is prepended.
    pub fn sign_pairing(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
        let key = self.signing_key.as_ref().ok_or(Error::Locked)?;
        Ok(pairing_signature(key, message))
    }

    /// Authorized revision authors as (device ID, public key).
    pub fn authorized_devices(&self) -> Result<Vec<([u8; DEVICE_ID_LEN], [u8; PUBLIC_KEY_LEN])>> {
        self.key()?;
        Ok(self
            .devices
            .iter()
            .map(|(device_id, key)| (*device_id, key.to_bytes()))
            .collect())
    }

    /// Exports what a paired device needs to open this vault. Call only for
    /// an owner-confirmed enrollment, and seal every epoch key to the joiner.
    pub fn enrollment_material(&self) -> Result<EnrollmentMaterial> {
        Ok(EnrollmentMaterial {
            vault_id: self.header.vault_id,
            current_epoch: self.header.current_epoch,
            epoch_keys: self.epoch_keys()?,
            recovery_check: self.header.recovery_check,
            devices: self.authorized_devices()?,
            revoked: self.revoked_devices()?,
        })
    }

    /// Signs a membership control request with this device's key;
    /// `CONTROL_SIGNATURE_DOMAIN` is prepended, so the signature can never
    /// pass as a revision or pairing signature.
    pub fn sign_control(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
        let key = self.signing_key.as_ref().ok_or(Error::Locked)?;
        let mut signed = CONTROL_SIGNATURE_DOMAIN.to_vec();
        signed.extend_from_slice(message);
        Ok(key.sign(&signed).to_bytes())
    }

    /// The secret this device's HPKE recipient key pair is derived from.
    /// Epoch keys for this device are sealed to that key.
    pub fn recipient_secret(&self) -> Result<SecretKey> {
        self.recipient_secret.clone().ok_or(Error::Locked)
    }

    /// Authors removed by committed membership.
    pub fn revoked_devices(&self) -> Result<Vec<[u8; DEVICE_ID_LEN]>> {
        self.key()?;
        Ok(self.revoked.iter().copied().collect())
    }

    /// Records that committed membership removed `device_id`. Its stored
    /// revisions stay readable. A revision of its that this device has not
    /// accepted yet is held for review, unless an authorized device's
    /// revision names it as a parent. Returns whether this is new.
    pub fn revoke_device(&mut self, device_id: [u8; DEVICE_ID_LEN]) -> Result<bool> {
        let root_key = self.key()?.clone();
        if Some(device_id) == self.device_id() {
            return Err(Error::InvalidDevice("a device cannot revoke itself"));
        }
        if !self.devices.contains_key(&device_id) {
            return Err(Error::InvalidDevice(
                "only an authorized author can be revoked",
            ));
        }
        if self.revoked.contains(&device_id) {
            return Ok(false);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_revocation(&transaction, &root_key, &self.header.vault_id, &device_id)?;
        reseal(&transaction, &root_key, &self.header.vault_id)?;
        transaction.commit()?;
        self.revoked.insert(device_id);
        Ok(true)
    }

    /// The earliest epoch new revisions may use.
    pub fn write_fence(&self) -> u64 {
        self.header.write_fence
    }

    /// Stops writes under any epoch before `epoch` until it is activated.
    /// Call when committed membership activates `epoch`. Works while
    /// locked; the fence is never lowered.
    pub fn raise_write_fence(&mut self, epoch: u64) -> Result<()> {
        if epoch == 0 || epoch > MAX_EPOCH {
            return Err(Error::Crypto);
        }
        let epoch_value = i64::try_from(epoch).map_err(|_| Error::Crypto)?;
        self.connection.execute(
            "UPDATE vault_meta SET write_fence=? WHERE singleton=1 AND write_fence<?",
            params![epoch_value, epoch_value],
        )?;
        self.header.write_fence = self.header.write_fence.max(epoch);
        Ok(())
    }

    /// Creates this device's copy of a vault from enrollment material, under
    /// a new root key of its own. Recovery starts disabled; see
    /// [`Vault::enable_recovery`]. Revisions arrive by sync.
    pub fn join(
        path: impl AsRef<Path>,
        password: &str,
        device: PendingDevice,
        material: EnrollmentMaterial,
    ) -> Result<Self> {
        let epochs: BTreeSet<u64> = material
            .epoch_keys
            .iter()
            .map(|(epoch, _)| *epoch)
            .collect();
        if epochs.len() != material.epoch_keys.len()
            || epochs.len() > MAX_EPOCHS
            || !epochs.contains(&material.current_epoch)
            || epochs.iter().any(|epoch| *epoch == 0 || *epoch > MAX_EPOCH)
        {
            return Err(Error::Crypto);
        }
        Self::build_new(path.as_ref(), |partial| {
            Self::initialize_joined(partial, password, device, material).map(|vault| (vault, ()))
        })
        .map(|(vault, ())| vault)
    }

    fn initialize_joined(
        path: &Path,
        password: &str,
        device: PendingDevice,
        material: EnrollmentMaterial,
    ) -> Result<Self> {
        let connection = open_connection(path)?;
        create_schema(&connection)?;
        let vault_id = material.vault_id;
        let root_key = Zeroizing::new(random_array::<KEY_LEN>());
        let kdf = KdfConfig::default();
        let password_salt = random_array::<SALT_LEN>();
        let password = wrap_with_password(password, &password_salt, kdf, &vault_id, &root_key)?;
        let public_key = device.public_key();
        let key_nonce = random_array::<NONCE_LEN>();
        let wrapped_signing_key = encrypt(
            &root_key,
            &key_nonce,
            &sealed_device_key_aad(&vault_id, &device.device_id, &public_key),
            device.seed.as_ref(),
        )?;
        let recipient =
            wrap_recipient_secret(&root_key, &vault_id, &device.device_id, &device.recipient)?;
        let header = Header {
            format_version: VAULT_FORMAT_VERSION,
            vault_id,
            kdf,
            password_salt,
            password_nonce: password.nonce,
            password_wrapped_key: password.wrapped_key,
            recovery: None,
            recovery_check: material.recovery_check,
            legacy_recovery: None,
            current_epoch: material.current_epoch,
            device: Some(DeviceHeader {
                device_id: device.device_id,
                public_key,
                key_nonce,
                wrapped_signing_key,
            }),
            recipient: Some(recipient),
            write_fence: material.current_epoch,
            rows_changed: false,
        };
        insert_header(&connection, &header)?;
        insert_device_authorization(&connection, &root_key, &header, &header.device_record()?)?;
        for (device_id, key) in &material.devices {
            if *device_id == device.device_id {
                // The inviter may already list this device; it must be the
                // same key.
                if *key != public_key {
                    return Err(Error::Crypto);
                }
                continue;
            }
            insert_device_authorization(
                &connection,
                &root_key,
                &header,
                &DeviceRecord {
                    device_id: *device_id,
                    public_key: *key,
                },
            )?;
        }
        for (epoch, key) in &material.epoch_keys {
            store_epoch_key(&connection, &root_key, &vault_id, *epoch, key)?;
        }
        for device_id in &material.revoked {
            if *device_id == device.device_id
                || !material.devices.iter().any(|(id, _)| id == device_id)
            {
                return Err(Error::Crypto);
            }
            insert_revocation(&connection, &root_key, &vault_id, device_id)?;
        }
        seal_rows(&connection, &root_key, &vault_id)?;
        let header = read_header(&connection)?;
        let mut vault = Self::from_parts(path, connection, header);
        vault.activate(root_key, None)?;
        Ok(vault)
    }

    /// Every epoch key this device holds. Each must leave this process only
    /// sealed to a recipient device.
    pub fn epoch_keys(&self) -> Result<Vec<(u64, SecretKey)>> {
        self.key()?;
        Ok(self
            .epoch_keys
            .iter()
            .map(|(epoch, key)| (*epoch, key.clone()))
            .collect())
    }

    /// Stores the key for `epoch`, received from another member. Installing
    /// the same key again is a no-op; a different key for a known epoch is
    /// refused. Staged revisions under that epoch become processable.
    pub fn install_epoch_key(&mut self, epoch: u64, key: &[u8; KEY_LEN]) -> Result<()> {
        let root_key = self.key()?.clone();
        if let Some(existing) = self.epoch_keys.get(&epoch) {
            return if keys_equal(existing, key) {
                Ok(())
            } else {
                Err(Error::Crypto)
            };
        }
        if self.epoch_keys.len() >= MAX_EPOCHS {
            return Err(Error::Crypto);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        store_epoch_key(&transaction, &root_key, &self.header.vault_id, epoch, key)?;
        reseal(&transaction, &root_key, &self.header.vault_id)?;
        transaction.commit()?;
        self.epoch_keys.insert(epoch, Zeroizing::new(*key));
        Ok(())
    }

    /// Creates and stores the key for the next epoch without activating it.
    /// Only for a vault without a control plane: committed rotation instead
    /// seals a fresh key into the removal proposal, and each member installs
    /// it from committed state, so a key stored here for that epoch would
    /// conflict with it.
    pub fn generate_epoch_key(&mut self) -> Result<(u64, SecretKey)> {
        self.key()?;
        let epoch = self.epoch_keys.keys().next_back().copied().unwrap_or(0) + 1;
        let key = Zeroizing::new(random_array::<KEY_LEN>());
        self.install_epoch_key(epoch, &key)?;
        Ok((epoch, key))
    }

    /// Makes `epoch` the one new revisions are written under. Call only when
    /// committed membership has activated it; older epochs stay readable.
    pub fn activate_epoch(&mut self, epoch: u64) -> Result<()> {
        self.key()?;
        if epoch <= self.header.current_epoch {
            return Err(Error::Conflict {
                expected: format!("an epoch after {}", self.header.current_epoch),
                actual: epoch.to_string(),
            });
        }
        if !self.epoch_keys.contains_key(&epoch) {
            return Err(Error::MissingEpochKey);
        }
        self.connection.execute(
            "UPDATE vault_meta SET current_epoch=? WHERE singleton=1",
            [i64::try_from(epoch).map_err(|_| Error::Crypto)?],
        )?;
        self.header.current_epoch = epoch;
        Ok(())
    }

    /// Turns on recovery for this device after checking that `recovery` is
    /// this vault's recovery key: against the vault's recovery check, or for
    /// a re-rooted vault against its old recovery wrapper.
    pub fn enable_recovery(&mut self, recovery: &RecoveryKey) -> Result<()> {
        let root_key = self.key()?.clone();
        let vault_id = self.header.vault_id;
        match (&self.header.recovery_check, &self.header.legacy_recovery) {
            (Some(check), _) => verify_recovery_check(recovery.expose(), &vault_id, check)?,
            (None, Some(legacy)) => {
                let old_key = decrypt(
                    recovery.expose(),
                    &legacy.nonce,
                    &key_wrap_aad(&vault_id, b"recovery"),
                    &legacy.wrapped_key,
                )
                .map_err(|_| Error::InvalidRecoveryKey)?;
                let first = self.epoch_keys.get(&FIRST_EPOCH).ok_or(Error::Crypto)?;
                if !keys_equal(&array(&old_key)?, first) {
                    return Err(Error::InvalidRecoveryKey);
                }
            }
            // Nothing to check a typed key against; enable recovery on a
            // device that has it first, then pair from there.
            (None, None) => return Err(Error::InvalidRecoveryKey),
        }
        let wrapper = wrap_with_recovery(recovery, &vault_id, &root_key)?;
        let check = recovery_check(recovery.expose(), &vault_id)?;
        self.connection.execute(
            "UPDATE vault_meta SET recovery_nonce=?, recovery_wrapped_key=?, recovery_check=?, \
             legacy_recovery_nonce=NULL, legacy_recovery_wrapped_key=NULL WHERE singleton=1",
            params![
                wrapper.nonce.as_slice(),
                wrapper.wrapped_key,
                check.as_slice()
            ],
        )?;
        self.header.recovery = Some(wrapper);
        self.header.recovery_check = Some(check);
        self.header.legacy_recovery = None;
        Ok(())
    }

    /// Keeps the vault's recovery key in the vault, wrapped by this device's
    /// root key, until [`Vault::confirm_recovery_key_stored`]. A recovery
    /// key is shown to the owner once, when a vault is made; if the app
    /// stops before that, the key would be lost with no way to make
    /// another. Kept like this, it can be shown again after any unlock.
    ///
    /// Only this vault's recovery key is taken. While it is kept, whoever
    /// can unlock this device can read it, and it opens every device of the
    /// vault that has recovery turned on.
    pub fn keep_recovery_key_until_confirmed(&mut self, recovery: &RecoveryKey) -> Result<()> {
        let root_key = self.key()?.clone();
        let vault_id = self.header.vault_id;
        let check = self
            .header
            .recovery_check
            .ok_or(Error::RecoveryNotEnabled)?;
        verify_recovery_check(recovery.expose(), &vault_id, &check)?;
        let nonce = random_array::<NONCE_LEN>();
        let wrapped = encrypt(
            &root_key,
            &nonce,
            &key_wrap_aad(&vault_id, b"unconfirmed-recovery"),
            recovery.expose(),
        )?;
        self.connection.execute_batch(UNCONFIRMED_RECOVERY_SCHEMA)?;
        self.connection.execute(
            "INSERT OR REPLACE INTO unconfirmed_recovery(singleton,nonce,wrapped_key) VALUES(1,?,?)",
            params![nonce.as_slice(), wrapped],
        )?;
        Ok(())
    }

    /// The recovery key the owner has not yet confirmed storing, if one is
    /// kept.
    pub fn unconfirmed_recovery_key(&self) -> Result<Option<RecoveryKey>> {
        let root_key = self.key()?;
        if !self.keeps_recovery_key()? {
            return Ok(None);
        }
        let kept = self
            .connection
            .query_row(
                "SELECT nonce, wrapped_key FROM unconfirmed_recovery WHERE singleton=1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let Some((nonce, wrapped)) = kept else {
            return Ok(None);
        };
        let key = decrypt(
            root_key,
            &array(&nonce)?,
            &key_wrap_aad(&self.header.vault_id, b"unconfirmed-recovery"),
            &wrapped,
        )
        .map_err(|_| Error::Crypto)?;
        Ok(Some(RecoveryKey::from_bytes(array(&key)?)))
    }

    /// The owner has stored the recovery key: it is no longer kept. Works
    /// while locked, since it only removes.
    pub fn confirm_recovery_key_stored(&mut self) -> Result<()> {
        if self.keeps_recovery_key()? {
            self.connection
                .execute("DELETE FROM unconfirmed_recovery", [])?;
        }
        Ok(())
    }

    fn keeps_recovery_key(&self) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master \
             WHERE type='table' AND name='unconfirmed_recovery')",
            [],
            |row| row.get(0),
        )?)
    }

    /// Re-roots a format 5 vault in one transaction. The shared vault key
    /// becomes epoch 1; a new random root key takes over wrapping the device
    /// key, the authorized-author MACs, and the epoch keys; and the password
    /// wrapper is rewritten for it. Recovery stays off until the recovery
    /// key is entered again; the old recovery wrapper is kept only to check
    /// it. Every revision row is copied unchanged.
    fn migrate_root_key(
        &mut self,
        shared_key: &SecretKey,
        password_key: &SecretKey,
    ) -> Result<SecretKey> {
        let vault_id = self.header.vault_id;
        let root_key = Zeroizing::new(random_array::<KEY_LEN>());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = transaction.query_row(
            "SELECT format_version FROM vault_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version != SHARED_KEY_FORMAT_VERSION {
            // Another process re-rooted the vault after this one read its
            // header, so the key just unwrapped is not the root. Unlocking
            // again reads the new header.
            drop(transaction);
            self.header = read_header(&self.connection)?;
            return Err(Error::Locked);
        }
        let device = self.header.device.clone().ok_or(Error::Crypto)?;
        let device_aad = device_key_aad(&vault_id, &device.device_id, &device.public_key);
        let seed = decrypt(
            shared_key,
            &device.key_nonce,
            &device_aad,
            &device.wrapped_signing_key,
        )
        .map_err(|_| Error::Crypto)?;
        let key_nonce = random_array::<NONCE_LEN>();
        let wrapped_signing_key = encrypt(&root_key, &key_nonce, &device_aad, &seed)?;
        let password = wrap_with(password_key, &vault_id, b"password", &root_key)?;
        let mut header = self.header.clone();
        header.format_version = MEMBERSHIP_FORMAT_VERSION;
        header.password_nonce = password.nonce;
        header.password_wrapped_key = password.wrapped_key;
        header.legacy_recovery = header.recovery.take();
        header.recovery_check = None;
        header.current_epoch = FIRST_EPOCH;
        header.device = Some(DeviceHeader {
            key_nonce,
            wrapped_signing_key,
            ..device
        });

        let devices = load_devices(&transaction, shared_key, &vault_id)?;
        transaction.execute_batch("DROP TRIGGER devices_no_update;")?;
        for (device_id, key) in &devices {
            let authorization =
                device_authorization(&root_key, &vault_id, device_id, &key.to_bytes())?;
            transaction.execute(
                "UPDATE devices SET authorization=? WHERE device_id=?",
                params![authorization.as_slice(), device_id.as_slice()],
            )?;
        }
        transaction.execute_batch(DEVICES_TRIGGER)?;
        transaction.execute_batch(REVOCATIONS_SCHEMA)?;
        transaction.execute_batch(EPOCH_KEYS_SCHEMA)?;
        store_epoch_key(&transaction, &root_key, &vault_id, FIRST_EPOCH, shared_key)?;
        transaction.execute_batch(SET_ASIDE_RECORD_TABLES)?;
        transaction.execute_batch(RECORD_SCHEMA)?;
        transaction.execute_batch(QUARANTINE_SCHEMA)?;
        transaction.execute_batch(INGRESS_SCHEMA)?;
        transaction.execute_batch(COPY_RECORD_TABLES)?;
        transaction.execute_batch("DROP TABLE vault_meta;")?;
        transaction.execute_batch(VAULT_META_TABLE)?;
        insert_header(&transaction, &header)?;
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(root_key)
    }

    /// Writes a vault in the format 5 layout, where one shared key wraps
    /// everything and encrypts records as epoch 1, with `items` as its
    /// revisions (an item repeated is an edit). For testing re-rooting.
    #[cfg(test)]
    pub(crate) fn create_format5(
        path: &Path,
        password: &str,
        items: &[Item],
    ) -> Result<RecoveryKey> {
        drop(OpenOptions::new().write(true).create_new(true).open(path)?);
        let connection = open_connection(path)?;
        create_schema(&connection)?;
        let vault_id = random_array::<32>();
        let shared_key = Zeroizing::new(random_array::<KEY_LEN>());
        let recovery = RecoveryKey::generate();
        let kdf = KdfConfig::default();
        let password_salt = random_array::<SALT_LEN>();
        let password = wrap_with_password(password, &password_salt, kdf, &vault_id, &shared_key)?;
        let (device, signing_key) =
            generate_device(&shared_key, &vault_id, SHARED_KEY_FORMAT_VERSION)?;
        let header = Header {
            format_version: SHARED_KEY_FORMAT_VERSION,
            vault_id,
            kdf,
            password_salt,
            password_nonce: password.nonce,
            password_wrapped_key: password.wrapped_key,
            recovery: Some(wrap_with_recovery(&recovery, &vault_id, &shared_key)?),
            recovery_check: None,
            legacy_recovery: None,
            current_epoch: FIRST_EPOCH,
            device: Some(device),
            recipient: None,
            write_fence: FIRST_EPOCH,
            rows_changed: false,
        };
        insert_header(&connection, &header)?;
        let record = header.device_record()?;
        insert_device_authorization(&connection, &shared_key, &header, &record)?;
        let signer = RevisionSigner {
            key: &shared_key,
            epoch: FIRST_EPOCH,
            signing_key: &signing_key,
            vault_id,
            author: record.device_id,
        };
        for item in items {
            let parents = head_ids(&connection, &item.id)?;
            let revision =
                signer.seal(&item.id, parents.clone(), false, &serde_json::to_vec(item)?)?;
            let id = revision.revision_id();
            insert_revision(&connection, "revisions", &revision, &id)?;
            for parent in &parents {
                connection.execute("DELETE FROM heads WHERE revision=?", [parent])?;
            }
            connection.execute(
                "INSERT INTO heads(revision,item_id,tombstone) VALUES(?,?,0)",
                params![id, item.id],
            )?;
        }
        Ok(recovery)
    }

    #[cfg(test)]
    pub(crate) fn root_key_for_tests(&self) -> SecretKey {
        self.root_key.clone().expect("unlocked")
    }

    /// IDs of every accepted revision in insertion order, so parents always
    /// precede children. Works while locked: IDs are public metadata.
    pub fn revision_ids(&self) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT revision FROM revisions ORDER BY rowid")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// The accepted revisions among `ids`, parents first. Unknown IDs are
    /// skipped. Works while locked: revisions are already encrypted and
    /// signed, so a locked device can still send them.
    pub fn revisions_by_id(&self, ids: &[String]) -> Result<Vec<EncryptedRevision>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT r.rowid,{REVISION_COLUMNS} FROM revisions r WHERE r.revision=?"
        ))?;
        let mut found = Vec::new();
        for id in ids {
            let row = statement
                .query_row([id], |row| {
                    let rowid: i64 = row.get(0)?;
                    let revision = row_to_revision_at(row, 1)?;
                    Ok((rowid, revision))
                })
                .optional()?;
            found.extend(row);
        }
        found.sort_by_key(|(rowid, _)| *rowid);
        found.dedup_by_key(|(rowid, _)| *rowid);
        Ok(found.into_iter().map(|(_, revision)| revision).collect())
    }
}

impl Vault {
    /// Durably stores a received revision for later processing. Works while
    /// locked: only the envelope's shape is checked, and nothing is
    /// decrypted or verified until [`Vault::process_staged`].
    pub fn stage_revision(&mut self, revision: EncryptedRevision) -> Result<StageOutcome> {
        // The ingress queue exists from format 5 on (a format 4 vault gains
        // it when opened); older layouts gain it on unlock. Staging needs no
        // key, so a format 5 vault receives before it is re-rooted.
        if self.header.format_version < SHARED_KEY_FORMAT_VERSION {
            return Err(Error::Locked);
        }
        revision.validate_shape(&self.header.vault_id)?;
        let id = revision.revision_id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: i64 = transaction.query_row(
            "SELECT (SELECT COUNT(*) FROM revisions WHERE revision=?1)
                  + (SELECT COUNT(*) FROM ingress WHERE revision=?1)
                  + (SELECT COUNT(*) FROM quarantine WHERE revision=?1)",
            [&id],
            |row| row.get(0),
        )?;
        if known > 0 {
            return Ok(StageOutcome::Duplicate);
        }
        let (count, bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(ciphertext)), 0) FROM ingress",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count >= MAX_INGRESS || bytes + revision.ciphertext.len() as i64 > MAX_INGRESS_BYTES {
            return Err(Error::IngressFull);
        }
        insert_revision(&transaction, "ingress", &revision, &id)?;
        transaction.commit()?;
        Ok(StageOutcome::Staged)
    }

    /// IDs of staged revisions in arrival order. Works while locked.
    pub fn staged_revision_ids(&self) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT revision FROM ingress ORDER BY rowid")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Parents named by staged revisions that are neither accepted nor
    /// staged, so a sync peer can be asked for them. Works while locked.
    pub fn staged_missing_parents(&self) -> Result<Vec<String>> {
        let known: BTreeSet<String> = self
            .revision_ids()?
            .into_iter()
            .chain(self.staged_revision_ids()?)
            .collect();
        let missing: BTreeSet<String> = staged_revisions(&self.connection)?
            .into_iter()
            .flat_map(|revision| revision.parents)
            .filter(|parent| !known.contains(parent))
            .collect();
        Ok(missing.into_iter().collect())
    }

    /// Verifies and applies staged revisions in arrival order, repeating
    /// while any progress is made. Each accepted or quarantined revision
    /// leaves the queue in the same transaction that stores it. A revision
    /// that fails verification is discarded; one still missing a parent
    /// stays staged. Storage failures stop processing and leave the queue
    /// and the vault as they were for that revision.
    pub fn process_staged(&mut self) -> Result<IngressReport> {
        self.key()?;
        let mut report = IngressReport::default();
        loop {
            let mut progressed = false;
            for revision in staged_revisions(&self.connection)? {
                let id = revision.revision_id();
                match self.apply_encrypted_revision(revision) {
                    Ok(_) => report.applied += 1,
                    Err(Error::Quarantined) => report.quarantined += 1,
                    // Wait for the parent, or for this device to receive
                    // the epoch's key.
                    Err(Error::MissingParent | Error::MissingEpochKey) => continue,
                    Err(error) if is_rejection(&error) => {
                        self.connection
                            .execute("DELETE FROM ingress WHERE revision=?", [&id])?;
                        report.rejected += 1;
                        report.first_rejection.get_or_insert(error);
                    }
                    Err(error) => return Err(error),
                }
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        report.pending = self.staged_revision_ids()?.len();
        Ok(report)
    }
}

/// Errors that prove a revision itself is invalid, as opposed to a storage
/// or state failure that must not discard it.
fn is_rejection(error: &Error) -> bool {
    matches!(
        error,
        Error::Crypto
            | Error::InvalidSignature
            | Error::InvalidParent
            | Error::InvalidItem(_)
            | Error::UnsupportedVersion(_)
            | Error::Serialization(_)
    )
}

fn staged_revisions(connection: &Connection) -> Result<Vec<EncryptedRevision>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {REVISION_COLUMNS} FROM ingress r ORDER BY r.rowid"
    ))?;
    let staged = statement
        .query_map([], row_to_revision)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(staged)
}
