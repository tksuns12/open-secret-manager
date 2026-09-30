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
use zeroize::Zeroizing;

use crate::{
    crypto::{
        decrypt, derive_password_key, device_authorization, device_key_aad, encrypt, key_wrap_aad,
        legacy_record_aad, legacy_revision_id, random_array, record_aad, revision_id,
        revision_signature_message, verify_device_authorization, KdfConfig, SecretKey,
        DEVICE_ID_LEN, KEY_LEN, NONCE_LEN, PUBLIC_KEY_LEN, SALT_LEN, SIGNATURE_LEN,
    },
    Error, Item, ItemSummary, ItemVersion, QuarantinedRevision, RecoveryKey, Result, RevisionInfo,
    VaultItem,
};

/// Storage layout: multi-head revisions plus a quarantine for revisions
/// from unauthorized devices.
const VAULT_FORMAT_VERSION: u32 = 4;
/// Multi-head layout without a quarantine table; migrated on first unlock.
const MULTI_HEAD_FORMAT_VERSION: u32 = 3;
/// Signed revisions with one head per item; migrated by SQL on first unlock.
const SINGLE_HEAD_FORMAT_VERSION: u32 = 2;
/// Unsigned revisions without an author; migrated on first unlock.
const LEGACY_FORMAT_VERSION: u32 = 1;
/// Signed revision envelope. Unchanged by the multi-head layout because a
/// single parent encodes identically.
const RECORD_FORMAT_VERSION: u32 = 2;
const BACKUP_FORMAT_VERSION: u32 = 3;
/// Upper bound on heads one revision may supersede.
const MAX_PARENTS: usize = 16;
/// Upper bound on held revisions awaiting owner review.
const MAX_QUARANTINE: i64 = 10_000;
const KEY_EPOCH: u64 = 1;
const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ITEM_BYTES: usize = 16 * 1024 * 1024;

const META_SCHEMA: &str = r#"
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
    recovery_nonce BLOB NOT NULL CHECK(length(recovery_nonce) = 24),
    recovery_wrapped_key BLOB NOT NULL CHECK(length(recovery_wrapped_key) = 48),
    device_id BLOB NOT NULL CHECK(length(device_id) = 16),
    device_public_key BLOB NOT NULL CHECK(length(device_public_key) = 32),
    device_key_nonce BLOB NOT NULL CHECK(length(device_key_nonce) = 24),
    device_wrapped_signing_key BLOB NOT NULL CHECK(length(device_wrapped_signing_key) = 48)
) STRICT;
CREATE TABLE devices (
    device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
    public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
    authorization BLOB NOT NULL CHECK(length(authorization) = 32)
) STRICT;
CREATE TRIGGER devices_no_update BEFORE UPDATE ON devices
BEGIN SELECT RAISE(ABORT, 'device authorizations are immutable'); END;
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
    key_epoch INTEGER NOT NULL CHECK(key_epoch = 1),
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
    key_epoch INTEGER NOT NULL CHECK(key_epoch = 1),
    author_device_id BLOB NOT NULL CHECK(length(author_device_id) = 16),
    nonce BLOB NOT NULL CHECK(length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 16777232),
    tombstone INTEGER NOT NULL CHECK(tombstone IN (0, 1)),
    signature BLOB NOT NULL CHECK(length(signature) = 64)
) STRICT;
CREATE TRIGGER quarantine_no_update BEFORE UPDATE ON quarantine
BEGIN SELECT RAISE(ABORT, 'quarantined revisions are immutable'); END;
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
        if self.key_epoch != KEY_EPOCH {
            return Err(Error::UnsupportedVersion(self.key_epoch as u32));
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
    recovery_nonce: [u8; NONCE_LEN],
    recovery_wrapped_key: Vec<u8>,
    /// `None` only for a format 1 vault that has not been unlocked yet.
    device: Option<DeviceHeader>,
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
    master_key: Option<SecretKey>,
    signing_key: Option<SigningKey>,
    /// Authorized revision authors, loaded and authenticated at unlock.
    devices: BTreeMap<[u8; DEVICE_ID_LEN], VerifyingKey>,
}

/// Seals revisions for one author. Borrowing the keys separately from the
/// connection lets callers seal while holding a write transaction.
struct RevisionSigner<'a> {
    key: &'a SecretKey,
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
            KEY_EPOCH,
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
            key_epoch: KEY_EPOCH,
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
            .field("unlocked", &self.master_key.is_some())
            .finish()
    }
}

impl Vault {
    pub fn create(path: impl AsRef<Path>, password: &str) -> Result<(Self, RecoveryKey)> {
        let path = path.as_ref();
        let placeholder = OpenOptions::new().write(true).create_new(true).open(path)?;
        drop(placeholder);

        let result = Self::initialize_created(path, password);
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn initialize_created(path: &Path, password: &str) -> Result<(Self, RecoveryKey)> {
        let connection = open_connection(path)?;
        create_schema(&connection)?;
        let vault_id = random_array::<32>();
        let master_key = Zeroizing::new(random_array::<KEY_LEN>());
        let password_salt = random_array::<SALT_LEN>();
        let password_nonce = random_array::<NONCE_LEN>();
        let recovery_nonce = random_array::<NONCE_LEN>();
        let kdf = KdfConfig::default();
        let password_key = derive_password_key(password, &password_salt, kdf)?;
        let recovery = RecoveryKey::generate();
        let password_wrapped_key = encrypt(
            &password_key,
            &password_nonce,
            &key_wrap_aad(&vault_id, b"password"),
            master_key.as_ref(),
        )?;
        let recovery_wrapped_key = encrypt(
            recovery.expose(),
            &recovery_nonce,
            &key_wrap_aad(&vault_id, b"recovery"),
            master_key.as_ref(),
        )?;
        let (device, _) = generate_device(&master_key, &vault_id)?;
        let header = Header {
            format_version: VAULT_FORMAT_VERSION,
            vault_id,
            kdf,
            password_salt,
            password_nonce,
            password_wrapped_key,
            recovery_nonce,
            recovery_wrapped_key,
            device: Some(device),
        };
        insert_header(&connection, &header)?;
        insert_device_authorization(&connection, &master_key, &header, &header.device_record()?)?;
        let header = read_header(&connection)?;
        let mut vault = Self::from_parts(path, connection, header);
        vault.activate(master_key)?;
        Ok((vault, recovery))
    }

    fn from_parts(path: &Path, connection: Connection, header: Header) -> Self {
        Self {
            path: path.to_path_buf(),
            connection,
            header,
            master_key: None,
            signing_key: None,
            devices: BTreeMap::new(),
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let connection = open_connection(path)?;
        let header = read_header(&connection)?;
        Ok(Self::from_parts(path, connection, header))
    }

    pub fn vault_id(&self) -> [u8; 32] {
        self.header.vault_id
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
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
        let master = decrypt(
            &wrapping_key,
            &self.header.password_nonce,
            &key_wrap_aad(&self.header.vault_id, b"password"),
            &self.header.password_wrapped_key,
        )
        .map_err(|_| Error::InvalidCredentials)?;
        self.activate(to_key(&master)?)
    }

    pub fn unlock_with_recovery(&mut self, recovery: &RecoveryKey) -> Result<()> {
        if self.is_unlocked() {
            return Err(Error::AlreadyUnlocked);
        }
        let master = decrypt(
            recovery.expose(),
            &self.header.recovery_nonce,
            &key_wrap_aad(&self.header.vault_id, b"recovery"),
            &self.header.recovery_wrapped_key,
        )
        .map_err(|_| Error::InvalidCredentials)?;
        self.activate(to_key(&master)?)
    }

    pub fn lock(&mut self) {
        self.master_key = None;
        self.signing_key = None;
        self.devices.clear();
    }

    /// Completes an unlock: migrates an older vault, then loads the device
    /// signing key and the authenticated author set. The vault stays locked
    /// if any step fails.
    fn activate(&mut self, master_key: SecretKey) -> Result<()> {
        if self.header.format_version == LEGACY_FORMAT_VERSION {
            self.migrate_legacy(&master_key)?;
        }
        if self.header.format_version == SINGLE_HEAD_FORMAT_VERSION {
            self.migrate_single_head()?;
        }
        if self.header.format_version == MULTI_HEAD_FORMAT_VERSION {
            self.migrate_add_quarantine()?;
        }
        let device = self.header.device.as_ref().ok_or(Error::Crypto)?;
        let seed = decrypt(
            &master_key,
            &device.key_nonce,
            &device_key_aad(&self.header.vault_id, &device.device_id, &device.public_key),
            &device.wrapped_signing_key,
        )
        .map_err(|_| Error::Crypto)?;
        let seed = Zeroizing::new(array::<32>(&seed)?);
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().to_bytes() != device.public_key {
            return Err(Error::Crypto);
        }
        let devices = load_devices(&self.connection, &master_key, &self.header.vault_id)?;
        if devices.get(&device.device_id).map(VerifyingKey::to_bytes) != Some(device.public_key) {
            return Err(Error::Crypto);
        }
        self.master_key = Some(master_key);
        self.signing_key = Some(signing_key);
        self.devices = devices;
        Ok(())
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
            let (device, signing_key) = generate_device(master_key, &vault_id)?;
            let mut header = self.header.clone();
            header.format_version = VAULT_FORMAT_VERSION;
            header.device = Some(device);

            transaction
                .execute_batch("DROP TABLE heads; DROP TABLE revisions; DROP TABLE vault_meta;")?;
            create_schema(&transaction)?;
            insert_header(&transaction, &header)?;
            let record = header.device_record()?;
            insert_device_authorization(&transaction, master_key, &header, &record)?;

            let signer = RevisionSigner {
                key: master_key,
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
                [VAULT_FORMAT_VERSION],
            )?;
        }
        transaction.commit()?;
        self.header = read_header(&self.connection)?;
        Ok(())
    }

    fn signer(&self) -> Result<RevisionSigner<'_>> {
        Ok(RevisionSigner {
            key: self.key()?,
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
        decrypt(
            self.key()?,
            &revision.nonce,
            &revision.aad(),
            &revision.ciphertext,
        )
        .map_err(|_| Error::Crypto)
    }

    fn open_item(&self, revision: &EncryptedRevision) -> Result<Item> {
        let plaintext = self.open_revision(revision)?;
        serde_json::from_slice(&plaintext).map_err(|_| Error::Crypto)
    }

    /// Adds another device's signing key to the authorized author set.
    /// Enrollment must eventually go through committed membership; until
    /// then this is only reachable from tests.
    #[cfg(test)]
    pub(crate) fn authorize_device(
        &mut self,
        device_id: [u8; DEVICE_ID_LEN],
        public_key: [u8; PUBLIC_KEY_LEN],
    ) -> Result<()> {
        let key = self.key()?.clone();
        let verifying = VerifyingKey::from_bytes(&public_key).map_err(|_| Error::Crypto)?;
        insert_device_authorization(
            &self.connection,
            &key,
            &self.header,
            &DeviceRecord {
                device_id,
                public_key,
            },
        )?;
        self.devices.insert(device_id, verifying);
        Ok(())
    }

    pub fn change_password(&mut self, current_password: &str, new_password: &str) -> Result<()> {
        let master = self.key()?.clone();
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

        let salt = random_array::<SALT_LEN>();
        let nonce = random_array::<NONCE_LEN>();
        let wrapping_key = derive_password_key(new_password, &salt, self.header.kdf)?;
        let wrapped = encrypt(
            &wrapping_key,
            &nonce,
            &key_wrap_aad(&self.header.vault_id, b"password"),
            master.as_ref(),
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

    pub fn list(&self) -> Result<Vec<ItemSummary>> {
        self.key()?;
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT item_id FROM heads WHERE tombstone=0 ORDER BY item_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        ids.iter().map(|id| self.get(id).map(Into::into)).collect()
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
        let mut ids = BTreeSet::new();
        for item in &items {
            item.validate()?;
            if serde_json::to_vec(item)?.len() > MAX_ITEM_BYTES {
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
                    let plaintext = Zeroizing::new(serde_json::to_vec(item)?);
                    signer.seal(&item.id, Vec::new(), false, &plaintext)
                })
                .collect::<Result<Vec<_>>>()?
        };
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
        transaction.commit()?;
        Ok(revisions)
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
        let plaintext = if tombstone {
            Zeroizing::new(Vec::new())
        } else {
            Zeroizing::new(serde_json::to_vec(&item)?)
        };
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

    pub fn export_backup(&self, path: impl AsRef<Path>) -> Result<()> {
        let key = self.key()?;
        let payload = BackupPayload {
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
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
        if plaintext.len() as u64 > MAX_BACKUP_BYTES {
            return Err(Error::InvalidBackup("backup is too large".into()));
        }
        let nonce = random_array::<NONCE_LEN>();
        let recovery_nonce = encode(&self.header.recovery_nonce);
        let recovery_wrapped_key = encode(&self.header.recovery_wrapped_key);
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
        let path = path.as_ref();
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error.into());
        }
        Ok(())
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
        let master_plaintext = decrypt(
            recovery.expose(),
            &recovery_nonce,
            &key_wrap_aad(&vault_id, b"recovery"),
            &recovery_wrapped_key,
        )
        .map_err(|_| Error::InvalidCredentials)?;
        let master_key = to_key(&master_plaintext)?;
        let nonce = decode_array::<NONCE_LEN>(&envelope.nonce)?;
        let ciphertext = decode(&envelope.ciphertext)?;
        let aad = backup_aad(
            &vault_id,
            &envelope.recovery_nonce,
            &envelope.recovery_wrapped_key,
        );
        let plaintext = decrypt(&master_key, &nonce, &aad, &ciphertext)
            .map_err(|_| Error::InvalidBackup("authentication failed".into()))?;
        let payload: BackupPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| Error::InvalidBackup("invalid payload".into()))?;
        if payload.revisions.len() > 1_000_000
            || payload.devices.len() > 10_000
            || payload.quarantine.len() as i64 > MAX_QUARANTINE
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

        let vault_path = vault_path.as_ref();
        let placeholder = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(vault_path)?;
        drop(placeholder);
        let result = Self::initialize_restored(
            vault_path,
            new_password,
            vault_id,
            master_key,
            recovery_nonce,
            recovery_wrapped_key,
            payload,
        );
        if result.is_err() {
            let _ = std::fs::remove_file(vault_path);
        }
        result
    }

    fn initialize_restored(
        path: &Path,
        password: &str,
        vault_id: [u8; 32],
        master_key: SecretKey,
        recovery_nonce: [u8; NONCE_LEN],
        recovery_wrapped_key: Vec<u8>,
        payload: BackupPayload,
    ) -> Result<Self> {
        let connection = open_connection(path)?;
        create_schema(&connection)?;
        let kdf = KdfConfig::default();
        let password_salt = random_array::<SALT_LEN>();
        let password_nonce = random_array::<NONCE_LEN>();
        let wrapping_key = derive_password_key(password, &password_salt, kdf)?;
        let password_wrapped_key = encrypt(
            &wrapping_key,
            &password_nonce,
            &key_wrap_aad(&vault_id, b"password"),
            master_key.as_ref(),
        )?;
        // A restored vault is a new writer: it gets a fresh signing identity
        // and never reuses the source device's key. The source authors stay
        // authorized so their revisions in the backup still verify.
        let (device, _) = generate_device(&master_key, &vault_id)?;
        let header = Header {
            format_version: VAULT_FORMAT_VERSION,
            vault_id,
            kdf,
            password_salt,
            password_nonce,
            password_wrapped_key,
            recovery_nonce,
            recovery_wrapped_key,
            device: Some(device),
        };
        insert_header(&connection, &header)?;
        insert_device_authorization(&connection, &master_key, &header, &header.device_record()?)?;
        for record in &payload.devices {
            insert_device_authorization(&connection, &master_key, &header, record)?;
        }
        let header = read_header(&connection)?;
        let mut vault = Self::from_parts(path, connection, header);
        vault.activate(master_key)?;
        // Revisions are exported in insertion order, so parents precede
        // children and the head set is rebuilt exactly.
        for revision in payload.revisions {
            vault.apply_encrypted_revision(revision)?;
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
    /// A revision whose author is not an authorized device is held in the
    /// quarantine and `Quarantined` is returned: it is not merged. Only a
    /// well-formed revision that decrypts with the vault key is held.
    pub fn apply_encrypted_revision(
        &mut self,
        revision: EncryptedRevision,
    ) -> Result<RevisionInfo> {
        self.key()?;
        revision.validate_shape(&self.header.vault_id)?;
        if !self.devices.contains_key(&revision.author_device_id) {
            self.quarantine(revision)?;
            return Err(Error::Quarantined);
        }
        self.commit_revision(revision, None, None)
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
                    parents: revision.parents.clone(),
                    item,
                })
            })
            .collect()
    }

    /// Accepts a held revision by re-authoring its content as this device
    /// against the same parents; the unauthorized signature is never
    /// trusted. The result may be a concurrent head to resolve. The held
    /// entry is released in the same transaction; on `MissingParent` it
    /// stays held.
    pub fn accept_quarantined(&mut self, revision_id: &str) -> Result<RevisionInfo> {
        self.key()?;
        let held = quarantined_by_id(&self.connection, revision_id)?.ok_or(Error::NotFound)?;
        let plaintext = self.decrypt_unverified(&held)?;
        let revision = self.signer()?.seal(
            &held.item_id,
            held.parents.clone(),
            held.tombstone,
            &plaintext,
        )?;
        self.commit_revision(revision, None, Some(revision_id))
    }

    /// Drops a held revision. If the same revision is received again it is
    /// held again rather than silently ignored.
    pub fn discard_quarantined(&mut self, revision_id: &str) -> Result<()> {
        self.key()?;
        let removed = self
            .connection
            .execute("DELETE FROM quarantine WHERE revision=?", [revision_id])?;
        if removed == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
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
        revision.validate_shape(&self.header.vault_id)?;
        if !revision.tombstone {
            let item = self.open_item(&revision)?;
            item.validate()?;
            if item.id != revision.item_id {
                return Err(Error::Crypto);
            }
        } else {
            self.open_revision(&revision)?;
        }

        let id = revision.revision_id();
        let info = RevisionInfo {
            item_id: revision.item_id.clone(),
            revision: id.clone(),
            parents: revision.parents.clone(),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(stored) = revision_by_id(&transaction, &id)? {
            if stored != revision {
                return Err(Error::Crypto);
            }
            return Ok(info);
        }
        for parent in &revision.parents {
            match revision_by_id(&transaction, parent)? {
                None => return Err(Error::MissingParent),
                Some(stored) if stored.item_id != revision.item_id => {
                    return Err(Error::InvalidParent)
                }
                Some(_) => {}
            }
        }
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
        // Parents always arrive before children, so a new revision is never
        // an ancestor of a stored one. Removing only the named parents keeps
        // every concurrent head.
        for parent in &revision.parents {
            transaction.execute("DELETE FROM heads WHERE revision=?", [parent])?;
        }
        transaction.execute(
            "INSERT INTO heads(revision,item_id,tombstone) VALUES(?,?,?)",
            params![id, revision.item_id, revision.tombstone],
        )?;
        transaction.commit()?;
        Ok(info)
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

fn is_revision_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(META_SCHEMA)?;
    connection.execute_batch(RECORD_SCHEMA)?;
    connection.execute_batch(QUARANTINE_SCHEMA)?;
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

impl Vault {
    fn key(&self) -> Result<&SecretKey> {
        self.master_key.as_ref().ok_or(Error::Locked)
    }
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    devices: Vec<DeviceRecord>,
    revisions: Vec<EncryptedRevision>,
    /// Held revisions, so pending owner review survives a restore.
    #[serde(default)]
    quarantine: Vec<EncryptedRevision>,
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

fn backup_aad(vault_id: &[u8; 32], recovery_nonce: &str, recovery_wrapped_key: &str) -> Vec<u8> {
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
            | VAULT_FORMAT_VERSION
    ) {
        return Err(Error::UnsupportedVersion(version));
    }
    let device_columns = if version != LEGACY_FORMAT_VERSION {
        "device_id,device_public_key,device_key_nonce,device_wrapped_signing_key"
    } else {
        "NULL,NULL,NULL,NULL"
    };
    let row = connection.query_row(
        &format!(
            "SELECT vault_id,kdf_memory_kib,kdf_iterations,kdf_parallelism,password_salt,\
             password_nonce,password_wrapped_key,recovery_nonce,recovery_wrapped_key,{device_columns} \
             FROM vault_meta WHERE singleton=1"
        ),
        [],
        |row| Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, u32>(1)?, row.get::<_, u32>(2)?, row.get::<_, u32>(3)?,
            row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?, row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?, row.get::<_, Vec<u8>>(8)?,
            row.get::<_, Option<Vec<u8>>>(9)?, row.get::<_, Option<Vec<u8>>>(10)?,
            row.get::<_, Option<Vec<u8>>>(11)?, row.get::<_, Option<Vec<u8>>>(12)?,
        )),
    )?;
    let device = match (row.9, row.10, row.11, row.12) {
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
    Ok(Header {
        format_version: version,
        vault_id: array(&row.0)?,
        kdf: KdfConfig {
            memory_kib: row.1,
            iterations: row.2,
            parallelism: row.3,
        },
        password_salt: array(&row.4)?,
        password_nonce: array(&row.5)?,
        password_wrapped_key: row.6,
        recovery_nonce: array(&row.7)?,
        recovery_wrapped_key: row.8,
        device,
    })
}

fn insert_header(connection: &Connection, header: &Header) -> Result<()> {
    let device = header.device.as_ref().ok_or(Error::Crypto)?;
    connection.execute(
        "INSERT INTO vault_meta(singleton,format_version,vault_id,kdf_memory_kib,kdf_iterations,\
         kdf_parallelism,password_salt,password_nonce,password_wrapped_key,recovery_nonce,\
         recovery_wrapped_key,device_id,device_public_key,device_key_nonce,device_wrapped_signing_key) \
         VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            header.format_version,
            header.vault_id.as_slice(),
            header.kdf.memory_kib,
            header.kdf.iterations,
            header.kdf.parallelism,
            header.password_salt.as_slice(),
            header.password_nonce.as_slice(),
            header.password_wrapped_key,
            header.recovery_nonce.as_slice(),
            header.recovery_wrapped_key,
            device.device_id.as_slice(),
            device.public_key.as_slice(),
            device.key_nonce.as_slice(),
            device.wrapped_signing_key,
        ],
    )?;
    Ok(())
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

/// Creates a random device identity whose signing key is wrapped by the
/// vault master key.
fn generate_device(
    master_key: &SecretKey,
    vault_id: &[u8; 32],
) -> Result<(DeviceHeader, SigningKey)> {
    let seed = Zeroizing::new(random_array::<32>());
    let signing_key = SigningKey::from_bytes(&seed);
    let device_id = random_array::<DEVICE_ID_LEN>();
    let public_key = signing_key.verifying_key().to_bytes();
    let key_nonce = random_array::<NONCE_LEN>();
    let wrapped_signing_key = encrypt(
        master_key,
        &key_nonce,
        &device_key_aad(vault_id, &device_id, &public_key),
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
                || legacy.key_epoch != KEY_EPOCH
            {
                return Err(Error::Crypto);
            }
            legacy.revision = revision;
            Ok(legacy)
        })
        .collect()
}

fn row_to_revision(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedRevision> {
    let vault_id: Vec<u8> = row.get(1)?;
    let author_device_id: Vec<u8> = row.get(5)?;
    let nonce: Vec<u8> = row.get(6)?;
    Ok(EncryptedRevision {
        format_version: row.get(0)?,
        vault_id: vault_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        item_id: row.get(2)?,
        parents: split_parents(&row.get::<_, String>(3)?).ok_or(rusqlite::Error::InvalidQuery)?,
        key_epoch: u64::try_from(row.get::<_, i64>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        author_device_id: author_device_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        nonce: nonce
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ciphertext: row.get(7)?,
        tombstone: row.get(8)?,
        signature: row.get(9)?,
    })
}

fn split_parents(joined: &str) -> Option<Vec<String>> {
    let chunks = joined.as_bytes().chunks_exact(64);
    if !chunks.remainder().is_empty() || !joined.is_ascii() {
        return None;
    }
    Some(
        chunks
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
