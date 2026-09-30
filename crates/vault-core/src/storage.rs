use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        decrypt, derive_password_key, encrypt, key_wrap_aad, random_array, record_aad, revision_id,
        KdfConfig, SecretKey, KEY_LEN, NONCE_LEN, SALT_LEN,
    },
    Error, Item, ItemSummary, RecoveryKey, Result, RevisionInfo, VaultItem,
};

const FORMAT_VERSION: u32 = 1;
const KEY_EPOCH: u64 = 1;
const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ITEM_BYTES: usize = 16 * 1024 * 1024;

const SCHEMA: &str = r#"
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
    recovery_wrapped_key BLOB NOT NULL CHECK(length(recovery_wrapped_key) = 48)
) STRICT;
CREATE TABLE revisions (
    revision TEXT PRIMARY KEY CHECK(length(revision) = 64),
    format_version INTEGER NOT NULL CHECK(format_version = 1),
    vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
    item_id TEXT NOT NULL CHECK(length(item_id) BETWEEN 1 AND 128),
    parent_revision TEXT CHECK(parent_revision IS NULL OR length(parent_revision) = 64),
    key_epoch INTEGER NOT NULL CHECK(key_epoch = 1),
    nonce BLOB NOT NULL CHECK(length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 16777232),
    tombstone INTEGER NOT NULL CHECK(tombstone IN (0, 1))
) STRICT;
CREATE INDEX revisions_item_id ON revisions(item_id);
CREATE TRIGGER revisions_no_update BEFORE UPDATE ON revisions
BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
CREATE TRIGGER revisions_no_delete BEFORE DELETE ON revisions
BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
CREATE TABLE heads (
    item_id TEXT PRIMARY KEY CHECK(length(item_id) BETWEEN 1 AND 128),
    revision TEXT NOT NULL REFERENCES revisions(revision),
    tombstone INTEGER NOT NULL CHECK(tombstone IN (0, 1))
) STRICT;
"#;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedRevision {
    pub format_version: u32,
    pub vault_id: [u8; 32],
    pub item_id: String,
    pub parent_revision: Option<String>,
    pub key_epoch: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub tombstone: bool,
}

impl std::fmt::Debug for EncryptedRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedRevision")
            .field("format_version", &self.format_version)
            .field("vault_id", &"[REDACTED]")
            .field("item_id", &self.item_id)
            .field("parent_revision", &self.parent_revision)
            .field("key_epoch", &self.key_epoch)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("tombstone", &self.tombstone)
            .finish()
    }
}

impl EncryptedRevision {
    pub fn revision_id(&self) -> String {
        let aad = record_aad(
            &self.vault_id,
            &self.item_id,
            self.parent_revision.as_deref(),
            self.key_epoch,
            self.tombstone,
        );
        revision_id(&aad, &self.nonce, &self.ciphertext)
    }

    fn validate_shape(&self, expected_vault_id: &[u8; 32]) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(self.format_version));
        }
        if &self.vault_id != expected_vault_id
            || self.item_id.is_empty()
            || self.item_id.len() > 128
            || self.ciphertext.len() < 16
            || self.ciphertext.len() > MAX_ITEM_BYTES + 16
            || self.parent_revision.as_ref().is_some_and(|parent| {
                parent.len() != 64
                    || !parent
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
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
    vault_id: [u8; 32],
    kdf: KdfConfig,
    password_salt: [u8; SALT_LEN],
    password_nonce: [u8; NONCE_LEN],
    password_wrapped_key: Vec<u8>,
    recovery_nonce: [u8; NONCE_LEN],
    recovery_wrapped_key: Vec<u8>,
}

pub struct Vault {
    path: PathBuf,
    connection: Connection,
    header: Header,
    master_key: Option<SecretKey>,
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
        connection.execute_batch(SCHEMA)?;
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
        connection.execute(
            "INSERT INTO vault_meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                FORMAT_VERSION,
                vault_id.as_slice(),
                kdf.memory_kib,
                kdf.iterations,
                kdf.parallelism,
                password_salt.as_slice(),
                password_nonce.as_slice(),
                password_wrapped_key,
                recovery_nonce.as_slice(),
                recovery_wrapped_key,
            ],
        )?;
        let header = read_header(&connection)?;
        Ok((
            Self {
                path: path.to_path_buf(),
                connection,
                header,
                master_key: Some(master_key),
            },
            recovery,
        ))
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let connection = open_connection(path)?;
        let header = read_header(&connection)?;
        Ok(Self {
            path: path.to_path_buf(),
            connection,
            header,
            master_key: None,
        })
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
        self.master_key = Some(to_key(&master)?);
        Ok(())
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
        self.master_key = Some(to_key(&master)?);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.master_key = None;
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

    pub fn get(&self, item_id: &str) -> Result<VaultItem> {
        let key = self.key()?;
        let revision = self.head_revision(item_id)?.ok_or(Error::NotFound)?;
        if revision.tombstone {
            return Err(Error::NotFound);
        }
        let item = decrypt_item(key, &revision)?;
        Ok(VaultItem {
            item,
            revision: revision.revision_id(),
        })
    }

    pub fn list(&self) -> Result<Vec<ItemSummary>> {
        self.key()?;
        let mut statement = self
            .connection
            .prepare("SELECT item_id FROM heads WHERE tombstone=0 ORDER BY item_id")?;
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
        if self.head_revision(&item.id)?.is_some() {
            return Err(Error::AlreadyExists);
        }
        self.write_item(item, None, false)
    }

    /// Commits an import as one SQLite transaction after validating every item.
    pub(crate) fn put_items_atomic(&mut self, items: Vec<Item>) -> Result<Vec<RevisionInfo>> {
        let key = self.key()?.clone();
        let mut ids = BTreeSet::new();
        for item in &items {
            item.validate()?;
            if serde_json::to_vec(item)?.len() > MAX_ITEM_BYTES {
                return Err(Error::InvalidItem("serialized item is too large".into()));
            }
            if !ids.insert(item.id.clone()) || self.head_revision(&item.id)?.is_some() {
                return Err(Error::AlreadyExists);
            }
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut revisions = Vec::with_capacity(items.len());
        for item in items {
            let nonce = random_array::<NONCE_LEN>();
            let aad = record_aad(&self.header.vault_id, &item.id, None, KEY_EPOCH, false);
            let plaintext = Zeroizing::new(serde_json::to_vec(&item)?);
            let ciphertext = encrypt(&key, &nonce, &aad, &plaintext)?;
            let revision = EncryptedRevision {
                format_version: FORMAT_VERSION,
                vault_id: self.header.vault_id,
                item_id: item.id.clone(),
                parent_revision: None,
                key_epoch: KEY_EPOCH,
                nonce,
                ciphertext,
                tombstone: false,
            };
            let revision_id = revision.revision_id();
            insert_revision(&transaction, &revision, &revision_id)?;
            transaction.execute(
                "INSERT INTO heads(item_id,revision,tombstone) VALUES(?,?,0)",
                params![revision.item_id, revision_id],
            )?;
            revisions.push(RevisionInfo {
                item_id: revision.item_id,
                revision: revision_id,
                parent_revision: None,
            });
        }
        transaction.commit()?;
        Ok(revisions)
    }

    pub fn update(&mut self, item: Item, expected_revision: &str) -> Result<RevisionInfo> {
        item.validate()?;
        self.write_item(item, Some(expected_revision), false)
    }

    pub fn delete(&mut self, item_id: &str, expected_revision: &str) -> Result<RevisionInfo> {
        if item_id.is_empty() {
            return Err(Error::InvalidItem("id must not be empty".into()));
        }
        let mut item = Item::new("deleted");
        item.id = item_id.to_owned();
        self.write_item(item, Some(expected_revision), true)
    }

    fn write_item(
        &mut self,
        item: Item,
        expected: Option<&str>,
        tombstone: bool,
    ) -> Result<RevisionInfo> {
        let key = self.key()?.clone();
        let actual = self
            .head_revision(&item.id)?
            .map(|revision| revision.revision_id());
        match (expected, actual.as_deref()) {
            (None, None) => {}
            (Some(expected), Some(actual)) if expected == actual => {}
            (Some(expected), Some(actual)) => {
                return Err(Error::Conflict {
                    expected: expected.into(),
                    actual: actual.into(),
                })
            }
            (Some(expected), None) => {
                return Err(Error::Conflict {
                    expected: expected.into(),
                    actual: "<missing>".into(),
                })
            }
            (None, Some(_)) => return Err(Error::AlreadyExists),
        }
        let parent_revision = actual;
        let nonce = random_array::<NONCE_LEN>();
        let aad = record_aad(
            &self.header.vault_id,
            &item.id,
            parent_revision.as_deref(),
            KEY_EPOCH,
            tombstone,
        );
        let plaintext = if tombstone {
            Zeroizing::new(Vec::new())
        } else {
            Zeroizing::new(serde_json::to_vec(&item)?)
        };
        if plaintext.len() > MAX_ITEM_BYTES {
            return Err(Error::InvalidItem("serialized item is too large".into()));
        }
        let ciphertext = encrypt(&key, &nonce, &aad, &plaintext)?;
        let revision = EncryptedRevision {
            format_version: FORMAT_VERSION,
            vault_id: self.header.vault_id,
            item_id: item.id.clone(),
            parent_revision,
            key_epoch: KEY_EPOCH,
            nonce,
            ciphertext,
            tombstone,
        };
        self.apply_encrypted_revision(revision, expected)
    }

    pub fn encrypted_revisions(&self) -> Result<Vec<EncryptedRevision>> {
        self.key()?;
        let mut statement = self.connection.prepare(
            "SELECT format_version,vault_id,item_id,parent_revision,key_epoch,nonce,ciphertext,tombstone FROM revisions ORDER BY rowid"
        )?;
        let revisions = statement
            .query_map([], row_to_revision)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into);
        revisions
    }

    pub fn export_backup(&self, path: impl AsRef<Path>) -> Result<()> {
        let key = self.key()?;
        let payload = BackupPayload {
            revisions: self.encrypted_revisions()?,
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
            format_version: FORMAT_VERSION,
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
        if envelope.format_version != FORMAT_VERSION {
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
        if payload.revisions.len() > 1_000_000 {
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
            payload.revisions,
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
        revisions: Vec<EncryptedRevision>,
    ) -> Result<Self> {
        let connection = open_connection(path)?;
        connection.execute_batch(SCHEMA)?;
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
        connection.execute(
            "INSERT INTO vault_meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                FORMAT_VERSION,
                vault_id.as_slice(),
                kdf.memory_kib,
                kdf.iterations,
                kdf.parallelism,
                password_salt.as_slice(),
                password_nonce.as_slice(),
                password_wrapped_key,
                recovery_nonce.as_slice(),
                recovery_wrapped_key,
            ],
        )?;
        let header = read_header(&connection)?;
        let mut vault = Self {
            path: path.to_path_buf(),
            connection,
            header,
            master_key: Some(master_key),
        };
        for revision in revisions {
            let expected = revision.parent_revision.clone();
            vault.apply_encrypted_revision(revision, expected.as_deref())?;
        }
        Ok(vault)
    }

    pub fn apply_encrypted_revision(
        &mut self,
        revision: EncryptedRevision,
        expected_head: Option<&str>,
    ) -> Result<RevisionInfo> {
        let key = self.key()?.clone();
        revision.validate_shape(&self.header.vault_id)?;
        if !revision.tombstone {
            let item = decrypt_item(&key, &revision)?;
            item.validate()?;
            if item.id != revision.item_id {
                return Err(Error::Crypto);
            }
        } else {
            decrypt_revision(&key, &revision)?;
        }

        let id = revision.revision_id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(stored) = revision_by_id(&transaction, &id)? {
            if stored != revision {
                return Err(Error::Crypto);
            }
            return Ok(RevisionInfo {
                item_id: revision.item_id,
                revision: id,
                parent_revision: revision.parent_revision,
            });
        }

        // Read the head while holding the same IMMEDIATE transaction that writes
        // it. Two processes editing one ancestor therefore cannot both pass the
        // compare-and-swap check and overwrite the materialized head.
        let actual =
            head_revision(&transaction, &revision.item_id)?.map(|value| value.revision_id());
        match (expected_head, actual.as_deref()) {
            (None, None) => {}
            (Some(expected), Some(actual)) if expected == actual => {}
            (_, Some(actual)) => {
                return Err(Error::Conflict {
                    expected: expected_head.unwrap_or("<missing>").into(),
                    actual: actual.into(),
                })
            }
            (Some(expected), None) => {
                return Err(Error::Conflict {
                    expected: expected.into(),
                    actual: "<missing>".into(),
                })
            }
        }
        if revision.parent_revision.as_deref() != actual.as_deref() {
            return Err(Error::Conflict {
                expected: revision
                    .parent_revision
                    .clone()
                    .unwrap_or_else(|| "<missing>".into()),
                actual: actual.unwrap_or_else(|| "<missing>".into()),
            });
        }

        insert_revision(&transaction, &revision, &id)?;
        transaction.execute(
            "INSERT INTO heads(item_id,revision,tombstone) VALUES(?,?,?) \
             ON CONFLICT(item_id) DO UPDATE SET revision=excluded.revision,tombstone=excluded.tombstone",
            params![revision.item_id, id, revision.tombstone],
        )?;
        transaction.commit()?;
        Ok(RevisionInfo {
            item_id: revision.item_id,
            revision: id,
            parent_revision: revision.parent_revision,
        })
    }

    fn head_revision(&self, item_id: &str) -> Result<Option<EncryptedRevision>> {
        self.connection.query_row(
            "SELECT r.format_version,r.vault_id,r.item_id,r.parent_revision,r.key_epoch,r.nonce,r.ciphertext,r.tombstone \
             FROM heads h JOIN revisions r ON r.revision=h.revision WHERE h.item_id=?",
            [item_id],
            row_to_revision,
        ).optional().map_err(Into::into)
    }
}

fn revision_by_id(connection: &Connection, revision_id: &str) -> Result<Option<EncryptedRevision>> {
    connection.query_row(
            "SELECT format_version,vault_id,item_id,parent_revision,key_epoch,nonce,ciphertext,tombstone \
             FROM revisions WHERE revision=?",
            [revision_id],
            row_to_revision,
        ).optional().map_err(Into::into)
}

fn head_revision(connection: &Connection, item_id: &str) -> Result<Option<EncryptedRevision>> {
    connection.query_row(
        "SELECT r.format_version,r.vault_id,r.item_id,r.parent_revision,r.key_epoch,r.nonce,r.ciphertext,r.tombstone \
         FROM heads h JOIN revisions r ON r.revision=h.revision WHERE h.item_id=?",
        [item_id],
        row_to_revision,
    ).optional().map_err(Into::into)
}

impl Vault {
    fn key(&self) -> Result<&SecretKey> {
        self.master_key.as_ref().ok_or(Error::Locked)
    }
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    revisions: Vec<EncryptedRevision>,
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
    let row = connection.query_row(
        "SELECT format_version,vault_id,kdf_memory_kib,kdf_iterations,kdf_parallelism,password_salt,password_nonce,password_wrapped_key,recovery_nonce,recovery_wrapped_key FROM vault_meta WHERE singleton=1",
        [],
        |row| Ok((
            row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?,
            row.get::<_, u32>(2)?, row.get::<_, u32>(3)?, row.get::<_, u32>(4)?,
            row.get::<_, Vec<u8>>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?,
            row.get::<_, Vec<u8>>(8)?, row.get::<_, Vec<u8>>(9)?,
        )),
    )?;
    if row.0 != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(row.0));
    }
    Ok(Header {
        vault_id: array(&row.1)?,
        kdf: KdfConfig {
            memory_kib: row.2,
            iterations: row.3,
            parallelism: row.4,
        },
        password_salt: array(&row.5)?,
        password_nonce: array(&row.6)?,
        password_wrapped_key: row.7,
        recovery_nonce: array(&row.8)?,
        recovery_wrapped_key: row.9,
    })
}

fn row_to_revision(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedRevision> {
    let vault_id: Vec<u8> = row.get(1)?;
    let nonce: Vec<u8> = row.get(5)?;
    Ok(EncryptedRevision {
        format_version: row.get(0)?,
        vault_id: vault_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        item_id: row.get(2)?,
        parent_revision: row.get(3)?,
        key_epoch: u64::try_from(row.get::<_, i64>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        nonce: nonce
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ciphertext: row.get(6)?,
        tombstone: row.get(7)?,
    })
}

fn insert_revision(connection: &Connection, revision: &EncryptedRevision, id: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO revisions(revision,format_version,vault_id,item_id,parent_revision,key_epoch,nonce,ciphertext,tombstone) VALUES(?,?,?,?,?,?,?,?,?)",
        params![
            id, revision.format_version, revision.vault_id.as_slice(), revision.item_id,
            revision.parent_revision, i64::try_from(revision.key_epoch).map_err(|_| Error::Crypto)?, revision.nonce.as_slice(),
            revision.ciphertext, revision.tombstone,
        ],
    )?;
    Ok(())
}

fn decrypt_revision(key: &SecretKey, revision: &EncryptedRevision) -> Result<Zeroizing<Vec<u8>>> {
    let aad = record_aad(
        &revision.vault_id,
        &revision.item_id,
        revision.parent_revision.as_deref(),
        revision.key_epoch,
        revision.tombstone,
    );
    decrypt(key, &revision.nonce, &aad, &revision.ciphertext).map_err(|_| Error::Crypto)
}

fn decrypt_item(key: &SecretKey, revision: &EncryptedRevision) -> Result<Item> {
    let plaintext = decrypt_revision(key, revision)?;
    serde_json::from_slice(&plaintext).map_err(|_| Error::Crypto)
}

fn array<const N: usize>(value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| Error::Crypto)
}

fn to_key(value: &[u8]) -> Result<SecretKey> {
    Ok(Zeroizing::new(array(value)?))
}
