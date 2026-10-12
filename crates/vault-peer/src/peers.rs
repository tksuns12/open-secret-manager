use std::path::Path;
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Keystore, NoKeystore, Result};

/// A device paired before the vault had a control plane, when the owner's
/// confirmation alone authorized one peer. Kept only so that such a pair
/// can be moved onto the control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub device_id: [u8; 16],
    pub public_key: [u8; 32],
    /// SHA-256 of the peer's TLS certificate.
    pub transport_pin: [u8; 32],
    /// Last address the peer was reached at, if known.
    pub address: Option<String>,
    pub paired_at: u64,
}

/// This device's TLS identity: a self-signed Ed25519 certificate. It is
/// separate from the revision signing key and is available while the vault
/// is locked, so a locked device can still receive ciphertext.
#[derive(Clone)]
pub struct TransportIdentity {
    pub(crate) certificate: Vec<u8>,
    pub(crate) private_key: Zeroizing<Vec<u8>>,
}

impl TransportIdentity {
    /// What peers pin: SHA-256 of the certificate.
    pub fn pin(&self) -> [u8; 32] {
        pin_of(&self.certificate)
    }
}

impl std::fmt::Debug for TransportIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportIdentity")
            .field("pin", &self.pin())
            .finish_non_exhaustive()
    }
}

pub(crate) fn pin_of(certificate: &[u8]) -> [u8; 32] {
    Sha256::digest(certificate).into()
}

/// The layout of the peer store file, which the address book shares.
/// Version 2 (Phase 14) keeps the TLS key sealed by the system's keystore,
/// in `transport_key`; a build that knows only version 1 would not find it
/// and would make the device another TLS identity, so it refuses the file.
/// Version 3 (Phase 16) keeps several addresses for each device, in
/// `device_addresses`; version 2 kept one, in `member_addresses`.
pub(crate) const STORE_VERSION: u32 = 3;

/// How this device's TLS key is kept in the peer store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKept {
    /// Sealed by the system's keystore.
    Sealed,
    /// Unsealed, in the file only, which only this account can read: the
    /// system has no keystore, or it did not answer when the key was last
    /// to be sealed. It is sealed the next time the store is opened with a
    /// keystore that answers.
    InFile,
}

/// This device's transport identity. A store written before the vault had a
/// control plane may also name the one device it was paired with.
///
/// The TLS key has to be usable while the vault is locked, so it is not
/// encrypted under the vault's keys. It is sealed by the system's keystore
/// ([`Keystore`]) where there is one; where there is none it is kept as it
/// is, as before Phase 14. The file is created with owner-only permissions.
/// Revision authenticity never depends on it.
pub struct PeerStore {
    connection: Connection,
    keystore: Arc<dyn Keystore>,
    /// The identity once it has been read, so that the keystore is asked
    /// once per opening of the store.
    identity: Option<TransportIdentity>,
}

impl PeerStore {
    /// Opens the store at `path`. A TLS key kept unsealed, by an earlier
    /// build or because no keystore answered, is sealed now if `keystore`
    /// does; that the keystore did not is not an error.
    pub fn open(path: impl AsRef<Path>, keystore: Arc<dyn Keystore>) -> Result<Self> {
        let path = path.as_ref();
        let connection = Connection::open(path)?;
        restrict_permissions(path)?;
        Self::from_connection(connection, keystore)
    }

    /// A store in memory, with no keystore.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?, Arc::new(NoKeystore))
    }

    fn from_connection(connection: Connection, keystore: Arc<dyn Keystore>) -> Result<Self> {
        osm_vault_sync::claim_store_version(&connection, STORE_VERSION)?;
        // Pages a key was on are overwritten when they are freed, so that
        // sealing a key leaves no copy of it in the file.
        connection.execute_batch(
            "PRAGMA secure_delete = ON;
             PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS transport_key (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 certificate BLOB NOT NULL,
                 private_key BLOB,
                 sealed_key BLOB,
                 CHECK((private_key IS NULL) <> (sealed_key IS NULL))
             ) STRICT;
             CREATE TABLE IF NOT EXISTS peers (
                 device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
                 public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
                 transport_pin BLOB NOT NULL UNIQUE CHECK(length(transport_pin) = 32),
                 address TEXT CHECK(address IS NULL OR length(address) <= 128),
                 paired_at INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS relay (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 code TEXT NOT NULL CHECK(length(code) BETWEEN 1 AND 1024)
             ) STRICT;",
        )?;
        let mut store = Self {
            connection,
            keystore,
            identity: None,
        };
        store.move_version_1_key()?;
        store.seal_kept_key()?;
        Ok(store)
    }

    /// Moves the key a version 1 store kept into `transport_key`, unsealed
    /// for now. This goes by what is in the file, not by its version
    /// number, which the address book may have raised first.
    fn move_version_1_key(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                           WHERE type = 'table' AND name = 'transport_identity')",
            [],
            |row| row.get(0),
        )?;
        if old {
            transaction.execute(
                "INSERT OR IGNORE INTO transport_key(singleton, certificate, private_key)
                 SELECT singleton, certificate, private_key FROM transport_identity",
                [],
            )?;
            transaction.execute("DROP TABLE transport_identity", [])?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Seals a key kept unsealed, if the keystore does it now. The sealed
    /// key replaces the unsealed one only once the keystore has opened it
    /// again to the same key.
    fn seal_kept_key(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let kept = transaction
            .query_row(
                "SELECT private_key FROM transport_key
                 WHERE singleton = 1 AND private_key IS NOT NULL",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(Zeroizing::new);
        if let Some(key) = kept {
            if let Some(sealed) = seal_checked(self.keystore.as_ref(), &key) {
                transaction.execute(
                    "UPDATE transport_key SET sealed_key = ?1, private_key = NULL
                     WHERE singleton = 1",
                    params![sealed],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// How this device's TLS key is kept, or `None` before it has one.
    pub fn key_kept(&self) -> Result<Option<KeyKept>> {
        let sealed = self
            .connection
            .query_row(
                "SELECT sealed_key IS NOT NULL FROM transport_key WHERE singleton = 1",
                [],
                |row| row.get::<_, bool>(0),
            )
            .optional()?;
        Ok(sealed.map(|sealed| {
            if sealed {
                KeyKept::Sealed
            } else {
                KeyKept::InFile
            }
        }))
    }

    /// Returns this device's TLS identity, creating it on first use. A
    /// sealed key is opened by the keystore; when the keystore cannot open
    /// it this fails with [`Error::Keystore`], and nothing is replaced.
    pub fn transport_identity(&mut self) -> Result<TransportIdentity> {
        if let Some(identity) = &self.identity {
            return Ok(identity.clone());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = transaction
            .query_row(
                "SELECT certificate, private_key, sealed_key FROM transport_key
                 WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?;
        let identity = match stored {
            Some((certificate, Some(private_key), _)) => TransportIdentity {
                certificate,
                private_key: Zeroizing::new(private_key),
            },
            Some((certificate, None, Some(sealed))) => TransportIdentity {
                certificate,
                private_key: self.keystore.open(&sealed).map_err(Error::Keystore)?,
            },
            Some((_, None, None)) => return Err(Error::MalformedFrame),
            None => {
                let identity = generate_identity()?;
                match seal_checked(self.keystore.as_ref(), &identity.private_key) {
                    Some(sealed) => transaction.execute(
                        "INSERT INTO transport_key(singleton, certificate, sealed_key)
                         VALUES (1, ?1, ?2)",
                        params![identity.certificate, sealed],
                    )?,
                    None => transaction.execute(
                        "INSERT INTO transport_key(singleton, certificate, private_key)
                         VALUES (1, ?1, ?2)",
                        params![identity.certificate, identity.private_key.as_slice()],
                    )?,
                };
                identity
            }
        };
        transaction.commit()?;
        self.identity = Some(identity.clone());
        Ok(identity)
    }

    /// The device this one was paired with before the vault had a control
    /// plane, if any. Nothing adds to this list any more.
    /// The code of the relay this device uses, as the vault last said when
    /// it was unlocked: kept here so that a locked device, which cannot read
    /// the vault, can still sync through it. It is kept as it is, unsealed:
    /// its token lets a device onto the relay, which passes bytes it cannot
    /// read, and opens nothing of the vault.
    pub fn relay_code(&self) -> Result<Option<Zeroizing<String>>> {
        Ok(self
            .connection
            .query_row("SELECT code FROM relay WHERE singleton = 1", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(Zeroizing::new))
    }

    /// Keeps `code` as the relay's, or forgets it with `None`.
    pub fn set_relay_code(&mut self, code: Option<&str>) -> Result<()> {
        match code {
            Some(code) => self.connection.execute(
                "INSERT INTO relay(singleton, code) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET code = excluded.code",
                [code],
            )?,
            None => self.connection.execute("DELETE FROM relay", [])?,
        };
        Ok(())
    }

    pub fn legacy_peers(&self) -> Result<Vec<Peer>> {
        let mut statement = self.connection.prepare(
            "SELECT device_id, public_key, transport_pin, address, paired_at
             FROM peers ORDER BY paired_at",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(device_id, public_key, transport_pin, address, paired_at)| {
                    Ok(Peer {
                        device_id: device_id.try_into().map_err(|_| Error::MalformedFrame)?,
                        public_key: public_key.try_into().map_err(|_| Error::MalformedFrame)?,
                        transport_pin: transport_pin
                            .try_into()
                            .map_err(|_| Error::MalformedFrame)?,
                        address,
                        paired_at: paired_at.try_into().map_err(|_| Error::MalformedFrame)?,
                    })
                },
            )
            .collect()
    }

    /// Records a device as paired before the vault had a control plane.
    /// Nothing in the product does this any more; it lets tests set up the
    /// state an older build left behind.
    #[doc(hidden)]
    pub fn insert_legacy_peer(&mut self, peer: &Peer) -> Result<()> {
        let paired_at = i64::try_from(peer.paired_at).map_err(|_| Error::MalformedFrame)?;
        self.connection.execute(
            "INSERT INTO peers(device_id, public_key, transport_pin, address, paired_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                peer.device_id.as_slice(),
                peer.public_key.as_slice(),
                peer.transport_pin.as_slice(),
                peer.address,
                paired_at
            ],
        )?;
        Ok(())
    }

    /// Forgets the devices paired before the vault had a control plane,
    /// once this device is a member of it.
    pub fn clear_legacy_peers(&mut self) -> Result<()> {
        self.connection.execute("DELETE FROM peers", [])?;
        Ok(())
    }
}

/// What `keystore` sealed `key` into, once it has opened that again to the
/// same key; `None` when it did not, for whatever reason, so that the key
/// stays kept unsealed rather than sealed into something that will not open.
fn seal_checked(keystore: &dyn Keystore, key: &[u8]) -> Option<Vec<u8>> {
    let sealed = keystore.seal(key).ok()?;
    let opened = keystore.open(&sealed).ok()?;
    (opened.as_slice() == key).then_some(sealed)
}

fn generate_identity() -> Result<TransportIdentity> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|_| Error::Transport("could not generate a TLS key"))?;
    // Peers pin the certificate hash and never check names or validity
    // periods, so the name is a placeholder.
    let certificate = rcgen::CertificateParams::new(vec!["osm-peer".to_owned()])
        .and_then(|params| params.self_signed(&key))
        .map_err(|_| Error::Transport("could not create a TLS certificate"))?;
    Ok(TransportIdentity {
        certificate: certificate.der().to_vec(),
        private_key: Zeroizing::new(key.serialize_der()),
    })
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| Error::Transport("could not restrict peer store permissions"))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{KeystoreError, MemoryKeystore};

    fn store(keystore: Arc<dyn Keystore>) -> (tempfile::TempDir, std::path::PathBuf, PeerStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.sqlite3");
        let peers = PeerStore::open(&path, keystore).unwrap();
        (dir, path, peers)
    }

    /// The part of the key that is secret: an Ed25519 PKCS#8 key holds its
    /// 32-byte seed after a 16-byte prefix (and may end with the public
    /// key, which the certificate also holds).
    pub(crate) fn secret(identity: &TransportIdentity) -> Vec<u8> {
        identity.private_key[16..48].to_vec()
    }

    fn in_file(path: &Path, secret: &[u8]) -> bool {
        std::fs::read(path)
            .unwrap()
            .windows(secret.len())
            .any(|window| window == secret)
    }

    #[test]
    fn a_new_key_is_sealed_and_never_written_unsealed() {
        let keystore = Arc::new(MemoryKeystore::default());
        let (_dir, path, mut peers) = store(keystore.clone());
        assert_eq!(peers.key_kept().unwrap(), None);
        let identity = peers.transport_identity().unwrap();
        assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::Sealed));
        drop(peers);
        assert!(!in_file(&path, &secret(&identity)));
        let mut again = PeerStore::open(&path, keystore).unwrap();
        assert_eq!(again.transport_identity().unwrap().pin(), identity.pin());
    }

    #[test]
    fn a_key_made_while_the_keystore_did_not_answer_is_sealed_when_it_does() {
        let keystore = Arc::new(MemoryKeystore::default());
        keystore.set_unavailable(true);
        let (_dir, path, mut peers) = store(keystore.clone());
        let identity = peers.transport_identity().unwrap();
        assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::InFile));
        drop(peers);
        assert!(in_file(&path, &secret(&identity)));

        // Still not answering: the store opens, and the key is read as it is.
        let mut peers = PeerStore::open(&path, keystore.clone()).unwrap();
        assert_eq!(peers.transport_identity().unwrap().pin(), identity.pin());
        drop(peers);

        keystore.set_unavailable(false);
        let mut peers = PeerStore::open(&path, keystore.clone()).unwrap();
        assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::Sealed));
        assert_eq!(peers.transport_identity().unwrap().pin(), identity.pin());
        drop(peers);
        assert!(!in_file(&path, &secret(&identity)));
    }

    #[test]
    fn a_sealed_key_the_keystore_cannot_open_is_an_error_and_nothing_replaces_it() {
        let keystore = Arc::new(MemoryKeystore::default());
        let (_dir, path, mut peers) = store(keystore.clone());
        let pin = peers.transport_identity().unwrap().pin();
        drop(peers);

        keystore.set_unavailable(true);
        let mut peers = PeerStore::open(&path, keystore.clone()).unwrap();
        assert!(matches!(
            peers.transport_identity(),
            Err(Error::Keystore(KeystoreError::Unavailable))
        ));
        drop(peers);
        keystore.set_unavailable(false);
        let mut peers = PeerStore::open(&path, keystore.clone()).unwrap();
        assert_eq!(peers.transport_identity().unwrap().pin(), pin);
        drop(peers);

        // Lost for good: still an error each time, and not a new identity.
        keystore.lose_everything();
        for _ in 0..2 {
            let mut peers = PeerStore::open(&path, keystore.clone()).unwrap();
            assert!(matches!(
                peers.transport_identity(),
                Err(Error::Keystore(KeystoreError::Lost))
            ));
            assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::Sealed));
        }
        // Where there is no keystore at all, it is not opened either.
        let mut peers = PeerStore::open(&path, Arc::new(NoKeystore)).unwrap();
        assert!(matches!(
            peers.transport_identity(),
            Err(Error::Keystore(KeystoreError::Absent))
        ));
    }

    /// Seals into something it then opens to another key.
    struct Garbling;

    impl Keystore for Garbling {
        fn seal(&self, _key: &[u8]) -> std::result::Result<Vec<u8>, KeystoreError> {
            Ok(vec![1])
        }

        fn open(&self, _sealed: &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, KeystoreError> {
            Ok(Zeroizing::new(vec![2; 48]))
        }
    }

    #[test]
    fn a_key_is_not_sealed_into_something_that_does_not_open_to_it() {
        let (_dir, path, mut peers) = store(Arc::new(Garbling));
        let identity = peers.transport_identity().unwrap();
        assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::InFile));
        drop(peers);
        let mut peers = PeerStore::open(&path, Arc::new(Garbling)).unwrap();
        assert_eq!(peers.key_kept().unwrap(), Some(KeyKept::InFile));
        assert_eq!(peers.transport_identity().unwrap().pin(), identity.pin());
    }
}
