use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

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
pub(crate) const STORE_VERSION: u32 = 1;

/// This device's transport identity. A store written before the vault had a
/// control plane may also name the one device it was paired with.
///
/// The file holds the TLS private key unencrypted, because it must be usable
/// while the vault is locked; it is created with owner-only permissions.
/// Revision authenticity never depends on it.
pub struct PeerStore {
    connection: Connection,
}

impl PeerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let connection = Connection::open(path)?;
        restrict_permissions(path)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        osm_vault_sync::claim_store_version(&connection, STORE_VERSION)?;
        connection.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS transport_identity (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 certificate BLOB NOT NULL,
                 private_key BLOB NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS peers (
                 device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
                 public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
                 transport_pin BLOB NOT NULL UNIQUE CHECK(length(transport_pin) = 32),
                 address TEXT CHECK(address IS NULL OR length(address) <= 128),
                 paired_at INTEGER NOT NULL
             ) STRICT;",
        )?;
        Ok(Self { connection })
    }

    /// Returns this device's TLS identity, creating it on first use.
    pub fn transport_identity(&mut self) -> Result<TransportIdentity> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = transaction
            .query_row(
                "SELECT certificate, private_key FROM transport_identity WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let identity = match stored {
            Some((certificate, private_key)) => TransportIdentity {
                certificate,
                private_key: Zeroizing::new(private_key),
            },
            None => {
                let identity = generate_identity()?;
                transaction.execute(
                    "INSERT INTO transport_identity(singleton, certificate, private_key)
                     VALUES (1, ?1, ?2)",
                    params![identity.certificate, identity.private_key.as_slice()],
                )?;
                identity
            }
        };
        transaction.commit()?;
        Ok(identity)
    }

    /// The device this one was paired with before the vault had a control
    /// plane, if any. Nothing adds to this list any more.
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
