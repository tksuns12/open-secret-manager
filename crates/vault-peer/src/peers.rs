use std::path::Path;

use rusqlite::{params, Connection, TransactionBehavior};

use crate::{Error, Result};

/// Until committed membership exists, owner-confirmed pairing is the only
/// enrollment authority, so a vault may have one paired device.
pub const MAX_PEERS: usize = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub device_id: [u8; 16],
    pub public_key: [u8; 32],
    pub paired_at: u64,
}

/// Devices this vault has paired with.
pub struct PeerStore {
    connection: Connection,
}

impl PeerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS peers (
                 device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
                 public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
                 paired_at INTEGER NOT NULL
             ) STRICT;",
        )?;
        Ok(Self { connection })
    }

    pub fn peers(&self) -> Result<Vec<Peer>> {
        let mut statement = self
            .connection
            .prepare("SELECT device_id, public_key, paired_at FROM peers ORDER BY paired_at")?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(device_id, public_key, paired_at)| {
                Ok(Peer {
                    device_id: device_id.try_into().map_err(|_| Error::MalformedFrame)?,
                    public_key: public_key.try_into().map_err(|_| Error::MalformedFrame)?,
                    paired_at: paired_at.try_into().map_err(|_| Error::MalformedFrame)?,
                })
            })
            .collect()
    }

    /// Fails with `PeerLimit` if another pairing would exceed [`MAX_PEERS`].
    pub fn ensure_capacity(&self) -> Result<()> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))?;
        if count as usize >= MAX_PEERS {
            return Err(Error::PeerLimit);
        }
        Ok(())
    }

    pub(crate) fn add(
        &mut self,
        device_id: [u8; 16],
        public_key: [u8; 32],
        now: u64,
    ) -> Result<()> {
        let now = i64::try_from(now).map_err(|_| Error::MalformedFrame)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))?;
        if count as usize >= MAX_PEERS {
            return Err(Error::PeerLimit);
        }
        transaction.execute(
            "INSERT INTO peers(device_id, public_key, paired_at) VALUES (?1, ?2, ?3)",
            params![device_id.as_slice(), public_key.as_slice(), now],
        )?;
        transaction.commit()?;
        Ok(())
    }
}
