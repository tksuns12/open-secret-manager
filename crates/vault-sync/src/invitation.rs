use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{DeviceId, Error, Result, VaultId};

const INVITATION_HASH_DOMAIN: &[u8] = b"osm-invitation-token-v1";

/// A bearer secret. It is high entropy, is never persisted in plaintext, and is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InvitationToken([u8; 32]);

impl InvitationToken {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes the token for an invitation link or direct out-of-band transfer.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(INVITATION_HASH_DOMAIN);
        hasher.update(self.0);
        hasher.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitationPolicy {
    max_ttl_secs: u64,
}

impl InvitationPolicy {
    pub const DEFAULT_MAX_TTL_SECS: u64 = 24 * 60 * 60;

    pub fn new(max_ttl_secs: u64) -> Result<Self> {
        if max_ttl_secs == 0 || max_ttl_secs > i64::MAX as u64 {
            return Err(Error::InvitationExpiryPolicy);
        }
        Ok(Self { max_ttl_secs })
    }

    pub fn max_ttl_secs(self) -> u64 {
        self.max_ttl_secs
    }
}

impl Default for InvitationPolicy {
    fn default() -> Self {
        Self {
            max_ttl_secs: Self::DEFAULT_MAX_TTL_SECS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedInvitation {
    pub vault_id: VaultId,
    pub recipient: DeviceId,
}

/// The layout of the invitation store.
const STORE_VERSION: u32 = 1;

pub struct InvitationStore {
    connection: Connection,
    policy: InvitationPolicy,
}

#[cfg(unix)]
fn precreate_owner_only(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
}

#[cfg(not(unix))]
fn precreate_owner_only(_path: &Path) {}

#[cfg(unix)]
fn restrict_db_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::Permissions::from_mode(0o600);
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        let candidate = std::path::PathBuf::from(candidate);
        if std::fs::symlink_metadata(&candidate).is_ok_and(|meta| meta.is_file()) {
            let _ = std::fs::set_permissions(&candidate, mode.clone());
        }
    }
}

#[cfg(not(unix))]
fn restrict_db_permissions(_path: &Path) {}

impl InvitationStore {
    pub fn open(path: impl AsRef<Path>, policy: InvitationPolicy) -> Result<Self> {
        let path = path.as_ref();
        precreate_owner_only(path);
        let connection = Connection::open(path)?;
        let store = Self::from_connection(connection, policy)?;
        restrict_db_permissions(path);
        Ok(store)
    }

    pub fn open_in_memory(policy: InvitationPolicy) -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?, policy)
    }

    fn from_connection(connection: Connection, policy: InvitationPolicy) -> Result<Self> {
        crate::claim_store_version(&connection, STORE_VERSION)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS invitations (
                 token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
                 vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
                 recipient BLOB CHECK(recipient IS NULL OR length(recipient) = 32),
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 used_at INTEGER
             ) STRICT;",
        )?;
        Ok(Self { connection, policy })
    }

    /// Issues a recipient-bound token. Times are Unix seconds supplied by the caller's clock.
    pub fn issue(
        &mut self,
        vault_id: VaultId,
        recipient: DeviceId,
        now: u64,
        expires_at: u64,
    ) -> Result<InvitationToken> {
        self.insert(vault_id, Some(recipient), now, expires_at)
    }

    /// Issues a pairing token before the joining device's identity is known.
    /// The first successful approval binds it to the claiming device and
    /// consumes it, so it stays single-use.
    pub fn issue_pairing(
        &mut self,
        vault_id: VaultId,
        now: u64,
        expires_at: u64,
    ) -> Result<InvitationToken> {
        self.insert(vault_id, None, now, expires_at)
    }

    fn insert(
        &mut self,
        vault_id: VaultId,
        recipient: Option<DeviceId>,
        now: u64,
        expires_at: u64,
    ) -> Result<InvitationToken> {
        expires_at
            .checked_sub(now)
            .filter(|ttl| *ttl > 0 && *ttl <= self.policy.max_ttl_secs)
            .ok_or(Error::InvitationExpiryPolicy)?;
        let now = sql_time(now)?;
        let expires_at = sql_time(expires_at)?;

        for _ in 0..4 {
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret).map_err(|_| Error::Randomness)?;
            let token = InvitationToken(secret);
            let changed = self.connection.execute(
                "INSERT OR IGNORE INTO invitations
                 (token_hash, vault_id, recipient, created_at, expires_at, used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![
                    token.digest(),
                    vault_id.0,
                    recipient.map(|recipient| recipient.0),
                    now,
                    expires_at
                ],
            )?;
            if changed == 1 {
                return Ok(token);
            }
        }
        Err(Error::Randomness)
    }

    /// Checks that a token is known, unused, and unexpired without consuming
    /// it, so an owner is only asked to confirm a pairing that can succeed.
    pub fn check(&self, token: &InvitationToken, now: u64) -> Result<VaultId> {
        let now = sql_time(now)?;
        let (vault_id, expires_at, used_at) = self
            .connection
            .query_row(
                "SELECT vault_id, expires_at, used_at FROM invitations WHERE token_hash = ?1",
                [token.digest()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(Error::InvalidInvitation)?;
        if used_at.is_some() {
            return Err(Error::InvitationReplay);
        }
        if now >= expires_at {
            return Err(Error::InvitationExpired);
        }
        Ok(VaultId(fixed_32(vault_id)?))
    }

    /// Atomically approves and consumes an invitation.
    ///
    /// Wrong-recipient and expired attempts do not consume it. A successful approval does,
    /// and every later attempt returns [`Error::InvitationReplay`], including after restart.
    pub fn approve(
        &mut self,
        token: &InvitationToken,
        claiming_recipient: DeviceId,
        now: u64,
    ) -> Result<ApprovedInvitation> {
        let now = sql_time(now)?;
        let digest = token.digest();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = transaction
            .query_row(
                "SELECT vault_id, recipient, expires_at, used_at
                 FROM invitations WHERE token_hash = ?1",
                [digest],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(Error::InvalidInvitation)?;

        let vault_id = VaultId(fixed_32(record.0)?);
        // An unbound pairing token accepts whichever device claims it first.
        if let Some(bound) = record.1 {
            if DeviceId(fixed_32(bound)?) != claiming_recipient {
                return Err(Error::InvitationRecipientMismatch);
            }
        }
        let recipient = claiming_recipient;
        if record.3.is_some() {
            return Err(Error::InvitationReplay);
        }
        if now >= record.2 {
            return Err(Error::InvitationExpired);
        }

        let changed = transaction.execute(
            "UPDATE invitations SET used_at = ?1, recipient = ?3
             WHERE token_hash = ?2 AND used_at IS NULL AND expires_at > ?1",
            params![now, digest, recipient.0],
        )?;
        if changed != 1 {
            return Err(Error::InvitationReplay);
        }
        transaction.commit()?;
        Ok(ApprovedInvitation {
            vault_id,
            recipient,
        })
    }
}

fn sql_time(value: u64) -> Result<i64> {
    value.try_into().map_err(|_| Error::TimeOutOfRange)
}

fn fixed_32(value: Vec<u8>) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| Error::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_recipient_bound_single_use_and_persistent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invites.sqlite");
        let token = {
            let mut store = InvitationStore::open(&path, InvitationPolicy::default()).unwrap();
            store
                .issue(VaultId([1; 32]), DeviceId([2; 32]), 100, 200)
                .unwrap()
        };
        let mut store = InvitationStore::open(&path, InvitationPolicy::default()).unwrap();
        assert!(matches!(
            store.approve(&token, DeviceId([3; 32]), 150),
            Err(Error::InvitationRecipientMismatch)
        ));
        let approved = store.approve(&token, DeviceId([2; 32]), 150).unwrap();
        assert_eq!(approved.vault_id, VaultId([1; 32]));
        assert!(matches!(
            store.approve(&token, DeviceId([2; 32]), 151),
            Err(Error::InvitationReplay)
        ));
    }

    #[test]
    fn pairing_token_binds_to_the_first_claimant_and_is_single_use() {
        let mut store = InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap();
        let token = store.issue_pairing(VaultId([1; 32]), 100, 200).unwrap();
        let expired = store.issue_pairing(VaultId([1; 32]), 100, 110).unwrap();
        assert!(matches!(
            store.approve(&expired, DeviceId([2; 32]), 110),
            Err(Error::InvitationExpired)
        ));
        assert_eq!(store.check(&token, 150).unwrap(), VaultId([1; 32]));
        let approved = store.approve(&token, DeviceId([2; 32]), 150).unwrap();
        assert_eq!(approved.recipient, DeviceId([2; 32]));
        assert!(matches!(
            store.check(&token, 150),
            Err(Error::InvitationReplay)
        ));
        // Once consumed the token is bound: the same device sees a replay and
        // any other device a recipient mismatch.
        assert!(matches!(
            store.approve(&token, DeviceId([2; 32]), 151),
            Err(Error::InvitationReplay)
        ));
        assert!(matches!(
            store.approve(&token, DeviceId([3; 32]), 151),
            Err(Error::InvitationRecipientMismatch)
        ));
    }

    #[test]
    fn expiry_is_enforced_at_the_boundary() {
        let mut store = InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap();
        let token = store
            .issue(VaultId([1; 32]), DeviceId([2; 32]), 100, 110)
            .unwrap();
        assert!(matches!(
            store.approve(&token, DeviceId([2; 32]), 110),
            Err(Error::InvitationExpired)
        ));
    }
}
