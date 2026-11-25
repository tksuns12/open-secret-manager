use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::{DeviceId, Error, MessageId, ProtocolLimits, Result, SignedRevision, VaultId};

const STATUS_RECEIVED: i64 = 0;
const STATUS_APPLIED: i64 = 1;
const STATUS_QUARANTINED_OLD_EPOCH: i64 = 2;
const DEFAULT_MAX_QUEUED_MESSAGES: i64 = 100_000;
const DEFAULT_MAX_QUEUED_BYTES: i64 = 128 * 1024 * 1024;
const APPLY_BATCH_SIZE: i64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxStatus {
    Received,
    Applied,
    QuarantinedOldEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxDisposition {
    Received,
    QuarantinedOldEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Inserted {
        message_id: MessageId,
        disposition: InboxDisposition,
    },
    Duplicate {
        message_id: MessageId,
        status: InboxStatus,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub applied: usize,
    pub quarantined_old_epoch: usize,
    /// Entries whose callback reported a dependency or other retryable failure.
    /// They remain in `Received` and can be retried after another entry applies.
    pub deferred: usize,
}

#[derive(Debug)]
pub enum ApplyError<E> {
    Store(Error),
    Callback {
        source: E,
        applied_before_failure: usize,
    },
}

/// A durable queue that stores only signed opaque ciphertext while the vault is locked.
pub struct LockedInbox {
    connection: Connection,
    limits: ProtocolLimits,
    max_queued_messages: i64,
    max_queued_bytes: i64,
}

impl LockedInbox {
    pub fn open(path: impl AsRef<Path>, limits: ProtocolLimits) -> Result<Self> {
        Self::from_connection(Connection::open(path)?, limits)
    }

    pub fn open_in_memory(limits: ProtocolLimits) -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?, limits)
    }

    /// Overrides the queue capacity caps (defaults: 100,000 messages / 128 MiB).
    pub fn with_queue_limits(mut self, max_messages: usize, max_bytes: usize) -> Self {
        self.max_queued_messages = i64::try_from(max_messages).unwrap_or(i64::MAX);
        self.max_queued_bytes = i64::try_from(max_bytes).unwrap_or(i64::MAX);
        self
    }

    fn from_connection(connection: Connection, limits: ProtocolLimits) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS locked_inbox (
                 message_id BLOB PRIMARY KEY CHECK(length(message_id) = 32),
                 vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
                 sender_id BLOB NOT NULL CHECK(length(sender_id) = 32),
                 revision_id BLOB NOT NULL CHECK(length(revision_id) = 32),
                 parent_revision BLOB,
                 key_epoch INTEGER NOT NULL CHECK(key_epoch >= 0),
                 frame BLOB NOT NULL,
                 received_at INTEGER NOT NULL,
                 status INTEGER NOT NULL CHECK(status IN (0, 1, 2)),
                 applied_at INTEGER,
                 UNIQUE(vault_id, revision_id),
                 CHECK(parent_revision IS NULL OR length(parent_revision) = 32)
             ) STRICT;
             CREATE INDEX IF NOT EXISTS locked_inbox_pending
             ON locked_inbox(vault_id, status, received_at);",
        )?;
        Ok(Self {
            connection,
            limits,
            max_queued_messages: DEFAULT_MAX_QUEUED_MESSAGES,
            max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
        })
    }

    /// Verifies the peer pin, expected vault identity, and signature before persisting the opaque frame.
    ///
    /// `minimum_epoch` is the oldest epoch this local member is currently permitted to apply.
    /// Older traffic is retained for auditability but permanently quarantined.
    pub fn receive_verified(
        &mut self,
        expected_vault: VaultId,
        frame: &[u8],
        pinned_sender: DeviceId,
        minimum_epoch: u64,
        received_at: u64,
    ) -> Result<ReceiveOutcome> {
        let signed = SignedRevision::verify_and_decode(frame, pinned_sender, self.limits)?;
        if signed.vault_id() != expected_vault {
            return Err(Error::VaultMismatch);
        }
        let message_id = signed.message_id();
        let received_at = sql_i64(received_at)?;
        let key_epoch = sql_i64(signed.key_epoch())?;
        let status = if signed.key_epoch() < minimum_epoch {
            STATUS_QUARANTINED_OLD_EPOCH
        } else {
            STATUS_RECEIVED
        };

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing_status) = transaction
            .query_row(
                "SELECT status FROM locked_inbox WHERE message_id = ?1",
                [message_id.0.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            return Ok(ReceiveOutcome::Duplicate {
                message_id,
                status: decode_status(existing_status)?,
            });
        }
        let revision_exists = transaction
            .query_row(
                "SELECT 1 FROM locked_inbox WHERE vault_id = ?1 AND revision_id = ?2",
                params![
                    signed.vault_id().0.as_slice(),
                    signed.revision_id().0.as_slice()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if revision_exists {
            return Err(Error::RevisionCollision);
        }
        let (queued_count, queued_bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(frame)), 0) FROM locked_inbox WHERE status != ?1",
            [STATUS_APPLIED],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let added = i64::try_from(frame.len()).unwrap_or(i64::MAX);
        if queued_count >= self.max_queued_messages
            || queued_bytes.saturating_add(added) > self.max_queued_bytes
        {
            return Err(Error::InboxFull);
        }

        let parent = signed.parent_revision().map(|id| id.0.to_vec());
        transaction.execute(
            "INSERT INTO locked_inbox
             (message_id, vault_id, sender_id, revision_id, parent_revision, key_epoch,
              frame, received_at, status, applied_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                message_id.0.as_slice(),
                signed.vault_id().0.as_slice(),
                signed.sender().0.as_slice(),
                signed.revision_id().0.as_slice(),
                parent,
                key_epoch,
                frame,
                received_at,
                status
            ],
        )?;
        transaction.commit()?;
        Ok(ReceiveOutcome::Inserted {
            message_id,
            disposition: if status == STATUS_RECEIVED {
                InboxDisposition::Received
            } else {
                InboxDisposition::QuarantinedOldEpoch
            },
        })
    }

    pub fn status(&self, message_id: MessageId) -> Result<Option<InboxStatus>> {
        self.connection
            .query_row(
                "SELECT status FROM locked_inbox WHERE message_id = ?1",
                [message_id.0.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(decode_status)
            .transpose()
    }

    /// Applies pending encrypted revisions after unlock.
    ///
    /// The callback should call vault-core's idempotent encrypted-revision apply operation.
    /// A process crash after that callback commits but before this queue marks the item applied
    /// can cause one retry; revision IDs make that retry safe. Callback errors leave the item in
    /// `Received` for a later attempt. The method continues through the batch so a child that
    /// arrived before its parent cannot block the parent forever; `ApplyReport::deferred` records
    /// those entries. If every callback fails, the first callback error is returned.
    pub fn apply_pending<E>(
        &mut self,
        vault_id: VaultId,
        minimum_epoch: u64,
        limit: usize,
        applied_at: u64,
        mut apply: impl FnMut(&SignedRevision) -> std::result::Result<(), E>,
    ) -> std::result::Result<ApplyReport, ApplyError<E>> {
        if limit == 0 {
            return Ok(ApplyReport::default());
        }
        let applied_at = sql_i64(applied_at).map_err(ApplyError::Store)?;
        let mut report = ApplyReport::default();
        let mut first_callback_error = None;
        let mut cursor: Option<(i64, i64)> = None;

        while report.applied + report.quarantined_old_epoch < limit {
            let batch = self
                .load_pending_batch(vault_id, cursor, APPLY_BATCH_SIZE)
                .map_err(ApplyError::Store)?;
            if batch.is_empty() {
                break;
            }
            for (received_at, rowid, message_id) in batch {
                cursor = Some((received_at, rowid));
                if report.applied + report.quarantined_old_epoch >= limit {
                    break;
                }
                let (frame, sender) = self.load_frame(message_id).map_err(ApplyError::Store)?;
                let signed = SignedRevision::verify_and_decode(&frame, sender, self.limits)
                    .map_err(ApplyError::Store)?;
                if signed.message_id() != message_id || signed.vault_id() != vault_id {
                    return Err(ApplyError::Store(Error::InvalidFrame));
                }
                if signed.key_epoch() < minimum_epoch {
                    self.connection
                        .execute(
                            "UPDATE locked_inbox SET status = ?1
                             WHERE message_id = ?2 AND status = ?3",
                            params![
                                STATUS_QUARANTINED_OLD_EPOCH,
                                message_id.0.as_slice(),
                                STATUS_RECEIVED
                            ],
                        )
                        .map_err(Error::from)
                        .map_err(ApplyError::Store)?;
                    report.quarantined_old_epoch += 1;
                    continue;
                }

                if let Err(source) = apply(&signed) {
                    report.deferred += 1;
                    if first_callback_error.is_none() {
                        first_callback_error = Some((source, report.applied));
                    }
                    continue;
                }
                self.connection
                    .execute(
                        "UPDATE locked_inbox SET status = ?1, applied_at = ?2
                         WHERE message_id = ?3 AND status = ?4",
                        params![
                            STATUS_APPLIED,
                            applied_at,
                            message_id.0.as_slice(),
                            STATUS_RECEIVED
                        ],
                    )
                    .map_err(Error::from)
                    .map_err(ApplyError::Store)?;
                report.applied += 1;
            }
        }
        if report.applied == 0 {
            if let Some((source, applied_before_failure)) = first_callback_error {
                return Err(ApplyError::Callback {
                    source,
                    applied_before_failure,
                });
            }
        }
        Ok(report)
    }

    fn load_pending_batch(
        &self,
        vault_id: VaultId,
        after: Option<(i64, i64)>,
        limit: i64,
    ) -> Result<Vec<(i64, i64, MessageId)>> {
        let mut ids = Vec::new();
        match after {
            None => {
                let mut statement = self.connection.prepare(
                    "SELECT received_at, rowid, message_id FROM locked_inbox
                     WHERE vault_id = ?1 AND status = ?2
                     ORDER BY received_at, rowid LIMIT ?3",
                )?;
                let rows = statement.query_map(
                    params![vault_id.0.as_slice(), STATUS_RECEIVED, limit],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )?;
                for row in rows {
                    let (received_at, rowid, raw) = row?;
                    ids.push((received_at, rowid, MessageId(fixed_32(raw)?)));
                }
            }
            Some((after_received, after_rowid)) => {
                let mut statement = self.connection.prepare(
                    "SELECT received_at, rowid, message_id FROM locked_inbox
                     WHERE vault_id = ?1 AND status = ?2
                       AND (received_at > ?3 OR (received_at = ?3 AND rowid > ?4))
                     ORDER BY received_at, rowid LIMIT ?5",
                )?;
                let rows = statement.query_map(
                    params![
                        vault_id.0.as_slice(),
                        STATUS_RECEIVED,
                        after_received,
                        after_rowid,
                        limit
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )?;
                for row in rows {
                    let (received_at, rowid, raw) = row?;
                    ids.push((received_at, rowid, MessageId(fixed_32(raw)?)));
                }
            }
        }
        Ok(ids)
    }

    fn load_frame(&self, message_id: MessageId) -> Result<(Vec<u8>, DeviceId)> {
        let (frame, sender) = self.connection.query_row(
            "SELECT frame, sender_id FROM locked_inbox WHERE message_id = ?1 AND status = ?2",
            params![message_id.0.as_slice(), STATUS_RECEIVED],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        Ok((frame, DeviceId(fixed_32(sender)?)))
    }
}

fn decode_status(status: i64) -> Result<InboxStatus> {
    match status {
        STATUS_RECEIVED => Ok(InboxStatus::Received),
        STATUS_APPLIED => Ok(InboxStatus::Applied),
        STATUS_QUARANTINED_OLD_EPOCH => Ok(InboxStatus::QuarantinedOldEpoch),
        _ => Err(Error::InvalidFrame),
    }
}

fn sql_i64(value: u64) -> Result<i64> {
    value.try_into().map_err(|_| Error::TimeOutOfRange)
}

fn fixed_32(value: Vec<u8>) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| Error::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{RevisionId, WireRevision};

    fn frame(epoch: u64) -> (Vec<u8>, DeviceId, MessageId) {
        let signed = SignedRevision::sign(
            WireRevision {
                vault_id: VaultId([1; 32]),
                revision_id: RevisionId([2; 32]),
                parent_revision: None,
                key_epoch: epoch,
                ciphertext: b"encrypted".to_vec(),
            },
            &SigningKey::from_bytes(&[8; 32]),
            ProtocolLimits::default(),
        )
        .unwrap();
        (signed.to_bytes(), signed.sender(), signed.message_id())
    }

    fn revision_frame(revision: [u8; 32], parent: Option<[u8; 32]>) -> (Vec<u8>, DeviceId) {
        let signed = SignedRevision::sign(
            WireRevision {
                vault_id: VaultId([1; 32]),
                revision_id: RevisionId(revision),
                parent_revision: parent.map(RevisionId),
                key_epoch: 3,
                ciphertext: b"encrypted".to_vec(),
            },
            &SigningKey::from_bytes(&[8; 32]),
            ProtocolLimits::default(),
        )
        .unwrap();
        (signed.to_bytes(), signed.sender())
    }

    #[test]
    fn persists_dedup_and_applied_status_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inbox.sqlite");
        let (frame, sender, id) = frame(3);
        let vault = VaultId([1; 32]);
        {
            let mut inbox = LockedInbox::open(&path, ProtocolLimits::default()).unwrap();
            let inserted = inbox
                .receive_verified(vault, &frame, sender, 3, 10)
                .unwrap();
            assert!(matches!(inserted, ReceiveOutcome::Inserted { .. }));
            let duplicate = inbox
                .receive_verified(vault, &frame, sender, 3, 11)
                .unwrap();
            assert!(matches!(duplicate, ReceiveOutcome::Duplicate { .. }));
        }
        let mut inbox = LockedInbox::open(&path, ProtocolLimits::default()).unwrap();
        let mut applied = Vec::new();
        let report = inbox
            .apply_pending(vault, 3, 10, 20, |revision| {
                applied.push(revision.revision_id());
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(applied, vec![RevisionId([2; 32])]);
        assert_eq!(inbox.status(id).unwrap(), Some(InboxStatus::Applied));
    }

    #[test]
    fn old_epoch_is_quarantined_without_calling_apply() {
        let (frame, sender, id) = frame(2);
        let vault = VaultId([1; 32]);
        let mut inbox = LockedInbox::open_in_memory(ProtocolLimits::default()).unwrap();
        let outcome = inbox
            .receive_verified(vault, &frame, sender, 3, 10)
            .unwrap();
        assert!(matches!(
            outcome,
            ReceiveOutcome::Inserted {
                disposition: InboxDisposition::QuarantinedOldEpoch,
                ..
            }
        ));
        let report = inbox
            .apply_pending(vault, 3, 10, 20, |_| -> std::result::Result<(), ()> {
                panic!("quarantined revisions must not be applied");
            })
            .unwrap();
        assert_eq!(report.applied, 0);
        assert_eq!(
            inbox.status(id).unwrap(),
            Some(InboxStatus::QuarantinedOldEpoch)
        );
    }

    #[test]
    fn child_received_before_parent_is_deferred_then_applied() {
        let (parent, sender) = revision_frame([2; 32], None);
        let (child, _) = revision_frame([4; 32], Some([2; 32]));
        let vault = VaultId([1; 32]);
        let mut inbox = LockedInbox::open_in_memory(ProtocolLimits::default()).unwrap();
        inbox
            .receive_verified(vault, &child, sender, 3, 10)
            .unwrap();
        inbox
            .receive_verified(vault, &parent, sender, 3, 20)
            .unwrap();
        let mut applied = Vec::new();
        let report = inbox
            .apply_pending(vault, 3, 10, 30, |revision| {
                if let Some(parent) = revision.parent_revision() {
                    if !applied.contains(&parent) {
                        return Err("parent missing");
                    }
                }
                applied.push(revision.revision_id());
                Ok::<_, &str>(())
            })
            .unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(report.deferred, 1);
        let report = inbox
            .apply_pending(vault, 3, 10, 31, |revision| {
                applied.push(revision.revision_id());
                Ok::<_, &str>(())
            })
            .unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(applied.len(), 2);
    }

    #[test]
    fn rejects_wrong_vault_enforces_queue_cap_and_avoids_hol_starvation() {
        let vault = VaultId([1; 32]);
        let other_vault = VaultId([9; 32]);
        let (parent, sender) = revision_frame([10; 32], None);
        let mut inbox = LockedInbox::open_in_memory(ProtocolLimits::default())
            .unwrap()
            .with_queue_limits(3, 10_000);
        // Wrong vault rejected immediately.
        assert!(matches!(
            inbox.receive_verified(other_vault, &parent, sender, 3, 1),
            Err(Error::VaultMismatch)
        ));
        // Two deferred orphans followed by their parent, applied with limit = 1
        // must still reach the parent beyond the deferred prefix.
        let (orphan1, _) = revision_frame([11; 32], Some([10; 32]));
        let (orphan2, _) = revision_frame([12; 32], Some([10; 32]));
        let (extra, _) = revision_frame([13; 32], None);
        inbox
            .receive_verified(vault, &orphan1, sender, 3, 1)
            .unwrap();
        inbox
            .receive_verified(vault, &orphan2, sender, 3, 2)
            .unwrap();
        inbox
            .receive_verified(vault, &parent, sender, 3, 3)
            .unwrap();
        // 4th message exceeds queue cap of 3.
        assert!(matches!(
            inbox.receive_verified(vault, &extra, sender, 3, 4),
            Err(Error::InboxFull)
        ));
        let mut applied = Vec::new();
        let report = inbox
            .apply_pending(vault, 3, 1, 10, |revision| {
                if let Some(p) = revision.parent_revision() {
                    if !applied.contains(&p) {
                        return Err("missing parent");
                    }
                }
                applied.push(revision.revision_id());
                Ok::<_, &str>(())
            })
            .unwrap();
        assert_eq!(report.applied, 1);
        assert_eq!(report.deferred, 2);
        assert_eq!(applied, vec![RevisionId([10; 32])]);
    }
}
