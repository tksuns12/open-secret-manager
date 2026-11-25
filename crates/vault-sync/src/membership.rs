use std::{collections::BTreeSet, path::Path};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::{DeviceId, EpochKeyEnvelope, Error, Result, VaultId};

const ROTATION_STAGED: i64 = 0;
const ROTATION_JOINT_COMMITTED: i64 = 1;
const ROTATION_ACTIVATED: i64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsensusPosition {
    pub term: u64,
    pub index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipPhase {
    Joint {
        old_members: BTreeSet<DeviceId>,
        new_members: BTreeSet<DeviceId>,
        new_epoch: u64,
    },
    Uniform {
        members: BTreeSet<DeviceId>,
        epoch: u64,
    },
}

/// A membership entry that an external OpenRaft adapter has already observed as committed.
///
/// Constructing this value is not proof of consensus. The transport/integration layer must
/// create it only from the persistent OpenRaft state machine's apply callback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedMembership {
    pub vault_id: VaultId,
    pub position: ConsensusPosition,
    pub phase: MembershipPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationState {
    Staged,
    JointCommitted,
    Activated,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StagedRecipientKey {
    pub recipient: DeviceId,
    pub envelope: EpochKeyEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationPlan {
    pub vault_id: VaultId,
    pub new_epoch: u64,
    pub old_members: BTreeSet<DeviceId>,
    pub new_members: BTreeSet<DeviceId>,
    pub state: RotationState,
}

/// Persistent rotation state consumed by, but deliberately independent from, OpenRaft.
///
/// It stages HPKE envelopes before proposing a membership change, records the committed joint
/// phase, and releases the new epoch envelopes only after the uniform membership is committed.
pub struct MembershipStore {
    connection: Connection,
}

impl MembershipStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS membership_state (
                 vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 32),
                 current_epoch INTEGER NOT NULL CHECK(current_epoch >= 0),
                 members BLOB NOT NULL,
                 committed_term INTEGER,
                 committed_index INTEGER
             ) STRICT;
             CREATE TABLE IF NOT EXISTS rotation_plan (
                 vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 32),
                 new_epoch INTEGER NOT NULL CHECK(new_epoch >= 0),
                 old_members BLOB NOT NULL,
                 new_members BLOB NOT NULL,
                 state INTEGER NOT NULL CHECK(state IN (0, 1, 2))
             ) STRICT;
             CREATE TABLE IF NOT EXISTS rotation_recipient_keys (
                 vault_id BLOB NOT NULL CHECK(length(vault_id) = 32),
                 new_epoch INTEGER NOT NULL CHECK(new_epoch >= 0),
                 recipient BLOB NOT NULL CHECK(length(recipient) = 32),
                 envelope BLOB NOT NULL,
                 PRIMARY KEY(vault_id, new_epoch, recipient)
             ) STRICT;",
        )?;
        Ok(Self { connection })
    }

    /// Bootstraps the local state once from the consensus cluster's initial membership.
    pub fn initialize(
        &mut self,
        vault_id: VaultId,
        epoch: u64,
        members: BTreeSet<DeviceId>,
    ) -> Result<()> {
        if epoch == 0 {
            return Err(Error::InvalidRotationEpoch);
        }
        if members.is_empty() {
            return Err(Error::InvalidMembershipTransition);
        }
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO membership_state
             (vault_id, current_epoch, members, committed_term, committed_index)
             VALUES (?1, ?2, ?3, NULL, NULL)",
            params![
                vault_id.0.as_slice(),
                sql_i64(epoch)?,
                encode_members(&members)
            ],
        )?;
        if changed != 1 {
            return Err(Error::InvalidMembershipTransition);
        }
        Ok(())
    }

    /// Persists the next epoch's recipient envelopes without making them deliverable.
    ///
    /// There must be exactly one authenticated HPKE envelope for each next member and none for
    /// a removed member. Existing activated plan data is replaced when staging the next epoch.
    pub fn stage_rotation(
        &mut self,
        vault_id: VaultId,
        new_epoch: u64,
        new_members: BTreeSet<DeviceId>,
        recipient_keys: Vec<StagedRecipientKey>,
    ) -> Result<()> {
        if new_members.is_empty() {
            return Err(Error::InvalidMembershipTransition);
        }
        let supplied: BTreeSet<_> = recipient_keys.iter().map(|key| key.recipient).collect();
        if supplied != new_members || supplied.len() != recipient_keys.len() {
            return Err(Error::RotationRecipientMismatch);
        }
        for key in &recipient_keys {
            if key.envelope.vault_id() != vault_id
                || key.envelope.epoch() != new_epoch
                || key.envelope.recipient() != key.recipient
            {
                return Err(Error::RotationRecipientMismatch);
            }
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_membership(&transaction, vault_id)?;
        if new_epoch
            != current
                .epoch
                .checked_add(1)
                .ok_or(Error::InvalidRotationEpoch)?
        {
            return Err(Error::InvalidRotationEpoch);
        }
        let existing_state = transaction
            .query_row(
                "SELECT state FROM rotation_plan WHERE vault_id = ?1",
                [vault_id.0.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if existing_state.is_some_and(|state| state != ROTATION_ACTIVATED) {
            return Err(Error::InvalidMembershipTransition);
        }
        transaction.execute(
            "DELETE FROM rotation_recipient_keys WHERE vault_id = ?1",
            [vault_id.0.as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO rotation_plan (vault_id, new_epoch, old_members, new_members, state)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(vault_id) DO UPDATE SET
               new_epoch=excluded.new_epoch,
               old_members=excluded.old_members,
               new_members=excluded.new_members,
               state=excluded.state",
            params![
                vault_id.0.as_slice(),
                sql_i64(new_epoch)?,
                encode_members(&current.members),
                encode_members(&new_members),
                ROTATION_STAGED
            ],
        )?;
        for key in recipient_keys {
            transaction.execute(
                "INSERT INTO rotation_recipient_keys
                 (vault_id, new_epoch, recipient, envelope) VALUES (?1, ?2, ?3, ?4)",
                params![
                    vault_id.0.as_slice(),
                    sql_i64(new_epoch)?,
                    key.recipient.0.as_slice(),
                    key.envelope.to_bytes().as_slice()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Aborts a rotation that was staged locally before consensus committed
    /// its joint configuration. Committed (`JointCommitted`) and `Activated`
    /// rotations cannot be aborted.
    pub fn abort_staged_rotation(&mut self, vault_id: VaultId) -> Result<bool> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing_state = transaction
            .query_row(
                "SELECT state FROM rotation_plan WHERE vault_id = ?1",
                [vault_id.0.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        match existing_state {
            None => Ok(false),
            Some(ROTATION_STAGED) => {
                transaction.execute(
                    "DELETE FROM rotation_recipient_keys WHERE vault_id = ?1",
                    [vault_id.0.as_slice()],
                )?;
                transaction.execute(
                    "DELETE FROM rotation_plan WHERE vault_id = ?1",
                    [vault_id.0.as_slice()],
                )?;
                transaction.commit()?;
                Ok(true)
            }
            Some(_) => Err(Error::InvalidMembershipTransition),
        }
    }

    /// Applies an already committed membership entry in monotonically increasing log order.
    pub fn apply_committed(&mut self, committed: CommittedMembership) -> Result<RotationState> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_membership(&transaction, committed.vault_id)?;
        validate_position(
            committed.position,
            current.committed_term,
            current.committed_index,
        )?;
        let plan = load_plan(&transaction, committed.vault_id)?;

        let next_state = match &committed.phase {
            MembershipPhase::Joint {
                old_members,
                new_members,
                new_epoch,
            } => {
                if plan.state != RotationState::Staged
                    || *old_members != current.members
                    || *old_members != plan.old_members
                    || *new_members != plan.new_members
                    || *new_epoch != plan.new_epoch
                {
                    return Err(Error::InvalidMembershipTransition);
                }
                transaction.execute(
                    "UPDATE rotation_plan SET state = ?1 WHERE vault_id = ?2",
                    params![ROTATION_JOINT_COMMITTED, committed.vault_id.0.as_slice()],
                )?;
                RotationState::JointCommitted
            }
            MembershipPhase::Uniform { members, epoch } => {
                if plan.state != RotationState::JointCommitted
                    || *members != plan.new_members
                    || *epoch != plan.new_epoch
                {
                    return Err(Error::InvalidMembershipTransition);
                }
                transaction.execute(
                    "UPDATE membership_state SET current_epoch = ?1, members = ?2
                     WHERE vault_id = ?3",
                    params![
                        sql_i64(*epoch)?,
                        encode_members(members),
                        committed.vault_id.0.as_slice()
                    ],
                )?;
                transaction.execute(
                    "UPDATE rotation_plan SET state = ?1 WHERE vault_id = ?2",
                    params![ROTATION_ACTIVATED, committed.vault_id.0.as_slice()],
                )?;
                RotationState::Activated
            }
        };
        transaction.execute(
            "UPDATE membership_state SET committed_term = ?1, committed_index = ?2
             WHERE vault_id = ?3",
            params![
                sql_i64(committed.position.term)?,
                sql_i64(committed.position.index)?,
                committed.vault_id.0.as_slice()
            ],
        )?;
        transaction.commit()?;
        Ok(next_state)
    }

    pub fn rotation_plan(&self, vault_id: VaultId) -> Result<Option<RotationPlan>> {
        load_plan(&self.connection, vault_id).optional_plan()
    }

    /// Returns an epoch key envelope only after the final uniform membership commit.
    pub fn activated_recipient_key(
        &self,
        vault_id: VaultId,
        epoch: u64,
        recipient: DeviceId,
    ) -> Result<Option<EpochKeyEnvelope>> {
        let plan = match self.rotation_plan(vault_id)? {
            Some(plan) if plan.state == RotationState::Activated && plan.new_epoch == epoch => plan,
            _ => return Ok(None),
        };
        if !plan.new_members.contains(&recipient) {
            return Ok(None);
        }
        let bytes = self
            .connection
            .query_row(
                "SELECT envelope FROM rotation_recipient_keys
                 WHERE vault_id = ?1 AND new_epoch = ?2 AND recipient = ?3",
                params![
                    vault_id.0.as_slice(),
                    sql_i64(epoch)?,
                    recipient.0.as_slice()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        bytes
            .map(|bytes| EpochKeyEnvelope::from_bytes(&bytes))
            .transpose()
    }
}

trait OptionalPlan {
    fn optional_plan(self) -> Result<Option<RotationPlan>>;
}

impl OptionalPlan for Result<RotationPlan> {
    fn optional_plan(self) -> Result<Option<RotationPlan>> {
        match self {
            Ok(plan) => Ok(Some(plan)),
            Err(Error::Database(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

struct LoadedMembership {
    epoch: u64,
    members: BTreeSet<DeviceId>,
    committed_term: Option<u64>,
    committed_index: Option<u64>,
}

fn load_membership(connection: &Connection, vault_id: VaultId) -> Result<LoadedMembership> {
    let (epoch, members, term, index) = connection.query_row(
        "SELECT current_epoch, members, committed_term, committed_index
         FROM membership_state WHERE vault_id = ?1",
        [vault_id.0.as_slice()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
    )?;
    Ok(LoadedMembership {
        epoch: from_sql_u64(epoch)?,
        members: decode_members(&members)?,
        committed_term: term.map(from_sql_u64).transpose()?,
        committed_index: index.map(from_sql_u64).transpose()?,
    })
}

fn load_plan(connection: &Connection, vault_id: VaultId) -> Result<RotationPlan> {
    let (new_epoch, old_members, new_members, state) = connection.query_row(
        "SELECT new_epoch, old_members, new_members, state
         FROM rotation_plan WHERE vault_id = ?1",
        [vault_id.0.as_slice()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    Ok(RotationPlan {
        vault_id,
        new_epoch: from_sql_u64(new_epoch)?,
        old_members: decode_members(&old_members)?,
        new_members: decode_members(&new_members)?,
        state: match state {
            ROTATION_STAGED => RotationState::Staged,
            ROTATION_JOINT_COMMITTED => RotationState::JointCommitted,
            ROTATION_ACTIVATED => RotationState::Activated,
            _ => return Err(Error::InvalidMembershipTransition),
        },
    })
}

fn validate_position(
    next: ConsensusPosition,
    prior_term: Option<u64>,
    prior_index: Option<u64>,
) -> Result<()> {
    if let (Some(term), Some(index)) = (prior_term, prior_index) {
        if next.index <= index || next.term < term {
            return Err(Error::StaleConsensusPosition);
        }
    }
    Ok(())
}

fn encode_members(members: &BTreeSet<DeviceId>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(members.len() * 32);
    for member in members {
        bytes.extend_from_slice(&member.0);
    }
    bytes
}

fn decode_members(bytes: &[u8]) -> Result<BTreeSet<DeviceId>> {
    if bytes.is_empty() || bytes.len() % 32 != 0 {
        return Err(Error::InvalidMembershipTransition);
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|chunk| DeviceId(chunk.try_into().expect("fixed chunk")))
        .collect())
}

fn sql_i64(value: u64) -> Result<i64> {
    value.try_into().map_err(|_| Error::TimeOutOfRange)
}

fn from_sql_u64(value: i64) -> Result<u64> {
    value.try_into().map_err(|_| Error::TimeOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seal_epoch_key, HpkeKeyPair};

    fn set(ids: &[[u8; 32]]) -> BTreeSet<DeviceId> {
        ids.iter().copied().map(DeviceId).collect()
    }

    #[test]
    fn only_committed_joint_then_uniform_releases_new_epoch_keys() {
        let vault = VaultId([9; 32]);
        let owner = DeviceId([1; 32]);
        let removed = DeviceId([2; 32]);
        let added = DeviceId([3; 32]);
        let next = set(&[owner.0, added.0]);
        let owner_hpke = HpkeKeyPair::generate().unwrap();
        let added_hpke = HpkeKeyPair::generate().unwrap();
        let keys = vec![
            StagedRecipientKey {
                recipient: owner,
                envelope: seal_epoch_key(vault, 2, owner, owner_hpke.public(), &[7; 32]).unwrap(),
            },
            StagedRecipientKey {
                recipient: added,
                envelope: seal_epoch_key(vault, 2, added, added_hpke.public(), &[7; 32]).unwrap(),
            },
        ];
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("membership.sqlite");
        let mut store = MembershipStore::open(&path).unwrap();
        let old = set(&[owner.0, removed.0]);
        store.initialize(vault, 1, old.clone()).unwrap();
        store.stage_rotation(vault, 2, next.clone(), keys).unwrap();
        assert!(store
            .activated_recipient_key(vault, 2, owner)
            .unwrap()
            .is_none());
        drop(store);

        let joint = CommittedMembership {
            vault_id: vault,
            position: ConsensusPosition { term: 4, index: 10 },
            phase: MembershipPhase::Joint {
                old_members: old,
                new_members: next.clone(),
                new_epoch: 2,
            },
        };
        let mut store = MembershipStore::open(&path).unwrap();
        assert_eq!(
            store.apply_committed(joint).unwrap(),
            RotationState::JointCommitted
        );
        assert!(store
            .activated_recipient_key(vault, 2, owner)
            .unwrap()
            .is_none());
        drop(store);

        let uniform = CommittedMembership {
            vault_id: vault,
            position: ConsensusPosition { term: 4, index: 11 },
            phase: MembershipPhase::Uniform {
                members: next,
                epoch: 2,
            },
        };
        let mut store = MembershipStore::open(&path).unwrap();
        assert_eq!(
            store.apply_committed(uniform).unwrap(),
            RotationState::Activated
        );
        assert!(store
            .activated_recipient_key(vault, 2, owner)
            .unwrap()
            .is_some());
        assert!(store
            .activated_recipient_key(vault, 2, removed)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_uniform_commit_without_joint_phase() {
        let vault = VaultId([9; 32]);
        let owner = DeviceId([1; 32]);
        let pair = HpkeKeyPair::generate().unwrap();
        let members = set(&[owner.0]);
        let mut store = MembershipStore::open_in_memory().unwrap();
        store.initialize(vault, 1, members.clone()).unwrap();
        store
            .stage_rotation(
                vault,
                2,
                members.clone(),
                vec![StagedRecipientKey {
                    recipient: owner,
                    envelope: seal_epoch_key(vault, 2, owner, pair.public(), &[5; 32]).unwrap(),
                }],
            )
            .unwrap();
        let result = store.apply_committed(CommittedMembership {
            vault_id: vault,
            position: ConsensusPosition { term: 1, index: 1 },
            phase: MembershipPhase::Uniform { members, epoch: 2 },
        });
        assert!(matches!(result, Err(Error::InvalidMembershipTransition)));
    }

    #[test]
    fn staged_rotation_can_be_aborted_but_committed_cannot_and_epoch_zero_refused() {
        let vault = VaultId([9; 32]);
        let owner = DeviceId([1; 32]);
        let pair = HpkeKeyPair::generate().unwrap();
        let members = set(&[owner.0]);
        let mut store = MembershipStore::open_in_memory().unwrap();
        assert!(matches!(
            store.initialize(vault, 0, members.clone()),
            Err(Error::InvalidRotationEpoch)
        ));
        store.initialize(vault, 1, members.clone()).unwrap();
        assert!(!store.abort_staged_rotation(vault).unwrap());
        let env = seal_epoch_key(vault, 2, owner, pair.public(), &[5; 32]).unwrap();
        store
            .stage_rotation(
                vault,
                2,
                members.clone(),
                vec![StagedRecipientKey {
                    recipient: owner,
                    envelope: env.clone(),
                }],
            )
            .unwrap();
        // Aborting unblocks re-staging epoch 2.
        assert!(store.abort_staged_rotation(vault).unwrap());
        assert!(store.rotation_plan(vault).unwrap().is_none());
        store
            .stage_rotation(
                vault,
                2,
                members.clone(),
                vec![StagedRecipientKey {
                    recipient: owner,
                    envelope: env,
                }],
            )
            .unwrap();
        store
            .apply_committed(CommittedMembership {
                vault_id: vault,
                position: ConsensusPosition { term: 1, index: 1 },
                phase: MembershipPhase::Joint {
                    old_members: members.clone(),
                    new_members: members,
                    new_epoch: 2,
                },
            })
            .unwrap();
        // Once joint-committed, aborting is refused.
        assert!(matches!(
            store.abort_staged_rotation(vault),
            Err(Error::InvalidMembershipTransition)
        ));
    }
}
