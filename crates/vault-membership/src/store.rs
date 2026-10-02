//! SQLite storage for the Raft log, vote, and control state machine.
//!
//! Every write is one transaction with `synchronous = FULL`, and the log
//! flush callback runs only after commit, so OpenRaft never acknowledges an
//! entry that is not on disk. The state machine persists its state in the
//! same transaction that records the applied log ID.

// OpenRaft's storage traits fix the error type, which is large.
#![allow(clippy::result_large_err)]

use std::{
    fmt::Debug,
    io::Cursor,
    ops::{Bound, RangeBounds},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use openraft::{
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
    Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader, RaftSnapshotBuilder,
    Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::watch;

use crate::{
    ControlConfig, ControlEntry, ControlRequest, ControlState, DeviceId, DeviceNode, Outcome,
};

type Result<T> = std::result::Result<T, StorageError<DeviceId>>;

/// The layout of the control-plane database: the tables below, with every
/// value but the snapshot's data as JSON text.
const STORE_VERSION: u32 = 1;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
CREATE TABLE IF NOT EXISTS raft_vote (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    vote TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS raft_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    committed TEXT,
    purged TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS raft_log (
    idx INTEGER PRIMARY KEY CHECK(idx >= 0),
    entry TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS control_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    state TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS control_snapshot (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    meta TEXT NOT NULL,
    data BLOB NOT NULL
) STRICT;
";

/// Where a test can make a node fail after a write has reached disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// After a joint membership entry is appended to the log.
    AppendJoint,
    /// After a uniform membership entry is appended to the log.
    AppendUniform,
    /// After a committed joint membership entry is applied.
    ApplyJoint,
    /// After a committed uniform membership entry is applied.
    ApplyUniform,
    /// After a membership proposal is applied.
    ApplyProposal,
}

/// A one-shot failure injected into a node's storage. The write completes,
/// then the call fails, which makes OpenRaft stop the node as if it had
/// crashed. For testing only.
#[derive(Clone, Default)]
pub struct CrashPlan {
    armed: Arc<Mutex<Option<CrashPoint>>>,
    fired: Arc<AtomicBool>,
}

impl CrashPlan {
    /// Arms the plan. Every node holding a clone shares it, and it fires on
    /// the first one to reach `point`.
    pub fn arm(&self, point: CrashPoint) {
        if let Ok(mut armed) = self.armed.lock() {
            *armed = Some(point);
        }
    }

    /// Whether the armed crash has happened; it fires at most once.
    pub fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }

    fn trigger(&self, reached: CrashPoint) -> bool {
        let Ok(mut armed) = self.armed.lock() else {
            return false;
        };
        if *armed == Some(reached) {
            *armed = None;
            self.fired.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }
}

fn membership_point(
    entry: &Entry<ControlConfig>,
    joint: CrashPoint,
    uniform: CrashPoint,
) -> Option<CrashPoint> {
    match &entry.payload {
        EntryPayload::Membership(membership) if membership.get_joint_config().len() > 1 => {
            Some(joint)
        }
        EntryPayload::Membership(_) => Some(uniform),
        _ => None,
    }
}

fn crashed() -> StorageError<DeviceId> {
    StorageIOError::write(&std::io::Error::other("injected crash")).into()
}

fn read_error(error: impl std::error::Error + 'static) -> StorageError<DeviceId> {
    StorageIOError::read(&error).into()
}

fn write_error(error: impl std::error::Error + 'static) -> StorageError<DeviceId> {
    StorageIOError::write(&error).into()
}

fn to_json(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(write_error)
}

fn from_json<T: DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(read_error)
}

fn wrong_vault() -> StorageError<DeviceId> {
    read_error(std::io::Error::other(
        "the control-plane database belongs to another vault",
    ))
}

/// Opens (or creates) a node's control-plane database for `vault_id`.
pub fn open(
    path: impl AsRef<Path>,
    vault_id: [u8; 32],
    crash: CrashPlan,
) -> Result<(LogStore, StateMachineStore)> {
    let connection = Connection::open(path).map_err(read_error)?;
    osm_vault_sync::claim_store_version(&connection, STORE_VERSION).map_err(read_error)?;
    connection.execute_batch(SCHEMA).map_err(write_error)?;
    let state = match connection
        .query_row(
            "SELECT state FROM control_state WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(read_error)?
    {
        Some(text) => from_json::<ControlState>(&text)?,
        None => ControlState::new(vault_id),
    };
    if state.vault_id != vault_id {
        return Err(wrong_vault());
    }
    let (applied, _) = watch::channel(state.last_applied);
    let db = Arc::new(Mutex::new(connection));
    Ok((
        LogStore {
            db: db.clone(),
            crash: crash.clone(),
        },
        StateMachineStore {
            db,
            state: Arc::new(Mutex::new(state)),
            applied: Arc::new(applied),
            crash,
        },
    ))
}

fn lock(db: &Mutex<Connection>) -> Result<std::sync::MutexGuard<'_, Connection>> {
    db.lock()
        .map_err(|_| write_error(std::io::Error::other("storage lock poisoned")))
}

/// The Raft log and vote. Cloning shares the same database.
#[derive(Clone)]
pub struct LogStore {
    db: Arc<Mutex<Connection>>,
    crash: CrashPlan,
}

impl LogStore {
    fn meta<T: DeserializeOwned>(&self, column: &str) -> Result<Option<T>> {
        let db = lock(&self.db)?;
        let text: Option<String> = db
            .query_row(
                &format!("SELECT {column} FROM raft_meta WHERE singleton = 1"),
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(read_error)?
            .flatten();
        text.map(|text| from_json(&text)).transpose()
    }

    fn set_meta(&self, column: &str, value: &impl Serialize) -> Result<()> {
        let text = to_json(value)?;
        let db = lock(&self.db)?;
        db.execute(
            &format!(
                "INSERT INTO raft_meta(singleton, {column}) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET {column} = excluded.{column}"
            ),
            [text],
        )
        .map_err(write_error)?;
        Ok(())
    }
}

impl RaftLogReader<ControlConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<ControlConfig>>> {
        let start = match range.start_bound() {
            Bound::Included(start) => *start,
            Bound::Excluded(start) => start.saturating_add(1),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(end) => end.saturating_add(1),
            Bound::Excluded(end) => *end,
            Bound::Unbounded => u64::MAX,
        };
        let db = lock(&self.db)?;
        let mut statement = db
            .prepare("SELECT entry FROM raft_log WHERE idx >= ?1 AND idx < ?2 ORDER BY idx")
            .map_err(read_error)?;
        let rows = statement
            .query_map(
                params![start as i64, end.min(i64::MAX as u64) as i64],
                |row| row.get::<_, String>(0),
            )
            .map_err(read_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(read_error)?;
        rows.iter().map(|text| from_json(text)).collect()
    }
}

impl RaftLogStorage<ControlConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<ControlConfig>> {
        let purged: Option<LogId<DeviceId>> = self.meta("purged")?;
        let last: Option<String> = {
            let db = lock(&self.db)?;
            db.query_row(
                "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(read_error)?
        };
        let last_log_id = match last {
            Some(text) => Some(from_json::<Entry<ControlConfig>>(&text)?.log_id),
            None => purged,
        };
        Ok(LogState {
            last_purged_log_id: purged,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<DeviceId>) -> Result<()> {
        let text = to_json(vote)?;
        let db = lock(&self.db)?;
        db.execute(
            "INSERT INTO raft_vote(singleton, vote) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET vote = excluded.vote",
            [text],
        )
        .map_err(write_error)?;
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<DeviceId>>> {
        let db = lock(&self.db)?;
        let text: Option<String> = db
            .query_row(
                "SELECT vote FROM raft_vote WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(read_error)?;
        text.map(|text| from_json(&text)).transpose()
    }

    async fn save_committed(&mut self, committed: Option<LogId<DeviceId>>) -> Result<()> {
        self.set_meta("committed", &committed)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<DeviceId>>> {
        Ok(self.meta::<Option<LogId<DeviceId>>>("committed")?.flatten())
    }

    async fn append<I>(&mut self, entries: I, callback: LogFlushed<ControlConfig>) -> Result<()>
    where
        I: IntoIterator<Item = Entry<ControlConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut crash = false;
        {
            let mut db = lock(&self.db)?;
            let transaction = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(write_error)?;
            for entry in entries {
                if let Some(point) =
                    membership_point(&entry, CrashPoint::AppendJoint, CrashPoint::AppendUniform)
                {
                    crash |= self.crash.trigger(point);
                }
                transaction
                    .execute(
                        "INSERT OR REPLACE INTO raft_log(idx, entry) VALUES (?1, ?2)",
                        params![entry.log_id.index as i64, to_json(&entry)?],
                    )
                    .map_err(write_error)?;
            }
            transaction.commit().map_err(write_error)?;
        }
        if crash {
            return Err(crashed());
        }
        // Committed with synchronous = FULL: the entries are on disk.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<DeviceId>) -> Result<()> {
        let db = lock(&self.db)?;
        db.execute(
            "DELETE FROM raft_log WHERE idx >= ?1",
            [log_id.index as i64],
        )
        .map_err(write_error)?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<DeviceId>) -> Result<()> {
        // Record the purge point first: a crash between the two steps then
        // leaves entries that are merely redundant, never a hole.
        self.set_meta("purged", &Some(log_id))?;
        let db = lock(&self.db)?;
        db.execute(
            "DELETE FROM raft_log WHERE idx <= ?1",
            [log_id.index as i64],
        )
        .map_err(write_error)?;
        Ok(())
    }
}

/// The control state machine and its snapshot.
#[derive(Clone)]
pub struct StateMachineStore {
    db: Arc<Mutex<Connection>>,
    state: Arc<Mutex<ControlState>>,
    /// The last applied log ID, published after the state is on disk.
    applied: Arc<watch::Sender<Option<LogId<DeviceId>>>>,
    crash: CrashPlan,
}

impl StateMachineStore {
    /// A shared view of the applied state, for reading outside Raft.
    pub fn state_handle(&self) -> Arc<Mutex<ControlState>> {
        self.state.clone()
    }

    /// Changes whenever newly applied state has been persisted.
    pub fn applied_handle(&self) -> watch::Receiver<Option<LogId<DeviceId>>> {
        self.applied.subscribe()
    }

    fn vault_id(&self) -> Result<[u8; 32]> {
        self.state
            .lock()
            .map(|state| state.vault_id)
            .map_err(|_| read_error(std::io::Error::other("state lock poisoned")))
    }

    fn persist(&self, state: &ControlState) -> Result<()> {
        let text = to_json(state)?;
        let db = lock(&self.db)?;
        db.execute(
            "INSERT INTO control_state(singleton, state) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET state = excluded.state",
            [text],
        )
        .map_err(write_error)?;
        Ok(())
    }

    fn snapshot_of(state: &ControlState) -> Result<(SnapshotMeta<DeviceId, DeviceNode>, Vec<u8>)> {
        let data = serde_json::to_vec(state).map_err(write_error)?;
        let snapshot_id = match &state.last_applied {
            Some(log_id) => log_id.to_string(),
            None => "empty".into(),
        };
        Ok((
            SnapshotMeta {
                last_log_id: state.last_applied,
                last_membership: state.membership.clone(),
                snapshot_id,
            },
            data,
        ))
    }
}

pub struct SnapshotBuilder {
    db: Arc<Mutex<Connection>>,
    state: ControlState,
}

impl RaftSnapshotBuilder<ControlConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<ControlConfig>> {
        let (meta, data) = StateMachineStore::snapshot_of(&self.state)?;
        {
            let db = lock(&self.db)?;
            db.execute(
                "INSERT INTO control_snapshot(singleton, meta, data) VALUES (1, ?1, ?2)
                 ON CONFLICT(singleton) DO UPDATE SET meta = excluded.meta, data = excluded.data",
                params![to_json(&meta)?, data],
            )
            .map_err(write_error)?;
        }
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<ControlConfig> for StateMachineStore {
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(
        Option<LogId<DeviceId>>,
        StoredMembership<DeviceId, DeviceNode>,
    )> {
        let state = self
            .state
            .lock()
            .map_err(|_| read_error(std::io::Error::other("state lock poisoned")))?;
        Ok((state.last_applied, state.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Outcome>>
    where
        I: IntoIterator<Item = Entry<ControlConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut crash = false;
        let (outcomes, snapshot) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| write_error(std::io::Error::other("state lock poisoned")))?;
            let mut outcomes = Vec::new();
            for entry in entries {
                if let Some(point) =
                    membership_point(&entry, CrashPoint::ApplyJoint, CrashPoint::ApplyUniform)
                {
                    crash |= self.crash.trigger(point);
                }
                if let EntryPayload::Normal(ControlEntry::Request(request)) = &entry.payload {
                    if matches!(request.request, ControlRequest::ProposeChange(_)) {
                        crash |= self.crash.trigger(CrashPoint::ApplyProposal);
                    }
                }
                outcomes.push(state.apply(entry.log_id, &entry.payload));
            }
            (outcomes, state.clone())
        };
        self.persist(&snapshot)?;
        if crash {
            return Err(crashed());
        }
        self.applied.send_replace(snapshot.last_applied);
        Ok(outcomes)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        let state = self
            .state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default();
        SnapshotBuilder {
            db: self.db.clone(),
            state,
        }
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<DeviceId, DeviceNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<()> {
        let data = snapshot.into_inner();
        let mut installed: ControlState = serde_json::from_slice(&data).map_err(read_error)?;
        if installed.vault_id != self.vault_id()? {
            return Err(wrong_vault());
        }
        installed.last_applied = meta.last_log_id;
        installed.membership = meta.last_membership.clone();
        {
            let db = lock(&self.db)?;
            db.execute(
                "INSERT INTO control_snapshot(singleton, meta, data) VALUES (1, ?1, ?2)
                 ON CONFLICT(singleton) DO UPDATE SET meta = excluded.meta, data = excluded.data",
                params![to_json(meta)?, data],
            )
            .map_err(write_error)?;
        }
        self.persist(&installed)?;
        let applied = installed.last_applied;
        *self
            .state
            .lock()
            .map_err(|_| write_error(std::io::Error::other("state lock poisoned")))? = installed;
        self.applied.send_replace(applied);
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<ControlConfig>>> {
        let db = lock(&self.db)?;
        let row: Option<(String, Vec<u8>)> = db
            .query_row(
                "SELECT meta, data FROM control_snapshot WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(read_error)?;
        row.map(|(meta, data)| {
            Ok(Snapshot {
                meta: from_json(&meta)?,
                snapshot: Box::new(Cursor::new(data)),
            })
        })
        .transpose()
    }
}
