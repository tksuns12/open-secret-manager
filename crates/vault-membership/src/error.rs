use openraft::{error::Fatal, StorageError};

use crate::DeviceId;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("control-plane storage: {0}")]
    Storage(#[from] StorageError<DeviceId>),
    #[error("consensus stopped: {0}")]
    Fatal(#[from] Fatal<DeviceId>),
    #[error("this device is not the leader")]
    NotLeader(Option<DeviceId>),
    /// Not enough voters are reachable to commit. Never bypassed.
    #[error("not enough devices are reachable to commit this change")]
    QuorumUnavailable,
    #[error("consensus: {0}")]
    Raft(String),
}
