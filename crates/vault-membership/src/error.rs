use openraft::{error::Fatal, StorageError};

use crate::DeviceId;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Boxed, as openraft's errors are large and every result carries this.
    #[error("control-plane storage: {0}")]
    Storage(Box<StorageError<DeviceId>>),
    #[error("consensus stopped: {0}")]
    Fatal(Box<Fatal<DeviceId>>),
    #[error("this device is not the leader")]
    NotLeader(Option<DeviceId>),
    /// Not enough voters are reachable to commit. Never bypassed.
    #[error("not enough devices are reachable to commit this change")]
    QuorumUnavailable,
    #[error("consensus: {0}")]
    Raft(String),
}

impl From<StorageError<DeviceId>> for Error {
    fn from(error: StorageError<DeviceId>) -> Self {
        Error::Storage(Box::new(error))
    }
}

impl From<Fatal<DeviceId>> for Error {
    fn from(error: Fatal<DeviceId>) -> Self {
        Error::Fatal(Box::new(error))
    }
}
