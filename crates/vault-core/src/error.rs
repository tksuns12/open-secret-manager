use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("vault is locked")]
    Locked,
    #[error("vault is already unlocked")]
    AlreadyUnlocked,
    #[error("the password or recovery key is invalid")]
    InvalidCredentials,
    #[error("invalid recovery key")]
    InvalidRecoveryKey,
    #[error("vault item not found")]
    NotFound,
    #[error("item already exists")]
    AlreadyExists,
    #[error("revision conflict (expected {expected}, actual {actual})")]
    Conflict { expected: String, actual: String },
    #[error("revision author is not an authorized device")]
    UnknownAuthor,
    #[error("revision signature is invalid")]
    InvalidSignature,
    #[error("invalid item: {0}")]
    InvalidItem(String),
    #[error("invalid import: {0}")]
    InvalidImport(String),
    #[error("invalid backup: {0}")]
    InvalidBackup(String),
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("vault database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
}
