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
    #[error("item has concurrent revisions; resolve them before editing")]
    Unresolved,
    #[error("revision parent is not stored yet")]
    MissingParent,
    #[error("revision parent belongs to a different item")]
    InvalidParent,
    #[error("revision author is not an authorized device")]
    UnknownAuthor,
    #[error("revision signature is invalid")]
    InvalidSignature,
    #[error("revision from an unauthorized device was quarantined for owner review")]
    Quarantined,
    #[error("recovery is not enabled on this device; enter the recovery key to enable it")]
    RecoveryNotEnabled,
    #[error("unlock with the password once to upgrade this vault")]
    UpgradeRequiresPassword,
    #[error("this device does not have the key for that epoch yet")]
    MissingEpochKey,
    #[error("quarantine is full; review or discard held revisions")]
    QuarantineFull,
    #[error("too many received revisions are waiting; unlock to process them")]
    IngressFull,
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
