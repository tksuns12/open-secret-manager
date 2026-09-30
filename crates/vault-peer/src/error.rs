use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors omit tokens, keys, and plaintext.
#[derive(Debug, Error)]
pub enum Error {
    #[error("vault: {0}")]
    Vault(#[from] osm_vault_core::Error),
    #[error("sync primitive: {0}")]
    Sync(#[from] osm_vault_sync::Error),
    #[error("peer store: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid invitation code")]
    InvalidInvitation,
    #[error("invitation has expired")]
    InvitationExpired,
    #[error("pairing was not confirmed by the owner")]
    NotConfirmed,
    #[error("message is for a different vault")]
    VaultMismatch,
    #[error("pairing signature is invalid")]
    InvalidSignature,
    #[error("this vault already has a paired device")]
    PeerLimit,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("frame exceeds the size limit")]
    FrameTooLarge,
    #[error("malformed frame")]
    MalformedFrame,
    #[error("peer violated the sync protocol")]
    ProtocolViolation,
    #[error("peer sent a revision that failed validation: {0}")]
    InvalidRevision(osm_vault_core::Error),
}
