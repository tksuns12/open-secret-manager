use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors omit tokens, keys, and plaintext.
#[derive(Debug, Error)]
pub enum Error {
    #[error("vault: {0}")]
    Vault(#[from] osm_vault_core::Error),
    #[error("sync primitive: {0}")]
    Sync(#[from] osm_vault_sync::Error),
    /// Boxed: OpenRaft's storage errors are large.
    #[error("membership: {0}")]
    Membership(Box<osm_vault_membership::Error>),
    #[error("the vault's devices refused the request: {0:?}")]
    Rejected(osm_vault_membership::Rejection),
    #[error("this device is not yet an enrolled member holding the vault's keys")]
    EnrollmentPending,
    #[error("an epoch key does not match the key committed for that epoch")]
    EpochKeyMismatch,
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
    #[error("invalid peer address")]
    InvalidAddress,
    #[error("no paired device")]
    NotPaired,
    #[error("the peer's TLS certificate does not match its pin")]
    PinMismatch,
    #[error("TLS handshake failed")]
    Handshake,
    #[error("the connection closed unexpectedly")]
    ConnectionClosed,
    #[error("the peer did not respond in time")]
    Timeout,
    #[error("network: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport: {0}")]
    Transport(&'static str),
}

impl From<osm_vault_membership::Error> for Error {
    fn from(error: osm_vault_membership::Error) -> Self {
        Self::Membership(Box::new(error))
    }
}
