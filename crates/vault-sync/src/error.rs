use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors deliberately omit tokens, plaintext, ciphertext, and key material.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid protocol frame")]
    InvalidFrame,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("protocol frame exceeds the configured size limit")]
    FrameTooLarge,
    #[error("the sender does not match the pinned peer identity")]
    SenderIdentityMismatch,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("HPKE operation failed")]
    Hpke,
    #[error("randomness source failed")]
    Randomness,
    #[error("invalid invitation")]
    InvalidInvitation,
    #[error("invitation recipient does not match")]
    InvitationRecipientMismatch,
    #[error("invitation has expired")]
    InvitationExpired,
    #[error("invitation has already been used")]
    InvitationReplay,
    #[error("invitation expiry is outside policy")]
    InvitationExpiryPolicy,
    #[error("time value is out of range")]
    TimeOutOfRange,
    #[error("a revision identifier was reused with different signed content")]
    RevisionCollision,
    #[error("invalid membership transition")]
    InvalidMembershipTransition,
    #[error("consensus position did not advance")]
    StaleConsensusPosition,
    #[error("rotation recipient keys do not exactly match the next membership")]
    RotationRecipientMismatch,
    #[error("rotation epoch must advance by exactly one")]
    InvalidRotationEpoch,
    #[error("database operation failed")]
    Database(#[from] rusqlite::Error),
}
