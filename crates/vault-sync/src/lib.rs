//! Security-sensitive, transport-independent synchronization primitives.
//!
//! This crate intentionally does not implement discovery, relays, TLS sockets, or a
//! consensus algorithm. The caller owns the direct peer-to-peer transport and must pin
//! the TLS peer to the same [`DeviceId`] passed to envelope verification. Membership
//! changes are only accepted through [`CommittedMembership`], an adapter boundary for
//! entries already committed by a real consensus implementation such as OpenRaft.

mod error;
mod hpke_keys;
mod inbox;
mod invitation;
mod membership;
mod protocol;
mod store_version;

pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use error::{Error, Result};
pub use hpke_keys::{
    open_epoch_key, seal_epoch_key, EpochKeyEnvelope, HpkeKeyPair, HpkePrivateKey, HpkePublicKey,
};
pub use inbox::{
    ApplyError, ApplyReport, InboxDisposition, InboxStatus, LockedInbox, ReceiveOutcome,
};
pub use invitation::{ApprovedInvitation, InvitationPolicy, InvitationStore, InvitationToken};
pub use membership::{
    CommittedMembership, ConsensusPosition, MembershipPhase, MembershipStore, RotationPlan,
    RotationState, StagedRecipientKey,
};
pub use protocol::{
    DeviceId, MessageId, ProtocolLimits, RevisionId, SignedRevision, VaultId, WireRevision,
    MAX_CIPHERTEXT_BYTES,
};
pub use store_version::claim_store_version;

#[cfg(test)]
mod fixture_tests;
#[cfg(test)]
mod properties;
