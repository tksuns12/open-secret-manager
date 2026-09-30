//! Pairing and revision synchronization between two copies of a vault.
//!
//! Everything here is sans-IO: pairing steps and [`SyncSession`] consume and
//! produce messages, and the caller moves [`wire`] frames over an
//! authenticated channel. Revisions are self-authenticating (signed by their
//! author and verified by the core), so the channel protects confidentiality
//! of metadata and liveness, not revision integrity.
//!
//! Pairing is owner-confirmed: both devices show a short code, and the owner
//! approves on each. That confirmation is the interim enrollment authority
//! until committed membership exists, so at most one paired peer is allowed.

mod error;
mod pairing;
mod peers;
mod session;
pub mod wire;

pub use error::{Error, Result};
pub use pairing::{
    approve_join, invite, review_join, DeviceEntry, Invitation, JoinGrant, JoinRequest, JoinReview,
    Joiner, MAX_INVITATION_TTL_SECS,
};
pub use peers::{Peer, PeerStore, MAX_PEERS};
pub use session::{SyncMessage, SyncReport, SyncSession, PROTOCOL_VERSION};

#[cfg(test)]
mod tests;
