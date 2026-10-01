//! Pairing and revision synchronization between two copies of a vault.
//!
//! Pairing steps and [`SyncSession`] are sans-IO: they consume and produce
//! messages. The TLS transport (`accept_pairing`, `start_pairing`,
//! `serve_sync`, `connect_sync`) moves them as [`wire`] frames over TLS 1.3
//! with both certificates pinned. Revisions are self-authenticating (signed by their
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
mod transport;
pub mod wire;

pub use error::{Error, Result};
pub use pairing::{
    approve_join, invite, review_join, DeviceEntry, Invitation, JoinGrant, JoinRequest, JoinReview,
    Joiner, MAX_INVITATION_TTL_SECS,
};
pub use peers::{Peer, PeerStore, TransportIdentity, MAX_PEERS};
pub use session::{SyncMessage, SyncReport, SyncSession, PROTOCOL_VERSION};
pub use transport::{
    accept_pairing, connect_sync, serve_sync, start_pairing, ApprovedJoin, IncomingJoin,
    PairingConnection, PairingListener, PendingJoin, SyncConnection, SyncEndpoint, SyncOutcome,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;
