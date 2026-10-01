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
//! approves on each. The owner's approval then becomes a proposal to the
//! vault's control plane, and a device is a member only once a quorum has
//! enrolled it; [`control`] couples the vault's authors and key epochs to
//! that committed state. The control plane's own messages travel between
//! devices over the same pinned TLS ([`MemberEndpoint`]). The interim path,
//! in which the owner's confirmation itself authorizes one paired device,
//! remains for the desktop app until it runs the control plane.

pub mod control;
mod error;
mod members;
mod pairing;
mod peers;
mod session;
mod transport;
pub mod wire;

pub use error::{Error, Result};
pub use members::{
    serve_members, start_node, AddressBook, ControlConnection, ControlLink, Incoming,
    MemberContact, MemberEndpoint, MemberSync, MAX_CONTACTS, MEMBER_PROTOCOL_VERSION,
};
pub use pairing::{
    approve_enrollment, approve_join, invite, review_join, DeviceEntry, EnrollmentGrant,
    Invitation, JoinGrant, JoinRequest, JoinReview, Joiner, MAX_INVITATION_TTL_SECS,
};
pub use peers::{Peer, PeerStore, TransportIdentity, MAX_PEERS};
pub use session::{SyncMessage, SyncReport, SyncSession, PROTOCOL_VERSION};
pub use transport::{
    accept_pairing, connect_sync, serve_sync, start_pairing, ApprovedEnrollment, ApprovedJoin,
    IncomingJoin, PairingConnection, PairingListener, PendingJoin, SyncConnection, SyncEndpoint,
    SyncOutcome,
};

#[cfg(test)]
mod control_tests;
#[cfg(test)]
mod member_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;
