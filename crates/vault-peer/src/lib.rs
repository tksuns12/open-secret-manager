//! Pairing and revision synchronization between the devices of a vault.
//!
//! Pairing steps and [`SyncSession`] are sans-IO: they consume and produce
//! messages. The TLS transport moves them as [`wire`] frames over TLS 1.3
//! with both certificates pinned. Revisions are self-authenticating (signed
//! by their author and verified by the core), so the channel protects
//! confidentiality of metadata and liveness, not revision integrity.
//!
//! Pairing is owner-confirmed: both devices show a short code, and the owner
//! approves on each. The owner's approval then becomes a proposal to the
//! vault's control plane, and a device is a member only once a quorum has
//! enrolled it; [`control`] couples the vault's authors and key epochs to
//! that committed state. The control plane's own messages and sync between
//! members travel over the same pinned TLS ([`MemberEndpoint`]).

pub mod control;
mod error;
mod keystore;
mod local;
mod members;
mod pairing;
mod peers;
mod relay;
mod session;
mod transport;
pub mod wire;

pub use control::Voting;
pub use error::{Error, Result};
pub use keystore::{Keystore, KeystoreError, MemoryKeystore, NoKeystore};
pub use local::{local_addresses, MAX_INVITATION_ADDRESSES};
pub use members::{
    serve_members, serve_relayed, start_node, AddressBook, ControlConnection, ControlLink,
    Incoming, MemberContact, MemberEndpoint, MemberSync, MAX_CONTACTS, MEMBER_PROTOCOL_VERSION,
};
pub use pairing::{
    approve_enrollment, invite, review_join, EnrollmentGrant, Invitation, JoinRequest, JoinReview,
    Joiner, MAX_INVITATION_TTL_SECS,
};
pub use peers::{KeyKept, Peer, PeerStore, TransportIdentity};
pub use relay::{serve_relay, Relay, RelayCode, RELAY_PROTOCOL_VERSION};
pub use session::{SyncMessage, SyncReport, SyncSession, PROTOCOL_VERSION};
pub use transport::{
    listen, start_pairing, start_pairing_with_vault, ApprovedEnrollment, IncomingJoin,
    PairingConnection, PairingListener, PendingJoin, PreparedJoin, SharedVault,
};

#[cfg(test)]
mod control_tests;
#[cfg(test)]
mod fixture;
#[cfg(test)]
mod member_tests;
#[cfg(test)]
mod properties;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;
