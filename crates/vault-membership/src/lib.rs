//! The vault's membership control plane, on OpenRaft.
//!
//! Enrollment and removal of devices are decided by a Raft majority of the
//! current voters; there is no way to force a minority decision. Each change
//! is a signed, replicated request that the state machine authorizes against
//! the committed membership, and the leader then carries it through
//! OpenRaft's joint-consensus membership change. Log, vote, and state are
//! persisted in SQLite before anything is acknowledged.
//!
//! The state also decides key epochs. A removal carries the next epoch key
//! sealed to every remaining voter, and that epoch becomes current only when
//! the removal completes; an enrolled device receives epoch keys only after
//! it has become a voter. Keys travel as HPKE envelopes, so the log holds no
//! key in the clear.
//!
//! Raft tolerates crashed and partitioned devices, not malicious ones: a
//! compromised voter is outside its safety model.

mod error;
mod network;
mod node;
mod state;
mod store;
mod types;

pub use error::{Error, Result};
pub use network::{
    verify_rpc_sender, ControlReply, ControlRpc, Dialer, Directory, Link, LinkError, Router,
    RouterDialer, RouterLink, SenderMismatch, SubmitRefusal,
};
pub use node::{default_config, timing, ControlNode, NodeOptions};
pub use state::{ControlState, PendingChange};
pub use store::{BoundedSnapshotData, CrashPlan, CrashPoint, MAX_SNAPSHOT_BYTES};
pub use types::{
    device_id_from_bytes, device_id_to_bytes, ControlEntry, ControlRequest, DeviceId, DeviceNode,
    KeySigner, MembershipChange, Outcome, Rejection, RequestSigner, Rotation, SignedRequest,
    SIGNATURE_DOMAIN,
};

openraft::declare_raft_types!(
    /// OpenRaft types for the control plane. Node IDs are device IDs.
    pub ControlConfig:
        D = ControlEntry,
        R = Outcome,
        NodeId = DeviceId,
        Node = DeviceNode,
        SnapshotData = BoundedSnapshotData,
);

#[cfg(test)]
mod tests;
