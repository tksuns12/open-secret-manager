//! The vault's membership control plane, on OpenRaft.
//!
//! Enrollment and removal of devices are decided by a Raft majority of the
//! current voters; there is no way to force a minority decision. Each change
//! is a signed, replicated request that the state machine authorizes against
//! the committed membership, and the leader then carries it through
//! OpenRaft's joint-consensus membership change. Log, vote, and state are
//! persisted in SQLite before anything is acknowledged.
//!
//! Raft tolerates crashed and partitioned devices, not malicious ones: a
//! compromised voter is outside its safety model.

mod error;
mod network;
mod node;
mod state;
mod store;
mod types;

use std::io::Cursor;

pub use error::{Error, Result};
pub use network::{verify_rpc_sender, NetworkFactory, Router, SenderMismatch};
pub use node::{default_config, ControlNode, NodeOptions};
pub use state::{ControlState, PendingChange};
pub use store::{CrashPlan, CrashPoint};
pub use types::{
    device_id_from_bytes, ControlRequest, DeviceId, DeviceNode, KeySigner, MembershipChange,
    Outcome, Rejection, RequestSigner, SignedRequest,
};

openraft::declare_raft_types!(
    /// OpenRaft types for the control plane. Node IDs are device IDs.
    pub ControlConfig:
        D = SignedRequest,
        R = Outcome,
        NodeId = DeviceId,
        Node = DeviceNode,
);

#[cfg(test)]
mod tests;
