//! Raft RPC delivery.
//!
//! OpenRaft requests carry the sender's claimed identity (the leader or
//! candidate in `vote`). That field is untrusted: a receiver must check it
//! against the identity the transport authenticated, which
//! [`verify_rpc_sender`] does. [`Router`] is an in-process transport for
//! tests: it knows each connection's true sender, models partitions, and
//! applies the same check the TLS transport will.
//!
//! Only the leader appends to the log, so a request submitted on a follower
//! is passed to the leader by a [`Forwarder`].

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use openraft::{
    error::{
        ClientWriteError, InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError,
        Unreachable,
    },
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    Raft, RaftNetwork, RaftNetworkFactory, Vote,
};

use crate::{ControlConfig, ControlEntry, DeviceId, DeviceNode, Error, Outcome, SignedRequest};

/// Passes a signed request to the current leader and returns its verdict.
/// The request is self-authenticating, so the leader needs nothing else.
pub trait Forwarder: Send + Sync + 'static {
    fn forward(
        &self,
        leader: DeviceId,
        request: SignedRequest,
    ) -> Pin<Box<dyn Future<Output = crate::Result<Outcome>> + Send + '_>>;
}

#[derive(Debug, thiserror::Error)]
#[error(
    "the RPC claims to come from device {claimed:?} but the connection is from {authenticated}"
)]
pub struct SenderMismatch {
    pub claimed: Option<DeviceId>,
    pub authenticated: DeviceId,
}

#[derive(Debug, thiserror::Error)]
#[error("device {0} is unreachable")]
struct Disconnected(DeviceId);

/// Rejects an RPC whose claimed leader or candidate is not the device the
/// transport authenticated.
pub fn verify_rpc_sender(
    vote: &Vote<DeviceId>,
    authenticated: DeviceId,
) -> Result<(), SenderMismatch> {
    let claimed = vote.leader_id().voted_for();
    if claimed == Some(authenticated) {
        Ok(())
    } else {
        Err(SenderMismatch {
            claimed,
            authenticated,
        })
    }
}

type Rpc<T, E = RaftError<DeviceId>> = Result<T, RPCError<DeviceId, DeviceNode, E>>;

#[derive(Default)]
struct RouterState {
    nodes: BTreeMap<DeviceId, Raft<ControlConfig>>,
    isolated: BTreeSet<DeviceId>,
}

/// In-process delivery between nodes, with partitions.
#[derive(Clone, Default)]
pub struct Router {
    state: Arc<Mutex<RouterState>>,
}

impl Router {
    pub fn register(&self, device: DeviceId, raft: Raft<ControlConfig>) {
        if let Ok(mut state) = self.state.lock() {
            state.nodes.insert(device, raft);
        }
    }

    pub fn unregister(&self, device: DeviceId) {
        if let Ok(mut state) = self.state.lock() {
            state.nodes.remove(&device);
        }
    }

    /// Cuts `device` off from every other node, in both directions.
    pub fn isolate(&self, device: DeviceId) {
        if let Ok(mut state) = self.state.lock() {
            state.isolated.insert(device);
        }
    }

    pub fn heal(&self, device: DeviceId) {
        if let Ok(mut state) = self.state.lock() {
            state.isolated.remove(&device);
        }
    }

    /// A network for `device`: every RPC it sends is authenticated as it.
    pub fn network(&self, device: DeviceId) -> NetworkFactory {
        NetworkFactory {
            router: self.clone(),
            from: device,
        }
    }

    /// Forwards `device`'s requests to the leader, subject to partitions.
    pub fn forwarder(&self, device: DeviceId) -> Arc<dyn Forwarder> {
        Arc::new(RouterForwarder {
            router: self.clone(),
            from: device,
        })
    }

    fn target(&self, from: DeviceId, to: DeviceId) -> Result<Raft<ControlConfig>, Unreachable> {
        let state = self
            .state
            .lock()
            .map_err(|_| Unreachable::new(&Disconnected(to)))?;
        if state.isolated.contains(&from) || state.isolated.contains(&to) {
            return Err(Unreachable::new(&Disconnected(to)));
        }
        state
            .nodes
            .get(&to)
            .cloned()
            .ok_or_else(|| Unreachable::new(&Disconnected(to)))
    }

    /// Delivers an append-entries RPC sent over a connection authenticated
    /// as `from`.
    pub async fn append_entries(
        &self,
        from: DeviceId,
        to: DeviceId,
        rpc: AppendEntriesRequest<ControlConfig>,
    ) -> Rpc<AppendEntriesResponse<DeviceId>> {
        let raft = self.target(from, to)?;
        verify_rpc_sender(&rpc.vote, from).map_err(|error| NetworkError::new(&error))?;
        raft.append_entries(rpc)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(to, error)))
    }

    pub async fn vote(
        &self,
        from: DeviceId,
        to: DeviceId,
        rpc: VoteRequest<DeviceId>,
    ) -> Rpc<VoteResponse<DeviceId>> {
        let raft = self.target(from, to)?;
        verify_rpc_sender(&rpc.vote, from).map_err(|error| NetworkError::new(&error))?;
        raft.vote(rpc)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(to, error)))
    }

    pub async fn install_snapshot(
        &self,
        from: DeviceId,
        to: DeviceId,
        rpc: InstallSnapshotRequest<ControlConfig>,
    ) -> Rpc<InstallSnapshotResponse<DeviceId>, RaftError<DeviceId, InstallSnapshotError>> {
        let raft = self.target(from, to)?;
        verify_rpc_sender(&rpc.vote, from).map_err(|error| NetworkError::new(&error))?;
        raft.install_snapshot(rpc)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(to, error)))
    }
}

pub struct NetworkFactory {
    router: Router,
    from: DeviceId,
}

impl RaftNetworkFactory<ControlConfig> for NetworkFactory {
    type Network = Connection;

    async fn new_client(&mut self, target: DeviceId, _node: &DeviceNode) -> Self::Network {
        Connection {
            router: self.router.clone(),
            from: self.from,
            to: target,
        }
    }
}

pub struct Connection {
    router: Router,
    from: DeviceId,
    to: DeviceId,
}

impl RaftNetwork<ControlConfig> for Connection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ControlConfig>,
        _option: RPCOption,
    ) -> Rpc<AppendEntriesResponse<DeviceId>> {
        self.router.append_entries(self.from, self.to, rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<ControlConfig>,
        _option: RPCOption,
    ) -> Rpc<InstallSnapshotResponse<DeviceId>, RaftError<DeviceId, InstallSnapshotError>> {
        self.router.install_snapshot(self.from, self.to, rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<DeviceId>,
        _option: RPCOption,
    ) -> Rpc<VoteResponse<DeviceId>> {
        self.router.vote(self.from, self.to, rpc).await
    }
}

struct RouterForwarder {
    router: Router,
    from: DeviceId,
}

impl Forwarder for RouterForwarder {
    fn forward(
        &self,
        leader: DeviceId,
        request: SignedRequest,
    ) -> Pin<Box<dyn Future<Output = crate::Result<Outcome>> + Send + '_>> {
        Box::pin(async move {
            let raft = self
                .router
                .target(self.from, leader)
                .map_err(|_| Error::QuorumUnavailable)?;
            match raft.client_write(ControlEntry::Request(request)).await {
                Ok(response) => Ok(response.data),
                Err(RaftError::APIError(ClientWriteError::ForwardToLeader(forward))) => {
                    Err(Error::NotLeader(forward.leader_id))
                }
                Err(error) => Err(Error::Raft(error.to_string())),
            }
        })
    }
}
