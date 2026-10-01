//! Raft RPC delivery.
//!
//! Devices exchange [`ControlRpc`]s: OpenRaft's append, vote, and snapshot
//! requests, and signed requests a follower passes to the leader. A
//! transport implements [`Dialer`] and [`Link`] to carry them and must
//! authenticate both ends; the receiving side hands each RPC to
//! [`crate::ControlNode::handle`] with the identity it authenticated.
//!
//! OpenRaft requests carry the sender's claimed identity (the leader or
//! candidate in `vote`). That field is untrusted: it is checked against the
//! authenticated identity ([`verify_rpc_sender`]) before the RPC reaches
//! Raft, and a forwarded request must be signed by the device forwarding it.
//!
//! [`Router`] is an in-process transport for tests: it knows each
//! connection's true sender and models partitions.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use openraft::{
    error::{
        ClientWriteError, Fatal, InstallSnapshotError, NetworkError, RPCError, RaftError,
        RemoteError, Unreachable,
    },
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    Raft, RaftMetrics, RaftNetwork, RaftNetworkFactory, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::{
    ControlConfig, ControlEntry, ControlState, DeviceId, DeviceNode, Error, Outcome, SignedRequest,
};

/// How many devices a node accepts on another member's word.
const MAX_INTRODUCED: usize = 256;

/// One control-plane message from one device to another.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlRpc {
    AppendEntries(AppendEntriesRequest<ControlConfig>),
    Vote(VoteRequest<DeviceId>),
    InstallSnapshot(InstallSnapshotRequest<ControlConfig>),
    /// A signed request passed to the leader by the device that signed it.
    Submit(SignedRequest),
}

/// The answer to a [`ControlRpc`], of the matching kind.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlReply {
    AppendEntries(Result<AppendEntriesResponse<DeviceId>, Fatal<DeviceId>>),
    Vote(Result<VoteResponse<DeviceId>, Fatal<DeviceId>>),
    InstallSnapshot(
        Result<InstallSnapshotResponse<DeviceId>, RaftError<DeviceId, InstallSnapshotError>>,
    ),
    Submit(Result<Outcome, SubmitRefusal>),
    /// The RPC did not come from the device it claims to come from. It never
    /// reached Raft.
    Refused,
}

/// Why a device did not commit a request passed to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmitRefusal {
    /// It is not the leader; this is the leader it knows of, if any.
    NotLeader(Option<DeviceId>),
    /// No quorum committed the request in time.
    QuorumUnavailable,
    Failed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The device cannot be reached now; retry later.
    #[error("device is unreachable: {0}")]
    Unreachable(String),
    #[error("control connection failed: {0}")]
    Failed(String),
}

/// A connection to one other device's control-plane node. An RPC that fails
/// or is abandoned must not leave the link unusable for the next one.
pub trait Link: Send + Sync + 'static {
    /// Sends `rpc` and waits up to `ttl` for the reply.
    fn call(
        &mut self,
        rpc: ControlRpc,
        ttl: Duration,
    ) -> impl Future<Output = Result<ControlReply, LinkError>> + Send;
}

/// Reaches other devices' control-plane nodes over an authenticated
/// transport.
pub trait Dialer: Send + Sync + 'static {
    type Link: Link;

    /// A link to `target`, which membership records as `node`; a transport
    /// connects only to the certificate pinned there. Connecting may be
    /// deferred to the first call.
    fn link(&self, target: DeviceId, node: &DeviceNode) -> Self::Link;
}

#[derive(Debug, thiserror::Error)]
#[error(
    "the RPC claims to come from device {claimed:?} but the connection is from {authenticated}"
)]
pub struct SenderMismatch {
    pub claimed: Option<DeviceId>,
    pub authenticated: DeviceId,
}

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

fn fatal(error: RaftError<DeviceId>) -> Fatal<DeviceId> {
    match error {
        RaftError::Fatal(fatal) => fatal,
        RaftError::APIError(never) => match never {},
    }
}

/// Handles an RPC received over a connection authenticated as
/// `authenticated`. A forwarded request waits up to `submit_timeout` for a
/// quorum.
pub(crate) async fn serve(
    raft: &Raft<ControlConfig>,
    authenticated: DeviceId,
    rpc: ControlRpc,
    submit_timeout: Duration,
) -> ControlReply {
    match rpc {
        ControlRpc::AppendEntries(rpc) => {
            if verify_rpc_sender(&rpc.vote, authenticated).is_err() {
                return ControlReply::Refused;
            }
            ControlReply::AppendEntries(raft.append_entries(rpc).await.map_err(fatal))
        }
        ControlRpc::Vote(rpc) => {
            if verify_rpc_sender(&rpc.vote, authenticated).is_err() {
                return ControlReply::Refused;
            }
            ControlReply::Vote(raft.vote(rpc).await.map_err(fatal))
        }
        ControlRpc::InstallSnapshot(rpc) => {
            if verify_rpc_sender(&rpc.vote, authenticated).is_err() {
                return ControlReply::Refused;
            }
            ControlReply::InstallSnapshot(raft.install_snapshot(rpc).await)
        }
        ControlRpc::Submit(request) => {
            // The state machine checks the signature; here a device may only
            // pass on what it signed itself.
            if request.requester != authenticated {
                return ControlReply::Refused;
            }
            let write = raft.client_write(ControlEntry::Request(request));
            ControlReply::Submit(match tokio::time::timeout(submit_timeout, write).await {
                Ok(Ok(response)) => Ok(response.data),
                Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(forward)))) => {
                    Err(SubmitRefusal::NotLeader(forward.leader_id))
                }
                Ok(Err(error)) => Err(SubmitRefusal::Failed(error.to_string())),
                Err(_) => Err(SubmitRefusal::QuorumUnavailable),
            })
        }
    }
}

type Rpc<T, E = RaftError<DeviceId>> = Result<T, RPCError<DeviceId, DeviceNode, E>>;

#[derive(Debug, thiserror::Error)]
#[error("device {0} sent a reply that does not answer the request")]
struct UnexpectedReply(DeviceId);

#[derive(Debug, thiserror::Error)]
#[error("device {0} refused the request's sender")]
struct RefusedByPeer(DeviceId);

fn link_failure<E: std::error::Error>(error: LinkError) -> RPCError<DeviceId, DeviceNode, E> {
    match &error {
        LinkError::Unreachable(_) => RPCError::Unreachable(Unreachable::new(&error)),
        LinkError::Failed(_) => RPCError::Network(NetworkError::new(&error)),
    }
}

fn wrong_reply<E: std::error::Error>(
    target: DeviceId,
    reply: ControlReply,
) -> RPCError<DeviceId, DeviceNode, E> {
    match reply {
        ControlReply::Refused => RPCError::Network(NetworkError::new(&RefusedByPeer(target))),
        _ => RPCError::Network(NetworkError::new(&UnexpectedReply(target))),
    }
}

/// OpenRaft's network over a [`Dialer`].
pub(crate) struct RpcNetwork<D> {
    pub(crate) dialer: Arc<D>,
}

impl<D: Dialer> RaftNetworkFactory<ControlConfig> for RpcNetwork<D> {
    type Network = RpcConnection<D::Link>;

    async fn new_client(&mut self, target: DeviceId, node: &DeviceNode) -> Self::Network {
        RpcConnection {
            target,
            link: self.dialer.link(target, node),
        }
    }
}

pub(crate) struct RpcConnection<L> {
    target: DeviceId,
    link: L,
}

impl<L: Link> RaftNetwork<ControlConfig> for RpcConnection<L> {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ControlConfig>,
        option: RPCOption,
    ) -> Rpc<AppendEntriesResponse<DeviceId>> {
        let reply = self
            .link
            .call(ControlRpc::AppendEntries(rpc), option.hard_ttl())
            .await
            .map_err(link_failure)?;
        match reply {
            ControlReply::AppendEntries(Ok(response)) => Ok(response),
            ControlReply::AppendEntries(Err(fatal)) => Err(RPCError::RemoteError(
                RemoteError::new(self.target, RaftError::Fatal(fatal)),
            )),
            other => Err(wrong_reply(self.target, other)),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<ControlConfig>,
        option: RPCOption,
    ) -> Rpc<InstallSnapshotResponse<DeviceId>, RaftError<DeviceId, InstallSnapshotError>> {
        let reply = self
            .link
            .call(ControlRpc::InstallSnapshot(rpc), option.hard_ttl())
            .await
            .map_err(link_failure)?;
        match reply {
            ControlReply::InstallSnapshot(Ok(response)) => Ok(response),
            ControlReply::InstallSnapshot(Err(error)) => {
                Err(RPCError::RemoteError(RemoteError::new(self.target, error)))
            }
            other => Err(wrong_reply(self.target, other)),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<DeviceId>,
        option: RPCOption,
    ) -> Rpc<VoteResponse<DeviceId>> {
        let reply = self
            .link
            .call(ControlRpc::Vote(rpc), option.hard_ttl())
            .await
            .map_err(link_failure)?;
        match reply {
            ControlReply::Vote(Ok(response)) => Ok(response),
            ControlReply::Vote(Err(fatal)) => Err(RPCError::RemoteError(RemoteError::new(
                self.target,
                RaftError::Fatal(fatal),
            ))),
            other => Err(wrong_reply(self.target, other)),
        }
    }
}

/// Passes a signed request to the leader and returns its verdict. The
/// request is self-authenticating, so the leader needs nothing else.
pub(crate) trait Forward: Send + Sync {
    fn forward(
        &self,
        leader: DeviceId,
        node: DeviceNode,
        request: SignedRequest,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<Outcome>> + Send + '_>>;
}

impl<D: Dialer> Forward for D {
    fn forward(
        &self,
        leader: DeviceId,
        node: DeviceNode,
        request: SignedRequest,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = crate::Result<Outcome>> + Send + '_>> {
        Box::pin(async move {
            let mut link = self.link(leader, &node);
            match link.call(ControlRpc::Submit(request), ttl).await {
                Ok(ControlReply::Submit(Ok(outcome))) => Ok(outcome),
                Ok(ControlReply::Submit(Err(SubmitRefusal::NotLeader(leader)))) => {
                    Err(Error::NotLeader(leader))
                }
                Ok(ControlReply::Submit(Err(SubmitRefusal::Failed(reason)))) => {
                    Err(Error::Raft(reason))
                }
                // An unreachable leader may have been replaced; the caller
                // retries until its own deadline.
                Ok(ControlReply::Submit(Err(SubmitRefusal::QuorumUnavailable))) | Err(_) => {
                    Err(Error::QuorumUnavailable)
                }
                Ok(_) => Err(Error::Raft("the leader refused the request".into())),
            }
        })
    }
}

/// Which devices this node accepts control connections from, by TLS
/// certificate pin.
///
/// A device is accepted if this node's own log names it: the nodes of the
/// committed membership, of the latest membership in the log, and of a
/// pending enrollment. A node whose log does not name the current members
/// yet (a device still being enrolled, or one that was away while others
/// joined) also accepts devices a member introduced; see
/// [`Directory::introduce`]. A removed device is never accepted.
#[derive(Clone)]
pub struct Directory {
    state: Arc<Mutex<ControlState>>,
    metrics: watch::Receiver<RaftMetrics<DeviceId, DeviceNode>>,
    introduced: Arc<Mutex<BTreeMap<DeviceId, [u8; 32]>>>,
}

impl Directory {
    pub(crate) fn new(
        state: Arc<Mutex<ControlState>>,
        metrics: watch::Receiver<RaftMetrics<DeviceId, DeviceNode>>,
    ) -> Self {
        Self {
            state,
            metrics,
            introduced: Arc::default(),
        }
    }

    fn with_state<T>(&self, read: impl FnOnce(&ControlState) -> T) -> Option<T> {
        self.state.lock().ok().map(|state| read(&state))
    }

    /// The pins of the vault's enrolled members in this node's committed
    /// state. This is what a node may introduce to another.
    pub fn members(&self) -> BTreeMap<DeviceId, [u8; 32]> {
        self.with_state(|state| {
            state
                .members()
                .into_iter()
                .filter_map(|device| Some((device, state.node(device)?.transport_pin)))
                .collect()
        })
        .unwrap_or_default()
    }

    /// Whether this node's committed state lists `device` as an enrolled
    /// member that has not been removed and is not being removed. Only such
    /// a device is synced with or believed about other members.
    pub fn is_member(&self, device: DeviceId) -> bool {
        self.with_state(|state| state.is_active_member(device))
            .unwrap_or(false)
    }

    /// The removed device that had the certificate with this pin, if any.
    /// A removed device is never served; a transport may still complete a
    /// handshake with it to tell it that it was removed.
    pub fn removed_device_for_pin(&self, pin: &[u8; 32]) -> Option<DeviceId> {
        self.with_state(|state| {
            state
                .removed_pins
                .iter()
                .find(|(_, known)| *known == pin)
                .map(|(device, _)| *device)
        })
        .flatten()
    }

    /// Every device this node accepts, with its pin.
    pub fn pins(&self) -> BTreeMap<DeviceId, [u8; 32]> {
        let effective = self.metrics.borrow().membership_config.clone();
        let mut pins: BTreeMap<DeviceId, [u8; 32]> = effective
            .membership()
            .nodes()
            .map(|(device, node)| (*device, node.transport_pin))
            .collect();
        let introduced = self
            .introduced
            .lock()
            .map(|introduced| introduced.clone())
            .unwrap_or_default();
        let read = self.with_state(|state| {
            pins.extend(
                state
                    .membership
                    .membership()
                    .nodes()
                    .map(|(device, node)| (*device, node.transport_pin)),
            );
            if let Some(pending) = state.pending.as_ref().filter(|pending| !pending.cancelled) {
                if let crate::MembershipChange::Enroll { device, node } = &pending.change {
                    pins.insert(*device, node.transport_pin);
                }
            }
            // What the log records overrides what a member said, for a
            // device and for a certificate alike.
            let recorded: BTreeSet<[u8; 32]> = pins.values().copied().collect();
            for (device, pin) in introduced {
                if !recorded.contains(&pin) {
                    pins.entry(device).or_insert(pin);
                }
            }
            pins.retain(|device, _| !state.removed.contains_key(device));
        });
        // Without the state, removals cannot be ruled out: accept no one.
        if read.is_none() {
            pins.clear();
        }
        pins
    }

    /// The device that presents the certificate with this pin, if exactly
    /// one accepted device does.
    pub fn device_for_pin(&self, pin: &[u8; 32]) -> Option<DeviceId> {
        let pins = self.pins();
        let mut matching = pins.iter().filter(|(_, known)| *known == pin);
        let (device, _) = matching.next()?;
        matching.next().is_none().then_some(*device)
    }

    /// Accepts `devices` on a member's word, until this node's own log
    /// names them. Call only with pins that came from a member over an
    /// authenticated channel: the signed enrollment grant, or a connection
    /// to a device for which [`Directory::is_member`] holds. What the log
    /// records wins: an introduction neither replaces a recorded device's
    /// pin nor claims a recorded pin for another device.
    pub fn introduce(&self, devices: impl IntoIterator<Item = (DeviceId, [u8; 32])>) {
        let Ok(mut introduced) = self.introduced.lock() else {
            return;
        };
        for (device, pin) in devices {
            if introduced.len() >= MAX_INTRODUCED && !introduced.contains_key(&device) {
                break;
            }
            introduced.insert(device, pin);
        }
    }
}

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

    /// `device`'s way to reach the others: every RPC it sends is
    /// authenticated as it.
    pub fn dialer(&self, device: DeviceId) -> RouterDialer {
        RouterDialer {
            router: self.clone(),
            from: device,
        }
    }

    fn target(&self, from: DeviceId, to: DeviceId) -> Result<Raft<ControlConfig>, LinkError> {
        let disconnected = || LinkError::Unreachable(format!("device {to} is disconnected"));
        let state = self.state.lock().map_err(|_| disconnected())?;
        if state.isolated.contains(&from) || state.isolated.contains(&to) {
            return Err(disconnected());
        }
        state.nodes.get(&to).cloned().ok_or_else(disconnected)
    }
}

pub struct RouterDialer {
    router: Router,
    from: DeviceId,
}

impl Dialer for RouterDialer {
    type Link = RouterLink;

    fn link(&self, target: DeviceId, _node: &DeviceNode) -> RouterLink {
        RouterLink {
            router: self.router.clone(),
            from: self.from,
            to: target,
        }
    }
}

pub struct RouterLink {
    router: Router,
    from: DeviceId,
    to: DeviceId,
}

impl Link for RouterLink {
    async fn call(&mut self, rpc: ControlRpc, ttl: Duration) -> Result<ControlReply, LinkError> {
        let raft = self.router.target(self.from, self.to)?;
        Ok(serve(&raft, self.from, rpc, ttl).await)
    }
}
