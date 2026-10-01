use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use openraft::{
    error::{ClientWriteError, RaftError},
    ChangeMembers, Config, LogId, Raft,
};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    network::{self, Forward, RpcNetwork},
    store::{self, CrashPlan},
    ControlConfig, ControlEntry, ControlReply, ControlRpc, ControlState, DeviceId, DeviceNode,
    Dialer, Directory, Error, MembershipChange, Outcome, PendingChange, Result, SignedRequest,
};

/// How often the leader checks for a pending change to advance, and how
/// long a submission waits before retrying while no leader is known.
const DRIVE_INTERVAL: Duration = Duration::from_millis(100);

/// Raft timing for devices on a local network.
pub fn default_config() -> Arc<Config> {
    Arc::new(
        Config {
            cluster_name: "osm-vault".into(),
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Config::default()
        }
        .validate()
        .expect("static Raft configuration is valid"),
    )
}

pub struct NodeOptions {
    pub config: Arc<Config>,
    /// How long a write may wait for a quorum before `QuorumUnavailable`.
    pub write_timeout: Duration,
    /// Test-only failure injection.
    pub crash: CrashPlan,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            config: default_config(),
            write_timeout: Duration::from_secs(10),
            crash: CrashPlan::default(),
        }
    }
}

impl Outcome {
    /// Accepted now, or accepted by an earlier submission of the same
    /// request.
    pub fn is_accepted(&self) -> bool {
        match self {
            Outcome::Accepted => true,
            Outcome::AlreadyApplied(earlier) => earlier.is_accepted(),
            _ => false,
        }
    }
}

/// One device's member of the vault's control plane.
///
/// Membership changes are themselves replicated commands: a signed
/// [`crate::ControlRequest::ProposeChange`] is committed first, and
/// whichever node is leader then drives it (learner catch-up, joint, then
/// uniform membership) and records [`ControlEntry::Complete`]. Because the
/// intent lives in the log, a leader crash at any step leaves the change
/// pending, and the next leader resumes the same request. Driving a change
/// needs no signature, so it continues while the leader's vault is locked.
pub struct ControlNode {
    device: DeviceId,
    raft: Raft<ControlConfig>,
    state: Arc<Mutex<ControlState>>,
    applied: watch::Receiver<Option<LogId<DeviceId>>>,
    write_timeout: Duration,
    forwarder: Arc<dyn Forward>,
    directory: Directory,
    stop: watch::Sender<bool>,
    driver: Mutex<Option<JoinHandle<()>>>,
}

impl ControlNode {
    /// Opens the node's database at `path` and starts Raft as `device` in
    /// the control plane of `vault_id`, reaching the other devices through
    /// `dialer`. A node that ran before resumes from its persisted log,
    /// vote, and state; a database for another vault is refused.
    pub async fn start(
        path: impl AsRef<Path>,
        device: DeviceId,
        vault_id: [u8; 32],
        dialer: impl Dialer,
        options: NodeOptions,
    ) -> Result<Self> {
        let (log, state_machine) = store::open(path, vault_id, options.crash)?;
        let state = state_machine.state_handle();
        let applied = state_machine.applied_handle();
        let dialer = Arc::new(dialer);
        let network = RpcNetwork {
            dialer: dialer.clone(),
        };
        let raft = Raft::new(device, options.config, network, log, state_machine).await?;
        let directory = Directory::new(state.clone(), raft.metrics());
        let (stop, stopped) = watch::channel(false);
        let driver = tokio::spawn(drive(
            raft.clone(),
            state.clone(),
            options.write_timeout,
            stopped,
        ));
        Ok(Self {
            device,
            raft,
            state,
            applied,
            write_timeout: options.write_timeout,
            forwarder: dialer,
            directory,
            stop,
            driver: Mutex::new(Some(driver)),
        })
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn raft(&self) -> &Raft<ControlConfig> {
        &self.raft
    }

    /// The applied control state on this node.
    pub fn state(&self) -> ControlState {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    /// Changes each time newly applied state is on disk, so a caller can
    /// bring its vault up to date.
    pub fn subscribe(&self) -> watch::Receiver<Option<LogId<DeviceId>>> {
        self.applied.clone()
    }

    pub fn current_leader(&self) -> Option<DeviceId> {
        self.raft.metrics().borrow().current_leader
    }

    /// Which devices this node accepts control connections from.
    pub fn directory(&self) -> Directory {
        self.directory.clone()
    }

    /// Handles an RPC that arrived over a connection the transport
    /// authenticated as `authenticated`, a device in [`Self::directory`].
    /// An RPC claiming another sender is refused before it reaches Raft.
    pub async fn handle(&self, authenticated: DeviceId, rpc: ControlRpc) -> ControlReply {
        network::serve(&self.raft, authenticated, rpc, self.write_timeout).await
    }

    /// Forms a new cluster with `members` as its voters. Only for a vault's
    /// first device(s); every later change goes through a proposal.
    pub async fn initialize(&self, members: BTreeMap<DeviceId, DeviceNode>) -> Result<()> {
        self.raft
            .initialize(members)
            .await
            .map_err(|error| Error::Raft(error.to_string()))
    }

    /// Commits a signed request and returns the state machine's verdict.
    /// On a follower the request is passed to the leader; while no leader
    /// is known or reachable it is retried.
    ///
    /// Fails with `QuorumUnavailable` if no quorum commits it in time. In
    /// that case the outcome is unknown until a quorum returns; resubmitting
    /// the same request is safe because request IDs are deduplicated (see
    /// [`Outcome::is_accepted`]).
    pub async fn submit(&self, request: SignedRequest) -> Result<Outcome> {
        let attempt = async {
            loop {
                match self.submit_once(request.clone()).await {
                    Err(Error::NotLeader(_) | Error::QuorumUnavailable) => {
                        tokio::time::sleep(DRIVE_INTERVAL).await;
                    }
                    other => return other,
                }
            }
        };
        tokio::time::timeout(self.write_timeout, attempt)
            .await
            .unwrap_or(Err(Error::QuorumUnavailable))
    }

    async fn submit_once(&self, request: SignedRequest) -> Result<Outcome> {
        match self
            .raft
            .client_write(ControlEntry::Request(request.clone()))
            .await
        {
            Ok(response) => Ok(response.data),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(forward))) => {
                match (forward.leader_id, forward.leader_node) {
                    (Some(leader), Some(node)) if leader != self.device => {
                        self.forwarder
                            .forward(leader, node, request, self.write_timeout)
                            .await
                    }
                    (leader, _) => Err(Error::NotLeader(leader)),
                }
            }
            Err(error) => Err(Error::Raft(error.to_string())),
        }
    }

    /// Stops the node. Its database keeps everything needed to restart.
    pub async fn shutdown(&self) {
        let _ = self.stop.send(true);
        let driver = self.driver.lock().ok().and_then(|mut driver| driver.take());
        if let Some(driver) = driver {
            let _ = driver.await;
        }
        let _ = self.raft.shutdown().await;
    }
}

async fn drive(
    raft: Raft<ControlConfig>,
    state: Arc<Mutex<ControlState>>,
    timeout: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stopped.changed() => return,
            _ = tokio::time::sleep(DRIVE_INTERVAL) => {}
        }
        let leading = {
            let metrics = raft.metrics();
            let metrics = metrics.borrow();
            metrics.running_state.is_ok() && metrics.current_leader == Some(metrics.id)
        };
        if !leading {
            continue;
        }
        let applied = state.lock().ok().map(|state| state.clone());
        if let Some(applied) = applied {
            // Every step is idempotent; a failed or timed-out step is simply
            // retried on a later tick, possibly by another leader.
            let _ = tokio::time::timeout(timeout, advance(&raft, &applied)).await;
        }
    }
}

async fn advance(raft: &Raft<ControlConfig>, state: &ControlState) -> Result<()> {
    let Some(pending) = &state.pending else {
        return remove_stale_learners(raft, state, None).await;
    };
    // A new voter first catches up as a learner. Catch-up is checked
    // explicitly on every attempt rather than trusted to a blocking call: a
    // learner entry can commit while its device is unreachable, and a
    // configuration that includes it would still reach a majority without it.
    if let (MembershipChange::Enroll { device, node }, false) = (&pending.change, pending.cancelled)
    {
        let known = raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .get_node(device)
            .is_some();
        if !known {
            raft.add_learner(*device, node.clone(), false)
                .await
                .map_err(|error| Error::Raft(error.to_string()))?;
        }
        let caught_up = {
            let metrics = raft.metrics();
            let metrics = metrics.borrow();
            let matched = metrics
                .replication
                .as_ref()
                .and_then(|replication| replication.get(device).copied().flatten())
                .map(|log_id| log_id.index);
            matched.is_some() && matched >= metrics.last_log_index
        };
        if !caught_up {
            return Ok(());
        }
    }
    if !(state.is_uniform() && state.voters() == pending.target_voters) {
        // Commits the joint configuration and then the uniform one; from a
        // joint configuration left by a crash, it finishes the change. A
        // device dropped from the target is removed outright, not kept as a
        // learner.
        raft.change_membership(pending.target_voters.clone(), false)
            .await
            .map_err(|error| Error::Raft(error.to_string()))?;
        return Ok(());
    }
    remove_stale_learners(raft, state, Some(pending)).await?;
    raft.client_write(ControlEntry::Complete {
        request_id: pending.request_id,
    })
    .await
    .map_err(|error| Error::Raft(error.to_string()))?;
    Ok(())
}

/// Removes learners that no pending enrollment is waiting for, such as the
/// device of a cancelled enrollment. Only from a committed, uniform
/// configuration, which is the only one a new change may start from.
async fn remove_stale_learners(
    raft: &Raft<ControlConfig>,
    state: &ControlState,
    pending: Option<&PendingChange>,
) -> Result<()> {
    let effective = raft.metrics().borrow().membership_config.clone();
    if effective.log_id() != state.membership.log_id() || !state.is_uniform() {
        return Ok(());
    }
    let enrolling = pending
        .filter(|pending| !pending.cancelled)
        .and_then(|pending| match &pending.change {
            MembershipChange::Enroll { device, .. } => Some(*device),
            MembershipChange::Remove { .. } => None,
        });
    let voters = state.voters();
    let stale: BTreeSet<DeviceId> = effective
        .membership()
        .nodes()
        .map(|(device, _)| *device)
        .filter(|device| !voters.contains(device) && Some(*device) != enrolling)
        .collect();
    if stale.is_empty() {
        return Ok(());
    }
    raft.change_membership(ChangeMembers::RemoveNodes(stale), false)
        .await
        .map_err(|error| Error::Raft(error.to_string()))?;
    Ok(())
}
