use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use openraft::{
    error::{ClientWriteError, RaftError},
    Config, Raft, RaftNetworkFactory,
};
use sha2::{Digest, Sha256};
use tokio::{sync::watch, task::JoinHandle};

use crate::{
    store::{self, CrashPlan},
    ControlConfig, ControlRequest, ControlState, DeviceId, DeviceNode, Error, MembershipChange,
    Outcome, PendingChange, RequestSigner, Result, SignedRequest,
};

/// How often the leader checks for a pending change to advance.
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

/// One device's member of the vault's control plane.
///
/// Membership changes are themselves replicated commands: a signed
/// [`ControlRequest::ProposeChange`] is committed first, and whichever node
/// is leader then drives it (learner catch-up, joint, then uniform
/// membership) and commits a [`ControlRequest::CompleteChange`]. Because the
/// intent lives in the log, a leader crash at any step leaves the change
/// pending, and the next leader resumes the same request.
pub struct ControlNode {
    device: DeviceId,
    raft: Raft<ControlConfig>,
    state: Arc<Mutex<ControlState>>,
    write_timeout: Duration,
    stop: watch::Sender<bool>,
    driver: JoinHandle<()>,
}

impl ControlNode {
    /// Opens the node's database at `path` and starts Raft. A node that ran
    /// before resumes from its persisted log, vote, and state.
    pub async fn start(
        path: impl AsRef<Path>,
        signer: Arc<dyn RequestSigner>,
        network: impl RaftNetworkFactory<ControlConfig>,
        options: NodeOptions,
    ) -> Result<Self> {
        let device = signer.device();
        let (log, state_machine) = store::open(path, options.crash)?;
        let state = state_machine.state_handle();
        let raft = Raft::new(device, options.config, network, log, state_machine).await?;
        let (stop, stopped) = watch::channel(false);
        let driver = tokio::spawn(drive(
            raft.clone(),
            state.clone(),
            signer,
            options.write_timeout,
            stopped,
        ));
        Ok(Self {
            device,
            raft,
            state,
            write_timeout: options.write_timeout,
            stop,
            driver,
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

    pub fn current_leader(&self) -> Option<DeviceId> {
        self.raft.metrics().borrow().current_leader
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
    ///
    /// Fails with `NotLeader` on a follower, and with `QuorumUnavailable`
    /// if no quorum commits it in time. In that case the outcome is unknown
    /// until a quorum returns; resubmitting the same request is safe because
    /// request IDs are deduplicated.
    pub async fn submit(&self, request: SignedRequest) -> Result<Outcome> {
        submit(&self.raft, request, self.write_timeout).await
    }

    /// Stops the node. Its database keeps everything needed to restart.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.driver.await;
        let _ = self.raft.shutdown().await;
    }
}

async fn submit(
    raft: &Raft<ControlConfig>,
    request: SignedRequest,
    timeout: Duration,
) -> Result<Outcome> {
    match tokio::time::timeout(timeout, raft.client_write(request)).await {
        Err(_) => Err(Error::QuorumUnavailable),
        Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(forward)))) => {
            Err(Error::NotLeader(forward.leader_id))
        }
        Ok(Err(error)) => Err(Error::Raft(error.to_string())),
        Ok(Ok(response)) => Ok(response.data),
    }
}

/// The stable ID of the completion for `request_id`, so a completion
/// retried by a new leader is recognized as the same request.
fn completion_id(request_id: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"osm-complete-change-v1\0")
        .chain_update(request_id)
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

async fn drive(
    raft: Raft<ControlConfig>,
    state: Arc<Mutex<ControlState>>,
    signer: Arc<dyn RequestSigner>,
    timeout: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let device = signer.device();
    loop {
        tokio::select! {
            _ = stopped.changed() => return,
            _ = tokio::time::sleep(DRIVE_INTERVAL) => {}
        }
        let leading = {
            let metrics = raft.metrics();
            let metrics = metrics.borrow();
            metrics.running_state.is_ok() && metrics.current_leader == Some(device)
        };
        if !leading {
            continue;
        }
        let pending = state.lock().ok().and_then(|state| state.pending.clone());
        if let Some(pending) = pending {
            // Every step is idempotent; a failed or timed-out step is simply
            // retried on a later tick, possibly by another leader.
            let _ = tokio::time::timeout(
                timeout,
                advance(&raft, &state, signer.as_ref(), &pending, timeout),
            )
            .await;
        }
    }
}

async fn advance(
    raft: &Raft<ControlConfig>,
    state: &Mutex<ControlState>,
    signer: &dyn RequestSigner,
    pending: &PendingChange,
    timeout: Duration,
) -> Result<()> {
    // A new voter first catches up as a learner. Catch-up is checked
    // explicitly on every attempt rather than trusted to a blocking call: a
    // learner entry can commit while its device is unreachable, and a
    // configuration that includes it would still reach a majority without it.
    if let MembershipChange::Enroll { device, node } = &pending.change {
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
    let committed = state
        .lock()
        .map(|state| state.is_uniform() && state.voters() == pending.target_voters)
        .unwrap_or(false);
    if !committed {
        // Commits the joint configuration and then the uniform one; from a
        // joint configuration left by a crash, it finishes the change.
        raft.change_membership(pending.target_voters.clone(), false)
            .await
            .map_err(|error| Error::Raft(error.to_string()))?;
        return Ok(());
    }
    let completion = SignedRequest::sign(
        completion_id(&pending.request_id),
        signer.device(),
        ControlRequest::CompleteChange {
            request_id: pending.request_id,
        },
        signer,
    );
    submit(raft, completion, timeout).await.map(|_| ())
}
