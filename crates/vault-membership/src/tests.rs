use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use openraft::{
    error::RPCError,
    raft::{AppendEntriesRequest, VoteRequest},
    Config, ServerState, Vote,
};
use tempfile::TempDir;

use crate::{
    verify_rpc_sender, ControlNode, ControlRequest, CrashPlan, CrashPoint, DeviceId, DeviceNode,
    Error, KeySigner, MembershipChange, NodeOptions, Outcome, Rejection, RequestSigner, Router,
    SignedRequest,
};

fn fast_config() -> Arc<Config> {
    Arc::new(
        Config {
            cluster_name: "test".into(),
            heartbeat_interval: 50,
            election_timeout_min: 300,
            election_timeout_max: 600,
            ..Config::default()
        }
        .validate()
        .unwrap(),
    )
}

/// N devices with their own control-plane databases on one in-process
/// network. Any of them can be crashed, restarted, or isolated.
struct Cluster {
    dir: TempDir,
    router: Router,
    keys: BTreeMap<DeviceId, SigningKey>,
    running: BTreeMap<DeviceId, ControlNode>,
}

impl Cluster {
    fn new(devices: u8) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            router: Router::default(),
            keys: (1..=devices)
                .map(|id| (DeviceId::from(id), SigningKey::from_bytes(&[id; 32])))
                .collect(),
            running: BTreeMap::new(),
        }
    }

    fn signer(&self, device: DeviceId) -> Arc<dyn RequestSigner> {
        Arc::new(KeySigner {
            device,
            key: self.keys[&device].clone(),
        })
    }

    fn node_info(&self, device: DeviceId) -> DeviceNode {
        DeviceNode {
            public_key: self.keys[&device].verifying_key().to_bytes(),
            transport_pin: [device as u8; 32],
        }
    }

    async fn start(&mut self, device: DeviceId, crash: CrashPlan) {
        let node = ControlNode::start(
            self.dir.path().join(format!("{device}.sqlite3")),
            self.signer(device),
            self.router.network(device),
            NodeOptions {
                config: fast_config(),
                write_timeout: Duration::from_secs(3),
                crash,
            },
        )
        .await
        .unwrap();
        self.router.register(device, node.raft().clone());
        self.running.insert(device, node);
    }

    async fn start_all(&mut self, crash: CrashPlan) {
        for device in self.keys.keys().copied().collect::<Vec<_>>() {
            self.start(device, crash.clone()).await;
        }
    }

    /// Stops a device as a crash would: everything not yet on disk is lost.
    async fn crash(&mut self, device: DeviceId) {
        self.router.unregister(device);
        if let Some(node) = self.running.remove(&device) {
            node.shutdown().await;
        }
    }

    async fn bootstrap(&mut self, voters: &[DeviceId]) {
        let members = voters
            .iter()
            .map(|device| (*device, self.node_info(*device)))
            .collect();
        self.running[&voters[0]].initialize(members).await.unwrap();
        self.leader().await;
    }

    /// The running device that is leader, once one is elected.
    async fn leader(&self) -> DeviceId {
        let all: Vec<DeviceId> = self.running.keys().copied().collect();
        self.leader_among(&all).await
    }

    /// A leader among `devices`. An isolated old leader keeps believing it
    /// leads, so callers on one side of a partition name that side.
    async fn leader_among(&self, devices: &[DeviceId]) -> DeviceId {
        for _ in 0..200 {
            for (device, node) in self
                .running
                .iter()
                .filter(|(device, _)| devices.contains(device))
            {
                let metrics = node.raft().metrics().borrow().clone();
                if metrics.running_state.is_ok() && metrics.state == ServerState::Leader {
                    return *device;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no leader was elected");
    }

    fn request(&self, requester: DeviceId, id: u8, request: ControlRequest) -> SignedRequest {
        SignedRequest::sign(
            [id; 16],
            requester,
            request,
            self.signer(requester).as_ref(),
        )
    }

    fn enroll(&self, requester: DeviceId, id: u8, device: DeviceId) -> SignedRequest {
        self.request(
            requester,
            id,
            ControlRequest::ProposeChange(MembershipChange::Enroll {
                device,
                node: self.node_info(device),
            }),
        )
    }

    fn remove(&self, requester: DeviceId, id: u8, device: DeviceId) -> SignedRequest {
        self.request(
            requester,
            id,
            ControlRequest::ProposeChange(MembershipChange::Remove { device }),
        )
    }

    /// Waits until every device in `devices` has applied a uniform
    /// membership of exactly `voters` with no change pending.
    async fn settle(&self, devices: &[DeviceId], voters: &[DeviceId]) {
        let voters: BTreeSet<DeviceId> = voters.iter().copied().collect();
        for _ in 0..400 {
            let settled = devices.iter().all(|device| {
                let state = self.running[device].state();
                state.pending.is_none() && state.is_uniform() && state.voters() == voters
            });
            if settled {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let states: Vec<_> = devices
            .iter()
            .map(|device| {
                let state = self.running[device].state();
                (
                    *device,
                    state.voters(),
                    state.pending.is_some(),
                    state.is_uniform(),
                )
            })
            .collect();
        panic!("membership did not settle on {voters:?}: {states:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_voters_survive_a_leader_crash_and_remove_the_lost_device() {
    let mut cluster = Cluster::new(3);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;
    let lost = cluster.leader().await;
    cluster.crash(lost).await;

    // The two survivors are a majority of three: they elect a leader and
    // can still decide.
    let leader = cluster.leader().await;
    assert_ne!(leader, lost);
    let removal = cluster.remove(leader, 1, lost);
    assert_eq!(
        cluster.running[&leader].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    let survivors: Vec<DeviceId> = cluster.running.keys().copied().collect();
    cluster.settle(&survivors, &survivors).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_minority_cannot_change_membership() {
    let mut cluster = Cluster::new(4);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;
    let isolated = cluster.leader().await;
    cluster.router.isolate(isolated);

    // Cut off from the other voters, the old leader cannot commit anything.
    let stranded = cluster.enroll(isolated, 1, 4);
    let result = cluster.running[&isolated].submit(stranded).await;
    assert!(
        matches!(result, Err(Error::QuorumUnavailable | Error::NotLeader(_))),
        "{result:?}"
    );

    // The majority elects a new leader and decides without it.
    let majority: Vec<DeviceId> = [1, 2, 3].into_iter().filter(|d| *d != isolated).collect();
    let leader = cluster.leader_among(&majority).await;
    for device in &majority {
        assert_eq!(
            cluster.running[device].state().voters(),
            BTreeSet::from([1, 2, 3])
        );
    }
    let enrollment = cluster.enroll(leader, 2, 4);
    assert_eq!(
        cluster.running[&leader].submit(enrollment).await.unwrap(),
        Outcome::Accepted
    );
    let mut settled = majority.clone();
    settled.push(4);
    cluster.settle(&settled, &[1, 2, 3, 4]).await;

    // After the partition heals, the old leader adopts the majority's log;
    // its stranded proposal was never applied anywhere.
    cluster.router.heal(isolated);
    cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;
    for node in cluster.running.values() {
        assert_eq!(node.state().outcome_of(&[1; 16]), None);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_are_authorized_against_the_committed_membership() {
    let mut cluster = Cluster::new(4);
    for device in [1, 2, 3] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;
    let node = &cluster.running[&leader];

    // Device 4 holds a key but is not a member.
    let outsider = cluster.enroll(4, 1, 4);
    assert_eq!(
        node.submit(outsider).await.unwrap(),
        Outcome::Rejected(Rejection::Unauthorized)
    );
    // A member's ID with someone else's signature.
    let mut forged = cluster.enroll(4, 2, 4);
    forged.requester = 2;
    assert_eq!(
        node.submit(forged).await.unwrap(),
        Outcome::Rejected(Rejection::BadSignature)
    );
    assert_eq!(
        node.submit(cluster.remove(1, 3, 9)).await.unwrap(),
        Outcome::Rejected(Rejection::InvalidChange("device is not a voter".into()))
    );

    // Device 4 is not running, so the enrollment cannot finish catching up
    // and stays pending; meanwhile other changes are refused.
    let enrollment = cluster.enroll(1, 4, 4);
    assert_eq!(
        node.submit(enrollment.clone()).await.unwrap(),
        Outcome::Accepted
    );
    assert_eq!(
        node.submit(cluster.remove(2, 5, 3)).await.unwrap(),
        Outcome::Rejected(Rejection::ChangeInProgress)
    );
    assert_eq!(
        node.submit(enrollment).await.unwrap(),
        Outcome::AlreadyApplied(Box::new(Outcome::Accepted))
    );
    let early = cluster.request(
        2,
        6,
        ControlRequest::CompleteChange {
            request_id: [4; 16],
        },
    );
    assert_eq!(
        node.submit(early.clone()).await.unwrap(),
        Outcome::Rejected(Rejection::NotPending)
    );
    // A rejection has no effect and is not remembered: the same request is
    // judged again, not answered from history.
    assert_eq!(
        node.submit(early).await.unwrap(),
        Outcome::Rejected(Rejection::NotPending)
    );

    // Once device 4 is up, the leader finishes the enrollment.
    cluster.start(4, CrashPlan::default()).await;
    cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_membership_change_survives_a_crash_at_every_persistence_step() {
    for point in [
        CrashPoint::ApplyProposal,
        CrashPoint::AppendJoint,
        CrashPoint::ApplyJoint,
        CrashPoint::AppendUniform,
        CrashPoint::ApplyUniform,
    ] {
        // The plan is shared and fires once, on whichever device reaches the
        // point first: normally the leader, which appends and applies first.
        let crash = CrashPlan::default();
        let mut cluster = Cluster::new(4);
        cluster.start_all(crash.clone()).await;
        cluster.bootstrap(&[1, 2, 3]).await;
        let leader = cluster.leader().await;
        // Armed after bootstrap, whose own membership entry would trip it.
        crash.arm(point);
        let enrollment = cluster.enroll(leader, 1, 4);
        // Crashing after the proposal applies can lose the reply even though
        // the proposal is committed.
        let _ = cluster.running[&leader].submit(enrollment).await;

        for _ in 0..200 {
            if crash.fired() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(crash.fired(), "{point:?} was never reached");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let crashed: Vec<DeviceId> = cluster
            .running
            .iter()
            .filter(|(_, node)| node.raft().metrics().borrow().running_state.is_err())
            .map(|(device, _)| *device)
            .collect();
        assert_eq!(crashed.len(), 1, "{point:?}");
        cluster.crash(crashed[0]).await;
        cluster.start(crashed[0], CrashPlan::default()).await;

        cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;
        for node in cluster.running.values() {
            assert_eq!(
                node.state().outcome_of(&[1; 16]),
                Some(&Outcome::Accepted),
                "{point:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpcs_cannot_claim_another_devices_identity() {
    let mut cluster = Cluster::new(3);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;

    // Device 2's connection carries a request claiming to be from leader 1.
    let forged_append = AppendEntriesRequest {
        vote: Vote::new_committed(99, 1),
        prev_log_id: None,
        entries: Vec::new(),
        leader_commit: None,
    };
    assert!(matches!(
        cluster.router.append_entries(2, 3, forged_append).await,
        Err(RPCError::Network(_))
    ));
    let forged_vote = VoteRequest {
        vote: Vote::new(99, 1),
        last_log_id: None,
    };
    assert!(matches!(
        cluster.router.vote(2, 3, forged_vote).await,
        Err(RPCError::Network(_))
    ));
    assert!(verify_rpc_sender(&Vote::new(1, 2), 2).is_ok());
    assert!(verify_rpc_sender(&Vote::new(1, 2), 3).is_err());
    // The forged term-99 requests were refused, so nothing was disturbed.
    let leader = cluster.leader().await;
    assert!(
        cluster.running[&leader]
            .raft()
            .metrics()
            .borrow()
            .current_term
            < 99
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_control_plane_resumes_after_every_device_restarts() {
    let mut cluster = Cluster::new(4);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;
    let enrollment = cluster.enroll(leader, 1, 4);
    cluster.running[&leader].submit(enrollment).await.unwrap();
    cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;

    for device in [1, 2, 3, 4] {
        cluster.crash(device).await;
    }
    cluster.start_all(CrashPlan::default()).await;
    let leader = cluster.leader().await;
    for node in cluster.running.values() {
        let state = node.state();
        assert_eq!(state.voters(), BTreeSet::from([1, 2, 3, 4]));
        assert_eq!(state.outcome_of(&[1; 16]), Some(&Outcome::Accepted));
    }
    // The restarted cluster still decides.
    let removal = cluster.remove(leader, 2, if leader == 4 { 3 } else { 4 });
    assert_eq!(
        cluster.running[&leader].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    let remaining: Vec<DeviceId> = [1, 2, 3, 4]
        .into_iter()
        .filter(|device| *device != if leader == 4 { 3 } else { 4 })
        .collect();
    cluster.settle(&remaining, &remaining).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_device_never_becomes_a_voter_before_catching_up() {
    let mut cluster = Cluster::new(4);
    for device in [1, 2, 3] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;
    let enrollment = cluster.enroll(leader, 1, 4);
    assert_eq!(
        cluster.running[&leader].submit(enrollment).await.unwrap(),
        Outcome::Accepted
    );
    // Longer than a driver step's timeout: the three voters alone would be
    // a majority of {1, 2, 3, 4}, so only the catch-up check keeps device 4
    // out.
    tokio::time::sleep(Duration::from_secs(5)).await;
    for device in [1, 2, 3] {
        let state = cluster.running[&device].state();
        assert_eq!(state.voters(), BTreeSet::from([1, 2, 3]));
        assert!(state.pending.is_some());
    }
    cluster.start(4, CrashPlan::default()).await;
    cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;
}
