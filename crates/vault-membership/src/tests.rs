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
use osm_vault_sync::{open_epoch_key, seal_epoch_key, HpkeKeyPair, VaultId};
use tempfile::TempDir;

use crate::{
    verify_rpc_sender, ControlNode, ControlRequest, CrashPlan, CrashPoint, DeviceId, DeviceNode,
    Error, KeySigner, MembershipChange, NodeOptions, Outcome, Rejection, RequestSigner, Rotation,
    Router, SignedRequest,
};

const VAULT: [u8; 32] = [42; 32];

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

/// The epoch key a test vault uses for `epoch`, and its check.
fn epoch_key(epoch: u64) -> [u8; 32] {
    [epoch as u8 + 100; 32]
}

fn check(epoch: u64) -> [u8; 32] {
    [epoch as u8 + 200; 32]
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

    fn hpke(device: DeviceId) -> HpkeKeyPair {
        HpkeKeyPair::from_secret(&[device as u8 + 50; 32])
    }

    fn node_info(&self, device: DeviceId) -> DeviceNode {
        DeviceNode {
            public_key: self.keys[&device].verifying_key().to_bytes(),
            transport_pin: [device as u8; 32],
            recipient_key: Self::hpke(device).public().as_bytes(),
        }
    }

    async fn start(&mut self, device: DeviceId, crash: CrashPlan) {
        let node = ControlNode::start(
            self.dir.path().join(format!("{device}.sqlite3")),
            device,
            VAULT,
            self.router.network(device),
            NodeOptions {
                config: fast_config(),
                write_timeout: Duration::from_secs(3),
                forwarder: Some(self.router.forwarder(device)),
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

    /// Forms a cluster of `voters` and commits genesis at epoch 1 from the
    /// first of them.
    async fn bootstrap(&mut self, voters: &[DeviceId]) {
        let members = voters
            .iter()
            .map(|device| (*device, self.node_info(*device)))
            .collect();
        self.running[&voters[0]].initialize(members).await.unwrap();
        self.leader().await;
        let genesis = self.request(
            voters[0],
            0,
            ControlRequest::Genesis {
                epoch: 1,
                checks: vec![check(1)],
                authors: Vec::new(),
            },
        );
        assert_eq!(
            self.running[&voters[0]].submit(genesis).await.unwrap(),
            Outcome::Accepted
        );
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
            &VAULT,
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

    /// The next epoch's key sealed to each of `remaining`.
    fn rotation(&self, epoch: u64, remaining: &[DeviceId]) -> Rotation {
        Rotation {
            epoch,
            check: check(epoch),
            envelopes: remaining
                .iter()
                .map(|device| (*device, self.envelope(*device, epoch)))
                .collect(),
        }
    }

    fn envelope(&self, device: DeviceId, epoch: u64) -> Vec<u8> {
        let node = self.node_info(device);
        seal_epoch_key(
            VaultId(VAULT),
            epoch,
            osm_vault_sync::DeviceId(node.public_key),
            Self::hpke(device).public(),
            &epoch_key(epoch),
        )
        .unwrap()
        .to_bytes()
        .to_vec()
    }

    /// Removes `device`, rotating from the epoch the requester last applied
    /// to a new key for every other voter it knows of.
    fn remove(&self, requester: DeviceId, id: u8, device: DeviceId) -> SignedRequest {
        let state = self.running[&requester].state();
        let remaining: Vec<DeviceId> = state
            .voters()
            .into_iter()
            .filter(|voter| *voter != device)
            .collect();
        self.request(
            requester,
            id,
            ControlRequest::ProposeChange(MembershipChange::Remove {
                device,
                rotation: self.rotation(state.epoch + 1, &remaining),
            }),
        )
    }

    fn grant(
        &self,
        requester: DeviceId,
        id: u8,
        device: DeviceId,
        epochs: &[u64],
    ) -> SignedRequest {
        self.request(
            requester,
            id,
            ControlRequest::GrantKeys {
                device,
                envelopes: epochs
                    .iter()
                    .map(|epoch| self.envelope(device, *epoch))
                    .collect(),
            },
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

    /// Waits until `device`'s membership lists no learners.
    async fn learners_removed(&self, device: DeviceId) {
        for _ in 0..200 {
            let metrics = self.running[&device].raft().metrics().borrow().clone();
            let membership = metrics.membership_config.membership();
            let voters: BTreeSet<DeviceId> = membership.voter_ids().collect();
            if membership.nodes().all(|(id, _)| voters.contains(id)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("learners were not removed");
    }
}

fn invalid(outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Rejected(Rejection::InvalidChange(_)))
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
    for device in &survivors {
        let state = cluster.running[device].state();
        assert_eq!(state.epoch, 2);
        assert_eq!(state.removed.get(&lost), Some(&leader));
    }
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
    // A member's request signed for another vault.
    let other_vault = SignedRequest::sign(
        &[7; 32],
        [3; 16],
        2,
        ControlRequest::ProposeChange(MembershipChange::Enroll {
            device: 4,
            node: cluster.node_info(4),
        }),
        cluster.signer(2).as_ref(),
    );
    assert_eq!(
        node.submit(other_vault).await.unwrap(),
        Outcome::Rejected(Rejection::BadSignature)
    );
    assert!(invalid(
        &node.submit(cluster.remove(1, 3, 9)).await.unwrap()
    ));

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
    // No keys before the enrollment completes.
    assert!(invalid(
        &node.submit(cluster.grant(2, 6, 4, &[1])).await.unwrap()
    ));
    let wrong = cluster.request(
        2,
        7,
        ControlRequest::CancelEnrollment {
            request_id: [9; 16],
        },
    );
    assert_eq!(
        node.submit(wrong.clone()).await.unwrap(),
        Outcome::Rejected(Rejection::NotPending)
    );
    // A rejection has no effect and is not remembered: the same request is
    // judged again, not answered from history.
    assert_eq!(
        node.submit(wrong).await.unwrap(),
        Outcome::Rejected(Rejection::NotPending)
    );

    // Once device 4 is up, the leader finishes the enrollment. Device 4 is
    // then an author and receives the existing epoch's key, once.
    cluster.start(4, CrashPlan::default()).await;
    cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;
    let node = &cluster.running[&1];
    let state = cluster.running[&4].state();
    assert_eq!(state.authors[&4], cluster.node_info(4).public_key);
    assert_eq!(state.missing_epochs(4), vec![1]);
    assert!(invalid(
        &node.submit(cluster.grant(2, 8, 4, &[2])).await.unwrap()
    ));
    assert_eq!(
        node.submit(cluster.grant(2, 9, 4, &[1])).await.unwrap(),
        Outcome::Accepted
    );
    assert!(invalid(
        &node.submit(cluster.grant(3, 10, 4, &[1])).await.unwrap()
    ));
    // Devices cannot remove themselves.
    assert!(invalid(
        &node.submit(cluster.remove(4, 11, 4)).await.unwrap()
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_changes_before_genesis_and_genesis_happens_once() {
    let mut cluster = Cluster::new(3);
    cluster.start_all(CrashPlan::default()).await;
    let members = [1, 2]
        .into_iter()
        .map(|device| (device, cluster.node_info(device)))
        .collect();
    cluster.running[&1].initialize(members).await.unwrap();
    cluster.leader().await;
    let node = &cluster.running[&1];
    assert_eq!(
        node.submit(cluster.enroll(1, 1, 3)).await.unwrap(),
        Outcome::Rejected(Rejection::NotInitialized)
    );
    let genesis = |requester, id, epoch, checks: Vec<[u8; 32]>| {
        cluster.request(
            requester,
            id,
            ControlRequest::Genesis {
                epoch,
                checks,
                authors: vec![(9, [9; 32])],
            },
        )
    };
    assert_eq!(
        node.submit(genesis(3, 2, 1, vec![check(1)])).await.unwrap(),
        Outcome::Rejected(Rejection::Unauthorized)
    );
    assert!(invalid(
        &node.submit(genesis(1, 3, 2, vec![check(1)])).await.unwrap()
    ));
    let valid_author = cluster.node_info(3).public_key;
    let founding = cluster.request(
        1,
        4,
        ControlRequest::Genesis {
            epoch: 2,
            checks: vec![check(1), check(2)],
            authors: vec![(9, valid_author)],
        },
    );
    assert_eq!(node.submit(founding).await.unwrap(), Outcome::Accepted);
    assert!(invalid(
        &node
            .submit(cluster.request(
                2,
                5,
                ControlRequest::Genesis {
                    epoch: 1,
                    checks: vec![check(1)],
                    authors: Vec::new(),
                },
            ))
            .await
            .unwrap()
    ));
    let state = node.state();
    assert_eq!(state.epoch, 2);
    // Voters are authors whether listed or not; the founder holds every
    // key, the other initial voter none yet.
    assert_eq!(
        state.authors.keys().copied().collect::<Vec<_>>(),
        vec![1, 2, 9]
    );
    assert_eq!(state.missing_epochs(1), Vec::<u64>::new());
    assert_eq!(state.missing_epochs(2), vec![1, 2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_seals_the_next_epoch_to_exactly_the_remaining_voters() {
    let mut cluster = Cluster::new(4);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3, 4]).await;
    // Submitted on any device: followers forward to the leader.
    let node = &cluster.running[&2];

    let rotation_request = |id, rotation| {
        cluster.request(
            2,
            id,
            ControlRequest::ProposeChange(MembershipChange::Remove {
                device: 4,
                rotation,
            }),
        )
    };
    // Missing a remaining voter, including the removed one, the wrong
    // epoch, or an envelope sealed to someone else: all refused.
    for (id, rotation) in [
        (1, cluster.rotation(2, &[1, 2])),
        (2, cluster.rotation(2, &[1, 2, 3, 4])),
        (3, cluster.rotation(3, &[1, 2, 3])),
        (
            4,
            Rotation {
                envelopes: vec![
                    (1, cluster.envelope(1, 2)),
                    (2, cluster.envelope(2, 2)),
                    (3, cluster.envelope(1, 2)),
                ],
                ..cluster.rotation(2, &[1, 2, 3])
            },
        ),
    ] {
        assert!(
            invalid(&node.submit(rotation_request(id, rotation)).await.unwrap()),
            "{id}"
        );
    }
    assert_eq!(node.state().epoch, 1);

    assert_eq!(
        node.submit(rotation_request(5, cluster.rotation(2, &[1, 2, 3])))
            .await
            .unwrap(),
        Outcome::Accepted
    );
    cluster.settle(&[1, 2, 3], &[1, 2, 3]).await;
    let state = cluster.running[&1].state();
    assert_eq!(state.epoch, 2);
    assert_eq!(state.epoch_checks[&2], check(2));
    assert_eq!(state.removed.get(&4), Some(&2));
    assert!(!state.keys_held.contains_key(&4) && !state.envelopes.contains_key(&4));
    // Each remaining device opens its own envelope; the removed device's
    // recipient key opens none of them.
    for device in [1, 2, 3] {
        let envelope =
            osm_vault_sync::EpochKeyEnvelope::from_bytes(&state.envelopes[&device][&2]).unwrap();
        let recipient = osm_vault_sync::DeviceId(cluster.node_info(device).public_key);
        let key = open_epoch_key(
            &envelope,
            VaultId(VAULT),
            2,
            recipient,
            Cluster::hpke(device).private(),
        )
        .unwrap();
        assert_eq!(*key, epoch_key(2));
        assert!(open_epoch_key(
            &envelope,
            VaultId(VAULT),
            2,
            recipient,
            Cluster::hpke(4).private()
        )
        .is_err());
    }
    // A removed device never rejoins under the same identity.
    let leader = cluster.leader_among(&[1, 2, 3]).await;
    assert!(invalid(
        &cluster.running[&leader]
            .submit(cluster.enroll(1, 6, 4))
            .await
            .unwrap()
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_leader_itself_can_be_removed() {
    let mut cluster = Cluster::new(3);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;
    let other = if leader == 1 { 2 } else { 1 };
    let removal = cluster.remove(other, 1, leader);
    assert!(cluster.running[&other]
        .submit(removal)
        .await
        .unwrap()
        .is_accepted());
    let remaining: Vec<DeviceId> = [1, 2, 3].into_iter().filter(|d| *d != leader).collect();
    cluster.settle(&remaining, &remaining).await;
    for device in &remaining {
        assert_eq!(cluster.running[device].state().epoch, 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrollment_whose_device_never_appears_can_be_cancelled() {
    let mut cluster = Cluster::new(4);
    for device in [1, 2, 3] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1, 2, 3]).await;
    let node = &cluster.running[&1];
    assert!(node
        .submit(cluster.enroll(1, 1, 4))
        .await
        .unwrap()
        .is_accepted());
    // Device 4 is never started: the enrollment stays pending and blocks
    // other changes until it is cancelled.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        node.submit(cluster.remove(2, 2, 3)).await.unwrap(),
        Outcome::Rejected(Rejection::ChangeInProgress)
    );
    let cancel = cluster.request(
        2,
        3,
        ControlRequest::CancelEnrollment {
            request_id: [1; 16],
        },
    );
    assert_eq!(
        node.submit(cancel.clone()).await.unwrap(),
        Outcome::Accepted
    );
    assert_eq!(
        node.submit(cancel).await.unwrap(),
        Outcome::AlreadyApplied(Box::new(Outcome::Accepted))
    );
    cluster.settle(&[1, 2, 3], &[1, 2, 3]).await;
    let leader = cluster.leader().await;
    cluster.learners_removed(leader).await;
    let state = node.state();
    assert!(!state.authors.contains_key(&4));
    assert!(state.missing_epochs(4).is_empty());

    // The cluster can change again.
    assert!(node
        .submit(cluster.remove(2, 4, 3))
        .await
        .unwrap()
        .is_accepted());
    cluster.settle(&[1, 2], &[1, 2]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_membership_change_survives_a_crash_at_every_persistence_step() {
    for removal in [false, true] {
        for point in [
            CrashPoint::ApplyProposal,
            CrashPoint::AppendJoint,
            CrashPoint::ApplyJoint,
            CrashPoint::AppendUniform,
            CrashPoint::ApplyUniform,
        ] {
            // The plan is shared and fires once, on whichever device reaches
            // the point first: normally the leader, which appends and applies
            // first.
            let crash = CrashPlan::default();
            let mut cluster = Cluster::new(4);
            cluster.start_all(crash.clone()).await;
            let voters: &[DeviceId] = if removal { &[1, 2, 3, 4] } else { &[1, 2, 3] };
            cluster.bootstrap(voters).await;
            let leader = cluster.leader().await;
            // Armed after bootstrap, whose own membership entry would trip it.
            crash.arm(point);
            // A removal targets a follower, which stays up.
            let removed = if leader == 4 { 3 } else { 4 };
            let (change, after): (_, Vec<DeviceId>) = if removal {
                (
                    cluster.remove(leader, 1, removed),
                    voters.iter().copied().filter(|d| *d != removed).collect(),
                )
            } else {
                (cluster.enroll(leader, 1, 4), vec![1, 2, 3, 4])
            };
            // Crashing after the proposal applies can lose the reply even
            // though the proposal is committed.
            let _ = cluster.running[&leader].submit(change).await;

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
            // Until the change completes, a rotation is not in effect.
            for node in cluster.running.values() {
                let state = node.state();
                if state.pending.is_some() {
                    assert_eq!(state.epoch, 1, "{point:?}");
                }
            }
            cluster.crash(crashed[0]).await;
            cluster.start(crashed[0], CrashPlan::default()).await;

            cluster.settle(&after, &after).await;
            for device in &after {
                let state = cluster.running[device].state();
                assert_eq!(
                    state.outcome_of(&[1; 16]),
                    Some(&Outcome::Accepted),
                    "{point:?}"
                );
                // Exactly one rotation, never a second epoch.
                assert_eq!(state.epoch, if removal { 2 } else { 1 }, "{point:?}");
            }
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
        assert_eq!(state.vault_id, VAULT);
    }
    // The restarted cluster still decides.
    let removed = if leader == 4 { 3 } else { 4 };
    let removal = cluster.remove(leader, 2, removed);
    assert_eq!(
        cluster.running[&leader].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    let remaining: Vec<DeviceId> = [1, 2, 3, 4]
        .into_iter()
        .filter(|device| *device != removed)
        .collect();
    cluster.settle(&remaining, &remaining).await;

    // A database belongs to one vault.
    cluster.crash(1).await;
    let reopened = ControlNode::start(
        cluster.dir.path().join("1.sqlite3"),
        1,
        [7; 32],
        cluster.router.network(1),
        NodeOptions::default(),
    )
    .await;
    assert!(reopened.is_err());
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
