use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use openraft::{
    raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest},
    ChangeMembers, Config, ServerState, SnapshotMeta, Vote,
};
use osm_vault_sync::{open_epoch_key, seal_epoch_key, HpkeKeyPair, VaultId};
use tempfile::TempDir;

use crate::{
    verify_rpc_sender, ControlNode, ControlReply, ControlRequest, ControlRpc, CrashPlan,
    CrashPoint, DeviceId, DeviceNode, Dialer, Error, KeySigner, Link, MembershipChange,
    NodeOptions, Outcome, Rejection, RequestSigner, Rotation, Router, SignedRequest,
};

const VAULT: [u8; 32] = [42; 32];

fn fast_config() -> Arc<Config> {
    crate::timing(50, 300, 600).unwrap()
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
            self.router.dialer(device),
            NodeOptions {
                config: fast_config(),
                write_timeout: Duration::from_secs(3),
                crash,
            },
        )
        .await
        .unwrap();
        self.router.register(&node);
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
        // Requests are built from a device's own applied state, so every
        // voter must have applied genesis before a test goes on.
        for _ in 0..200 {
            if voters
                .iter()
                .all(|device| self.running[device].state().epoch == 1)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("genesis did not reach every voter");
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
                votes: true,
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

    fn enroll_without_vote(&self, requester: DeviceId, id: u8, device: DeviceId) -> SignedRequest {
        self.request(
            requester,
            id,
            ControlRequest::ProposeChange(MembershipChange::Enroll {
                device,
                node: self.node_info(device),
                votes: false,
            }),
        )
    }

    /// Removes `device`, rotating from the epoch the requester last applied
    /// to a new key for every other member it knows of, voting or not.
    fn remove(&self, requester: DeviceId, id: u8, device: DeviceId) -> SignedRequest {
        let state = self.running[&requester].state();
        let remaining: Vec<DeviceId> = state
            .members()
            .into_iter()
            .filter(|member| *member != device)
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
            votes: true,
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
            // The crash reaches the node's state a moment after it fires.
            let crashed_nodes = || -> Vec<DeviceId> {
                cluster
                    .running
                    .iter()
                    .filter(|(_, node)| node.raft().metrics().borrow().running_state.is_err())
                    .map(|(device, _)| *device)
                    .collect()
            };
            for _ in 0..200 {
                tokio::time::sleep(Duration::from_millis(25)).await;
                if !crashed_nodes().is_empty() {
                    break;
                }
            }
            // A second node that fails a moment later is still one too many.
            tokio::time::sleep(Duration::from_millis(250)).await;
            let crashed = crashed_nodes();
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

    // Device 2's connection carries requests claiming to be from device 1.
    let mut link = cluster.router.dialer(2).link(3, &cluster.node_info(3));
    let ttl = Duration::from_secs(1);
    let forged_append = AppendEntriesRequest {
        vote: Vote::new_committed(99, 1),
        prev_log_id: None,
        entries: Vec::new(),
        leader_commit: None,
    };
    assert!(matches!(
        link.call(ControlRpc::AppendEntries(forged_append), ttl)
            .await,
        Ok(ControlReply::Refused)
    ));
    let forged_vote = VoteRequest {
        vote: Vote::new(99, 1),
        last_log_id: None,
    };
    assert!(matches!(
        link.call(ControlRpc::Vote(forged_vote), ttl).await,
        Ok(ControlReply::Refused)
    ));
    let forged_snapshot = InstallSnapshotRequest {
        vote: Vote::new_committed(99, 1),
        meta: SnapshotMeta::default(),
        offset: 0,
        data: Vec::new(),
        done: true,
    };
    assert!(matches!(
        link.call(ControlRpc::InstallSnapshot(forged_snapshot), ttl)
            .await,
        Ok(ControlReply::Refused)
    ));
    // A device passes on only requests it signed itself.
    let borrowed = cluster.remove(1, 9, 3);
    assert!(matches!(
        link.call(ControlRpc::Submit(borrowed), ttl).await,
        Ok(ControlReply::Refused)
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
        cluster.router.dialer(1),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voter_without_a_signed_enrollment_has_no_authority() {
    let mut cluster = Cluster::new(4);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;

    // What a device holding only a voter's transport identity could do if
    // it led: a membership entry carries no signature. Device 4 is made a
    // voter in one change: added first as a learner, the leader would be
    // removing it, as a learner no enrollment waits for, when the second
    // change came.
    let raft = cluster.running[&leader].raft();
    raft.change_membership(
        ChangeMembers::AddVoters(BTreeMap::from([(4, cluster.node_info(4))])),
        false,
    )
    .await
    .unwrap();
    cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;
    let node = &cluster.running[&leader];
    let state = node.state();
    assert_eq!(state.members(), BTreeSet::from([1, 2, 3]));
    assert!(!state.is_settled_member(4));
    assert!(!node.directory().members().contains_key(&4));

    // It can ask for nothing, and no member's request gives it keys.
    let request = cluster.request(
        4,
        1,
        ControlRequest::CancelEnrollment {
            request_id: [0; 16],
        },
    );
    assert_eq!(
        node.submit(request).await.unwrap(),
        Outcome::Rejected(Rejection::Unauthorized)
    );
    assert!(invalid(
        &node.submit(cluster.grant(1, 2, 4, &[1])).await.unwrap()
    ));
    let removal = |id, remaining: &[DeviceId]| {
        cluster.request(
            1,
            id,
            ControlRequest::ProposeChange(MembershipChange::Remove {
                device: 3,
                rotation: cluster.rotation(2, remaining),
            }),
        )
    };
    assert!(invalid(&node.submit(removal(3, &[1, 2, 4])).await.unwrap()));
    assert_eq!(
        node.submit(removal(4, &[1, 2])).await.unwrap(),
        Outcome::Accepted
    );
    cluster.settle(&[1, 2, 4], &[1, 2, 4]).await;
    let state = cluster.running[&1].state();
    assert_eq!(state.epoch, 2);
    assert_eq!(
        state.envelopes.keys().copied().collect::<Vec<_>>(),
        vec![1, 2]
    );

    // A member can remove it like any voter.
    let leader = cluster.leader().await;
    let eviction = cluster.request(
        1,
        5,
        ControlRequest::ProposeChange(MembershipChange::Remove {
            device: 4,
            rotation: cluster.rotation(3, &[1, 2]),
        }),
    );
    assert_eq!(
        cluster.running[&leader].submit(eviction).await.unwrap(),
        Outcome::Accepted
    );
    cluster.settle(&[1, 2], &[1, 2]).await;
    assert_eq!(cluster.running[&1].state().removed.get(&4), Some(&1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_are_accepted_from_recorded_and_introduced_devices_only() {
    let mut cluster = Cluster::new(5);
    for device in [1, 2, 3] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;
    let node = &cluster.running[&leader];
    let directory = node.directory();
    // `node_info` pins device N to a certificate hash of N repeated.
    let pin = |device: DeviceId| [device as u8; 32];
    for device in [1, 2, 3] {
        assert_eq!(cluster.node_info(device).transport_pin, pin(device));
        assert_eq!(directory.device_for_pin(&pin(device)), Some(device));
        assert!(directory.is_member(device));
    }
    assert_eq!(directory.device_for_pin(&pin(4)), None);

    // A certificate identifies one device.
    let mut duplicate = cluster.node_info(4);
    duplicate.transport_pin = pin(2);
    let reused = cluster.request(
        1,
        1,
        ControlRequest::ProposeChange(MembershipChange::Enroll {
            device: 4,
            node: duplicate,
            votes: true,
        }),
    );
    assert!(invalid(&node.submit(reused).await.unwrap()));

    // A device is accepted from the moment its enrollment is proposed, so
    // it can announce itself, but it is not a member until it completes.
    assert_eq!(
        node.submit(cluster.enroll(1, 2, 4)).await.unwrap(),
        Outcome::Accepted
    );
    assert_eq!(directory.device_for_pin(&pin(4)), Some(4));
    assert!(!directory.is_member(4));
    assert!(!directory.members().contains_key(&4));
    cluster.start(4, CrashPlan::default()).await;
    cluster.settle(&[1, 2, 3, 4], &[1, 2, 3, 4]).await;
    assert!(directory.is_member(4));

    // An introduction is honoured until the log says otherwise.
    directory.introduce([(5, pin(5)), (2, [0xEE; 32])]);
    assert_eq!(directory.device_for_pin(&pin(5)), Some(5));
    assert_eq!(directory.device_for_pin(&pin(2)), Some(2));
    assert_eq!(directory.device_for_pin(&[0xEE; 32]), None);
    // Two introduced devices claiming one certificate: neither is accepted
    // by it. A certificate the log records stays with its device.
    directory.introduce([(6, pin(5)), (7, pin(1))]);
    assert_eq!(directory.device_for_pin(&pin(5)), None);
    assert_eq!(directory.device_for_pin(&pin(1)), Some(1));

    // A removed device is refused, whatever a member said about it.
    let leader = cluster.leader().await;
    let removed = if leader == 4 { 3 } else { 4 };
    let removal = cluster.remove(leader, 3, removed);
    assert_eq!(
        cluster.running[&leader].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    let remaining: Vec<DeviceId> = [1, 2, 3, 4]
        .into_iter()
        .filter(|device| *device != removed)
        .collect();
    cluster.settle(&remaining, &remaining).await;
    let directory = cluster.running[&leader].directory();
    directory.introduce([(removed, pin(removed))]);
    assert_eq!(directory.device_for_pin(&pin(removed)), None);
    // Its certificate is remembered only to tell it that it was removed.
    assert_eq!(
        directory.removed_device_for_pin(&pin(removed)),
        Some(removed)
    );
    assert_eq!(directory.removed_device_for_pin(&pin(leader)), None);
    assert!(!directory.is_member(removed));

    // While another device's change is pending, the rest stay members;
    // the device being removed does not.
    let other = remaining
        .iter()
        .copied()
        .find(|device| *device != leader)
        .unwrap();
    cluster.crash(other).await;
    let leaving = remaining
        .iter()
        .copied()
        .find(|device| *device != leader && *device != other)
        .unwrap();
    let removal = cluster.remove(leader, 4, leaving);
    assert_eq!(
        cluster.running[&leader].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let state = cluster.running[&leader].state();
    assert!(state.pending.is_some());
    assert!(state.is_active_member(leader) && state.is_active_member(other));
    assert!(!state.is_active_member(leaving));
    assert!(!directory.is_member(leaving));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_far_behind_catches_up_from_the_signed_log_and_refuses_remote_snapshots() {
    let mut cluster = Cluster::new(4);
    for device in [1, 2, 3] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;
    let removed = if leader == 3 { 2 } else { 3 };
    let removal = cluster.remove(leader, 1, removed);
    assert_eq!(
        cluster.running[&leader].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    let remaining: Vec<DeviceId> = [1, 2, 3]
        .into_iter()
        .filter(|device| *device != removed)
        .collect();
    cluster.settle(&remaining, &remaining).await;

    // Even a remote snapshot sent by the current leader is refused: v1
    // snapshots carry no quorum signatures, so nodes must catch up by
    // replaying the full signed log instead.
    let leader = cluster.leader_among(&remaining).await;
    let follower = remaining
        .iter()
        .copied()
        .find(|device| *device != leader)
        .unwrap();
    let snapshot_rpc = ControlRpc::InstallSnapshot(InstallSnapshotRequest {
        vote: Vote::new_committed(99, leader),
        meta: SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
            snapshot_id: "remote".into(),
        },
        offset: 0,
        data: serde_json::to_vec(&cluster.running[&leader].state()).unwrap(),
        done: true,
    });
    assert!(matches!(
        cluster.running[&follower]
            .handle(leader, snapshot_rpc)
            .await,
        ControlReply::Refused
    ));

    // A new device catches up from index 1 over the retained signed log and
    // ends up with the same state, surviving crash and restart.
    let enrollment = cluster.enroll(leader, 2, 4);
    assert_eq!(
        cluster.running[&leader].submit(enrollment).await.unwrap(),
        Outcome::Accepted
    );
    cluster.start(4, CrashPlan::default()).await;
    let mut voters = remaining.clone();
    voters.push(4);
    cluster.settle(&voters, &voters).await;
    let joined = &cluster.running[&4];
    let state = joined.state();
    assert_eq!(state.epoch, 2);
    assert_eq!(state.removed, cluster.running[&leader].state().removed);
    assert_eq!(state.vault_id, VAULT);
    assert_eq!(state.enrolled_node(4), Some(&cluster.node_info(4)));

    cluster.crash(4).await;
    cluster.start(4, CrashPlan::default()).await;
    assert_eq!(cluster.running[&4].state().epoch, 2);
    cluster.settle(&voters, &voters).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unauthenticated_install_snapshot_cannot_inject_authors_or_steal_keys() {
    let mut cluster = Cluster::new(3);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;
    let leader = cluster.leader().await;
    let victim = [1, 2, 3]
        .into_iter()
        .find(|device| *device != leader)
        .unwrap();

    // Craft a poisoned snapshot claiming epoch 2, adding attacker device 99
    // as an enrolled author and clearing keys_held to harvest key grants.
    let mut forged = cluster.running[&victim].state();
    let attacker: DeviceId = 99;
    let attacker_key = SigningKey::from_bytes(&[99; 32]);
    let attacker_node = DeviceNode {
        public_key: attacker_key.verifying_key().to_bytes(),
        transport_pin: [99; 32],
        recipient_key: HpkeKeyPair::from_secret(&[149; 32]).public().as_bytes(),
    };
    forged.epoch = 2;
    forged.epoch_checks.insert(2, check(2));
    forged.authors.insert(attacker, attacker_node.public_key);
    forged
        .enrolled_nodes
        .insert(attacker, attacker_node.clone());
    forged.keys_held.clear();
    let forged_bytes = serde_json::to_vec(&forged).unwrap();

    let make_rpc = |sender: DeviceId| {
        ControlRpc::InstallSnapshot(InstallSnapshotRequest {
            vote: Vote::new_committed(50, sender),
            meta: SnapshotMeta {
                last_log_id: Some(openraft::LogId::new(
                    openraft::CommittedLeaderId::new(50, sender),
                    100,
                )),
                last_membership: Default::default(),
                snapshot_id: "poisoned".into(),
            },
            offset: 0,
            data: forged_bytes.clone(),
            done: true,
        })
    };

    // Refused whether sent by a compromised voter or an outside device.
    assert!(matches!(
        cluster.running[&victim]
            .handle(leader, make_rpc(leader))
            .await,
        ControlReply::Refused
    ));
    assert!(matches!(
        cluster.running[&victim]
            .handle(attacker, make_rpc(attacker))
            .await,
        ControlReply::Refused
    ));

    let state = cluster.running[&victim].state();
    assert_eq!(state.epoch, 1);
    assert!(!state.authors.contains_key(&attacker));
    assert!(!state.is_enrolled(attacker));
    assert!(state.enrolled_node(attacker).is_none());
}

#[test]
fn an_unsigned_membership_entry_cannot_swap_recipient_key_or_transport_pin() {
    use openraft::{CommittedLeaderId, EntryPayload, LogId, Membership};

    let mut state = crate::ControlState::new(VAULT);
    let mut index = 0_u64;
    let mut apply = |state: &mut crate::ControlState,
                     payload: EntryPayload<crate::ControlConfig>| {
        index += 1;
        state.apply(LogId::new(CommittedLeaderId::new(1, 1), index), &payload)
    };
    let key = |device: DeviceId| SigningKey::from_bytes(&[device as u8; 32]);
    let hpke = |device: DeviceId| HpkeKeyPair::from_secret(&[device as u8 + 50; 32]);
    let node = |device: DeviceId| DeviceNode {
        public_key: key(device).verifying_key().to_bytes(),
        transport_pin: [device as u8; 32],
        recipient_key: hpke(device).public().as_bytes(),
    };
    let request = |by: DeviceId, id: u8, req: ControlRequest| {
        EntryPayload::Normal(crate::ControlEntry::Request(SignedRequest::sign(
            &VAULT,
            [id; 16],
            by,
            req,
            &KeySigner {
                device: by,
                key: key(by),
            },
        )))
    };

    // Device 1 founds the vault at epoch 1 with historical non-voter author 9.
    let initial = BTreeMap::from([(1, node(1))]);
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(vec![BTreeSet::from([1])], initial)),
    );
    assert_eq!(
        apply(
            &mut state,
            request(
                1,
                0,
                ControlRequest::Genesis {
                    epoch: 1,
                    checks: vec![check(1)],
                    authors: vec![(9, key(9).verifying_key().to_bytes())],
                },
            ),
        ),
        Outcome::Accepted
    );

    // Promoting non-founder historical author 9 via unsigned membership does
    // not enroll it, grant it keys, or let it sign requests.
    let with_author_9 = BTreeMap::from([(1, node(1)), (9, node(9))]);
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(vec![BTreeSet::from([1, 9])], with_author_9)),
    );
    assert!(!state.is_enrolled(9));
    assert!(state.enrolled_node(9).is_none());
    let author_9_envelope = seal_epoch_key(
        VaultId(VAULT),
        1,
        osm_vault_sync::DeviceId(node(9).public_key),
        hpke(9).public(),
        &epoch_key(1),
    )
    .unwrap()
    .to_bytes()
    .to_vec();
    assert!(matches!(
        apply(
            &mut state,
            request(
                1,
                1,
                ControlRequest::GrantKeys {
                    device: 9,
                    envelopes: vec![author_9_envelope],
                },
            ),
        ),
        Outcome::Rejected(_)
    ));
    assert!(matches!(
        apply(
            &mut state,
            request(
                9,
                2,
                ControlRequest::ProposeChange(MembershipChange::Enroll {
                    device: 3,
                    node: node(3),
                    votes: true,
                }),
            ),
        ),
        Outcome::Rejected(_)
    ));

    // Restore membership to [1] and properly enroll device 2.
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1])],
            BTreeMap::from([(1, node(1))]),
        )),
    );
    assert_eq!(
        apply(
            &mut state,
            request(
                1,
                3,
                ControlRequest::ProposeChange(MembershipChange::Enroll {
                    device: 2,
                    node: node(2),
                    votes: true,
                }),
            ),
        ),
        Outcome::Accepted
    );
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1, 2])],
            BTreeMap::from([(1, node(1)), (2, node(2))]),
        )),
    );
    assert_eq!(
        apply(
            &mut state,
            EntryPayload::Normal(crate::ControlEntry::Complete {
                request_id: [3; 16]
            }),
        ),
        Outcome::Accepted
    );
    assert_eq!(state.enrolled_node(2), Some(&node(2)));

    // An unsigned membership entry swaps device 2's recipient_key and
    // transport_pin to an attacker's keys while keeping its public_key.
    let attacker_hpke = HpkeKeyPair::from_secret(&[0xEE; 32]);
    let attacker_pin = [0xDD; 32];
    let tampered_node_2 = DeviceNode {
        public_key: node(2).public_key,
        transport_pin: attacker_pin,
        recipient_key: attacker_hpke.public().as_bytes(),
    };
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1, 2])],
            BTreeMap::from([(1, node(1)), (2, tampered_node_2.clone())]),
        )),
    );

    // State keeps the signed enrolled node, rejects envelopes sealed to the
    // attacker's HPKE key, and Directory refuses the attacker's transport pin.
    assert_eq!(state.enrolled_node(2), Some(&node(2)));
    let forged_envelope = seal_epoch_key(
        VaultId(VAULT),
        1,
        osm_vault_sync::DeviceId(node(2).public_key),
        attacker_hpke.public(),
        &epoch_key(1),
    )
    .unwrap()
    .to_bytes()
    .to_vec();
    assert!(matches!(
        apply(
            &mut state,
            request(
                1,
                4,
                ControlRequest::GrantKeys {
                    device: 2,
                    envelopes: vec![forged_envelope],
                },
            ),
        ),
        Outcome::Rejected(_)
    ));

    let (_tx, rx) = tokio::sync::watch::channel(openraft::RaftMetrics::new_initial(1));
    let directory = crate::Directory::new(1, Arc::new(std::sync::Mutex::new(state.clone())), rx);
    assert_eq!(directory.device_for_pin(&node(2).transport_pin), Some(2));
    assert_eq!(directory.device_for_pin(&attacker_pin), None);
    assert_eq!(directory.members().get(&2), Some(&node(2).transport_pin));

    // Honest-leader learner-reuse defense: pre-seeding device 3 as a learner
    // with a forged DeviceNode must NOT allow a signed Enroll for device 3 to
    // complete until the node entry matches the signed Enroll node.
    let forged_node_3 = DeviceNode {
        public_key: node(3).public_key,
        transport_pin: [0xCC; 32],
        recipient_key: attacker_hpke.public().as_bytes(),
    };
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1, 2])],
            BTreeMap::from([(1, node(1)), (2, node(2)), (3, forged_node_3.clone())]),
        )),
    );
    assert_eq!(
        apply(
            &mut state,
            request(
                1,
                5,
                ControlRequest::ProposeChange(MembershipChange::Enroll {
                    device: 3,
                    node: node(3),
                    votes: true,
                }),
            ),
        ),
        Outcome::Accepted
    );
    // Promoting device 3 with the pre-seeded forged node does not satisfy
    // `in_effect`, so Complete is rejected.
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1, 2, 3])],
            BTreeMap::from([(1, node(1)), (2, node(2)), (3, forged_node_3)]),
        )),
    );
    assert!(matches!(
        apply(
            &mut state,
            EntryPayload::Normal(crate::ControlEntry::Complete {
                request_id: [5; 16]
            }),
        ),
        Outcome::Rejected(_)
    ));
    // Replacing device 3's entry with the signed node lets Complete succeed.
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1, 2, 3])],
            BTreeMap::from([(1, node(1)), (2, node(2)), (3, node(3))]),
        )),
    );
    assert_eq!(
        apply(
            &mut state,
            EntryPayload::Normal(crate::ControlEntry::Complete {
                request_id: [5; 16]
            }),
        ),
        Outcome::Accepted
    );
    assert_eq!(state.enrolled_node(3), Some(&node(3)));
}

#[tokio::test]
async fn bounded_snapshot_data_refuses_large_seeks_and_writes_before_allocating() {
    use std::io::SeekFrom;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    let mut snap = crate::BoundedSnapshotData::new(1024);
    assert!(snap
        .seek(SeekFrom::Start(4 * 1024 * 1024 * 1024))
        .await
        .is_err());
    assert!(snap.seek(SeekFrom::Start(1025)).await.is_err());
    assert!(snap.write_all(&vec![0u8; 1025]).await.is_err());
    assert!(snap.into_inner().is_empty());

    let mut snap = crate::BoundedSnapshotData::new(1024);
    snap.seek(SeekFrom::Start(1000)).await.unwrap();
    assert!(snap.write_all(&[1u8; 25]).await.is_err());
    snap.write_all(&[2u8; 24]).await.unwrap();
    assert_eq!(snap.into_inner().len(), 1024);
}

#[test]
fn directory_removal_requires_quorum_of_committed_enrolled_voters() {
    use openraft::{EntryPayload, LogId, Membership};

    let keys: BTreeMap<DeviceId, SigningKey> = (1..=4)
        .map(|id| (DeviceId::from(id), SigningKey::from_bytes(&[id; 32])))
        .collect();
    let node = |id: DeviceId| DeviceNode {
        public_key: keys[&id].verifying_key().to_bytes(),
        transport_pin: [id as u8; 32],
        recipient_key: Cluster::hpke(id).public().as_bytes(),
    };
    let mut index = 0u64;
    let mut apply = |state: &mut crate::ControlState,
                     payload: EntryPayload<crate::ControlConfig>| {
        index += 1;
        state.apply(
            LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
            &payload,
        )
    };
    let sign = |requester: DeviceId, id: u8, req: ControlRequest| {
        EntryPayload::Normal(crate::ControlEntry::Request(SignedRequest::sign(
            &VAULT,
            [id; 16],
            requester,
            req,
            &KeySigner {
                device: requester,
                key: keys[&requester].clone(),
            },
        )))
    };

    // 1-voter cluster {1} + non-voter phone {4}: sole voter 1 cannot be
    // declared removed by phone 4, whereas voter 1 CAN confirm removal of 4.
    let mut state = crate::ControlState::new(VAULT);
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1])],
            BTreeMap::from([(1, node(1))]),
        )),
    );
    assert_eq!(
        apply(
            &mut state,
            sign(
                1,
                1,
                ControlRequest::Genesis {
                    epoch: 1,
                    checks: vec![check(1)],
                    authors: Vec::new(),
                },
            ),
        ),
        Outcome::Accepted
    );
    assert_eq!(
        apply(
            &mut state,
            sign(
                1,
                2,
                ControlRequest::ProposeChange(MembershipChange::Enroll {
                    device: 4,
                    node: node(4),
                    votes: false,
                }),
            ),
        ),
        Outcome::Accepted
    );
    apply(
        &mut state,
        EntryPayload::Membership(Membership::new(
            vec![BTreeSet::from([1])],
            BTreeMap::from([(1, node(1)), (4, node(4))]),
        )),
    );
    assert_eq!(
        apply(
            &mut state,
            EntryPayload::Normal(crate::ControlEntry::Complete {
                request_id: [2; 16]
            }),
        ),
        Outcome::Accepted
    );
    let (_tx, rx) = tokio::sync::watch::channel(openraft::RaftMetrics::new_initial(1));
    let dir_voter = crate::Directory::new(
        1,
        Arc::new(std::sync::Mutex::new(state.clone())),
        rx.clone(),
    );
    assert!(!dir_voter.removal_confirmed(&BTreeSet::from([4])));
    assert!(!dir_voter.is_voter(4));
    assert!(dir_voter.is_voter(1));
    let dir_phone = crate::Directory::new(
        4,
        Arc::new(std::sync::Mutex::new(state.clone())),
        rx.clone(),
    );
    assert!(dir_phone.removal_confirmed(&BTreeSet::from([1])));

    // 3-voter cluster {1, 2, 3}: 1 voter reporting removal of 3 is a minority
    // (1 < 2), while 2 voters {1, 2} form a strict majority (2 >= 2).
    for (req_id, dev) in [(3u8, 2u128), (4u8, 3u128)] {
        assert_eq!(
            apply(
                &mut state,
                sign(
                    1,
                    req_id,
                    ControlRequest::ProposeChange(MembershipChange::Enroll {
                        device: dev,
                        node: node(dev),
                        votes: true,
                    }),
                ),
            ),
            Outcome::Accepted
        );
        let voters: BTreeSet<DeviceId> = if dev == 2 {
            BTreeSet::from([1, 2])
        } else {
            BTreeSet::from([1, 2, 3])
        };
        let mut nodes = BTreeMap::from([(1, node(1)), (2, node(2)), (4, node(4))]);
        if dev == 3 {
            nodes.insert(3, node(3));
        }
        apply(
            &mut state,
            EntryPayload::Membership(Membership::new(vec![voters], nodes)),
        );
        assert_eq!(
            apply(
                &mut state,
                EntryPayload::Normal(crate::ControlEntry::Complete {
                    request_id: [req_id; 16]
                }),
            ),
            Outcome::Accepted
        );
    }
    let dir_three = crate::Directory::new(3, Arc::new(std::sync::Mutex::new(state)), rx);
    assert!(!dir_three.removal_confirmed(&BTreeSet::from([4])));
    assert!(!dir_three.removal_confirmed(&BTreeSet::from([1])));
    assert!(!dir_three.removal_confirmed(&BTreeSet::from([1, 4])));
    assert!(dir_three.removal_confirmed(&BTreeSet::from([1, 2])));
}

mod fixtures;
mod properties;
mod without_vote;
