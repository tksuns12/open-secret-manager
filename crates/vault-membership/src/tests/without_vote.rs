//! Members without a vote: devices, such as phones, that are sent the log
//! and given the vault's keys like any member, and count toward no
//! majority, so being off or out of reach never holds up a change.

use std::{collections::BTreeSet, time::Duration};

use ed25519_dalek::SigningKey;
use openraft::ServerState;
use serde_json::{json, Value};

use super::{
    fixtures::{counting, differences, folder, hex, round_trip},
    invalid, Cluster,
};
use crate::{
    device_id_from_bytes, ControlEntry, ControlRequest, ControlState, CrashPlan, DeviceId,
    DeviceNode, Error, KeySigner, MembershipChange, Outcome, Rejection, SignedRequest,
};

impl Cluster {
    /// Waits until `check` holds for the applied state of every device in
    /// `devices`.
    async fn until(&self, devices: &[DeviceId], what: &str, check: impl Fn(&ControlState) -> bool) {
        for _ in 0..400 {
            if devices
                .iter()
                .all(|device| check(&self.running[device].state()))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("never saw: {what}");
    }

    /// Enrolls `device` without a vote through the leader and waits until
    /// every running device has it as a settled member.
    async fn add_without_vote(&self, id: u8, device: DeviceId) {
        let leader = self.leader().await;
        let enrollment = self.enroll_without_vote(leader, id, device);
        assert_eq!(
            self.running[&leader].submit(enrollment).await.unwrap(),
            Outcome::Accepted
        );
        let running: Vec<DeviceId> = self.running.keys().copied().collect();
        self.until(&running, "the member without a vote enrolled", |state| {
            state.pending.is_none() && state.is_settled_member(device)
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_without_a_vote_is_sent_the_log_and_keys_and_counts_toward_no_majority() {
    let mut cluster = Cluster::new(3);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2]).await;
    cluster.add_without_vote(1, 3).await;

    for device in [1, 2, 3] {
        let state = cluster.running[&device].state();
        assert_eq!(state.voters(), BTreeSet::from([1, 2]));
        assert_eq!(state.members(), BTreeSet::from([1, 2, 3]));
        assert_eq!(state.without_vote, BTreeSet::from([3]));
        assert!(state.votes(1) && state.votes(2) && !state.votes(3));
    }
    // A learner to Raft: it follows the log and never stands for election.
    let metrics = cluster.running[&3].raft().metrics().borrow().clone();
    assert_eq!(metrics.state, ServerState::Learner);

    // It is given the keys like any member.
    assert_eq!(cluster.running[&1].state().missing_epochs(3), vec![1]);
    let leader = cluster.leader().await;
    let grant = cluster.grant(leader, 2, 3, &[1]);
    assert_eq!(
        cluster.running[&leader].submit(grant).await.unwrap(),
        Outcome::Accepted
    );
    cluster
        .until(
            &[1, 2, 3],
            "the member without a vote holds the key",
            |state| state.missing_epochs(3).is_empty() && state.envelopes[&3].contains_key(&1),
        )
        .await;

    // With one of the two voters gone, nothing commits, although the member
    // without a vote is there: it does not count.
    cluster.crash(2).await;
    let stranded = cluster.grant(1, 3, 3, &[1]);
    let result = cluster.running[&1].submit(stranded).await;
    assert!(
        matches!(result, Err(Error::QuorumUnavailable | Error::NotLeader(_))),
        "{result:?}"
    );
    // With both voters and without it, everything does.
    cluster.start(2, CrashPlan::default()).await;
    cluster.crash(3).await;
    let leader = cluster.leader_among(&[1, 2]).await;
    let removal = cluster.remove(leader, 4, 3);
    assert_eq!(
        cluster.running[&leader].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    cluster
        .until(&[1, 2], "the member without a vote removed", |state| {
            state.pending.is_none() && state.removed.contains_key(&3)
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_with_one_voter_removes_a_lost_member_without_a_vote() {
    let mut cluster = Cluster::new(2);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1]).await;
    cluster.add_without_vote(1, 2).await;
    let grant = cluster.grant(1, 2, 2, &[1]);
    assert_eq!(
        cluster.running[&1].submit(grant).await.unwrap(),
        Outcome::Accepted
    );

    // The phone is lost. The one voter is a majority by itself.
    cluster.crash(2).await;
    let removal = cluster.remove(1, 3, 2);
    assert_eq!(
        cluster.running[&1].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    cluster
        .until(&[1], "the lost member removed", |state| {
            state.pending.is_none()
                && state.epoch == 2
                && state.removed.get(&2) == Some(&1)
                && state.node(2).is_none()
                && state.without_vote.is_empty()
                && !state.is_enrolled(2)
        })
        .await;
    let state = cluster.running[&1].state();
    assert!(!state.envelopes.contains_key(&2));
    assert_eq!(state.members(), BTreeSet::from([1]));
    // It cannot be enrolled again, with a vote or without.
    let again = cluster.enroll_without_vote(1, 4, 2);
    assert!(invalid(&cluster.running[&1].submit(again).await.unwrap()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_rotates_the_key_to_members_without_a_vote_too() {
    let mut cluster = Cluster::new(4);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2, 3]).await;
    cluster.add_without_vote(1, 4).await;

    // Device 1 removes device 3. A new key sealed to the remaining voters
    // alone leaves the member without a vote out, and is refused.
    let mut rotation = cluster.rotation(2, &[1, 2]);
    let refused = cluster.request(
        1,
        2,
        ControlRequest::ProposeChange(MembershipChange::Remove {
            device: 3,
            rotation: rotation.clone(),
        }),
    );
    assert!(invalid(&cluster.running[&1].submit(refused).await.unwrap()));
    rotation.envelopes.push((4, cluster.envelope(4, 2)));
    let removal = cluster.request(
        1,
        3,
        ControlRequest::ProposeChange(MembershipChange::Remove {
            device: 3,
            rotation,
        }),
    );
    assert_eq!(
        cluster.running[&1].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    let remaining: Vec<DeviceId> = vec![1, 2, 4];
    cluster
        .until(&remaining, "the removal completed", |state| {
            state.pending.is_none() && state.epoch == 2 && state.removed.contains_key(&3)
        })
        .await;
    for device in remaining {
        let state = cluster.running[&device].state();
        assert!(state.keys_held[&4].contains(&2));
        assert!(state.envelopes[&4].contains_key(&2));
        assert_eq!(state.voters(), BTreeSet::from([1, 2]));
        assert_eq!(state.without_vote, BTreeSet::from([4]));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_without_a_vote_may_ask_and_its_kind_of_enrollment_cannot_be_changed() {
    let mut cluster = Cluster::new(4);
    for device in [1, 2, 3] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1, 2]).await;
    cluster.add_without_vote(1, 3).await;

    // Its requests count like a voter's: it asks for another device.
    let asked = cluster.enroll(3, 2, 4);
    assert_eq!(
        cluster.running[&3].submit(asked).await.unwrap(),
        Outcome::Accepted
    );
    let leader = cluster.leader().await;
    let cancel = cluster.request(
        leader,
        3,
        ControlRequest::CancelEnrollment {
            request_id: [2; 16],
        },
    );
    assert_eq!(
        cluster.running[&leader].submit(cancel).await.unwrap(),
        Outcome::Accepted
    );
    cluster
        .until(&[1, 2, 3], "the cancelled enrollment ended", |state| {
            state.pending.is_none()
        })
        .await;

    // An enrollment signed as one kind does not pass as the other.
    let mut flipped = cluster.enroll_without_vote(leader, 4, 4);
    if let ControlRequest::ProposeChange(MembershipChange::Enroll { votes, .. }) =
        &mut flipped.request
    {
        *votes = true;
    }
    assert_eq!(
        cluster.running[&leader].submit(flipped).await.unwrap(),
        Outcome::Rejected(Rejection::BadSignature)
    );
    // A member is not enrolled twice, as either kind.
    for request in [
        cluster.enroll(leader, 5, 3),
        cluster.enroll_without_vote(leader, 6, 3),
        cluster.enroll_without_vote(leader, 7, 2),
    ] {
        assert!(invalid(
            &cluster.running[&leader].submit(request).await.unwrap()
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrollment_without_a_vote_whose_device_never_appears_is_cancelled_cleanly() {
    let mut cluster = Cluster::new(3);
    for device in [1, 2] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1, 2]).await;
    let leader = cluster.leader().await;
    let enrollment = cluster.enroll_without_vote(leader, 1, 3);
    assert_eq!(
        cluster.running[&leader].submit(enrollment).await.unwrap(),
        Outcome::Accepted
    );
    // Device 3 never starts, so it never catches up and never completes.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(cluster.running[&leader].state().pending.is_some());
    let cancel = cluster.request(
        leader,
        2,
        ControlRequest::CancelEnrollment {
            request_id: [1; 16],
        },
    );
    assert_eq!(
        cluster.running[&leader].submit(cancel).await.unwrap(),
        Outcome::Accepted
    );
    cluster.settle(&[1, 2], &[1, 2]).await;
    cluster.learners_removed(1).await;
    let state = cluster.running[&1].state();
    assert!(!state.is_enrolled(3) && state.without_vote.is_empty());
    assert!(!state.authors.contains_key(&3));
}

/// The frozen form of what members without a vote added: the enrollment's
/// signed bytes and stored texts, and a state holding such a member.
fn vectors() -> Value {
    let vault_id: [u8; 32] = counting(0x10);
    let device = device_id_from_bytes(counting(0xf0));
    let other = device_id_from_bytes(counting(0x40));
    let signer = KeySigner {
        device,
        key: SigningKey::from_bytes(&counting(0x60)),
    };
    let node = DeviceNode {
        public_key: counting(0x01),
        transport_pin: counting(0x21),
        recipient_key: counting(0x41),
    };
    let request = ControlRequest::ProposeChange(MembershipChange::Enroll {
        device: other,
        node,
        votes: false,
    });
    let signed = SignedRequest::sign(&vault_id, [7; 16], signer.device, request, &signer);
    assert!(signed.verify(&vault_id, &signer.key.verifying_key().to_bytes()));
    let mut state = ControlState::new(vault_id);
    state.epoch = 1;
    state.without_vote.insert(other);
    json!({
        "about": "What members without a vote added to the control-plane formats, with the inputs of vectors.json. An enrollment without a vote is signed under tag 6 instead of 2, and stored with \"votes\":false; a voting enrollment is stored as before, without the field. A state lists its members without a vote under without_vote, which is absent while there are none.",
        "enroll_without_vote": {
            "signed_message": hex(&signed.signed_message(&vault_id)),
            "signature": hex(&signed.signature),
            "as_log_entry": serde_json::to_string(&ControlEntry::Request(signed)).unwrap(),
        },
        "state_with_a_member_without_a_vote": serde_json::to_string(&state).unwrap(),
    })
}

#[test]
fn members_without_a_vote_are_signed_and_stored_as_frozen() {
    let path = folder().join("without-vote.json");
    let made = vectors();
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&made).unwrap() + "\n").unwrap();
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found = Vec::new();
    differences("without-vote", &frozen, &made, &mut found);
    assert!(found.is_empty(), "no longer as frozen: {found:#?}");

    let stored = frozen["enroll_without_vote"]["as_log_entry"]
        .as_str()
        .unwrap();
    let ControlEntry::Request(request) = round_trip::<ControlEntry>(stored) else {
        panic!("not a request");
    };
    assert!(matches!(
        request.request,
        ControlRequest::ProposeChange(MembershipChange::Enroll { votes: false, .. })
    ));
    assert_eq!(
        hex(&request.signed_message(&counting(0x10))),
        frozen["enroll_without_vote"]["signed_message"]
    );
    let state: ControlState = round_trip(
        frozen["state_with_a_member_without_a_vote"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(state.without_vote.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_without_a_vote_that_a_stray_entry_made_a_voter_is_still_removed() {
    let mut cluster = Cluster::new(3);
    cluster.start_all(CrashPlan::default()).await;
    cluster.bootstrap(&[1, 2]).await;
    cluster.add_without_vote(1, 3).await;

    // A membership entry carries no signature: whoever holds a voter's
    // transport identity can make the phone a voter.
    let leader = cluster.leader().await;
    cluster.running[&leader]
        .raft()
        .change_membership(BTreeSet::from([1, 2, 3]), false)
        .await
        .unwrap();
    cluster
        .until(&[1, 2, 3], "the phone made a voter", |state| {
            state.voters() == BTreeSet::from([1, 2, 3]) && state.is_uniform()
        })
        .await;
    // That gives it a vote, not a different enrollment: it is still listed
    // as a member without one, with the same keys and authority.
    assert!(cluster.running[&1].state().without_vote.contains(&3));

    // Its removal completes as a voter's would.
    let removal = cluster.remove(1, 2, 3);
    assert_eq!(
        cluster.running[&1].submit(removal).await.unwrap(),
        Outcome::Accepted
    );
    cluster
        .until(&[1, 2], "the removal completed", |state| {
            state.pending.is_none()
                && state.removed.contains_key(&3)
                && state.voters() == BTreeSet::from([1, 2])
                && state.node(3).is_none()
                && state.without_vote.is_empty()
        })
        .await;
}
