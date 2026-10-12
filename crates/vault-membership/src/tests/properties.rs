//! The state machine under any sequence of entries: membership entries,
//! which carry no signature and may say anything, and requests and
//! completions of every kind, valid or not. Whatever the log holds, keys
//! and authority follow signed enrollment and removal. The cases are new on
//! every run; a failing one is kept in `proptest-regressions/`.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use openraft::{CommittedLeaderId, EntryPayload, LogId, Membership};
use osm_vault_sync::{seal_epoch_key, HpkeKeyPair, VaultId};
use proptest::prelude::*;

use super::VAULT;
use crate::{
    ControlConfig, ControlEntry, ControlRequest, ControlState, DeviceId, DeviceNode, KeySigner,
    MembershipChange, Outcome, Rotation, SignedRequest,
};

const DEVICES: [DeviceId; 5] = [1, 2, 3, 4, 5];

fn key(device: DeviceId) -> SigningKey {
    SigningKey::from_bytes(&[device as u8; 32])
}

fn hpke(device: DeviceId) -> HpkeKeyPair {
    HpkeKeyPair::from_secret(&[device as u8 + 50; 32])
}

fn node(device: DeviceId) -> DeviceNode {
    DeviceNode {
        public_key: key(device).verifying_key().to_bytes(),
        transport_pin: [device as u8; 32],
        recipient_key: hpke(device).public().as_bytes(),
    }
}

fn envelope(device: DeviceId, epoch: u64) -> Vec<u8> {
    seal_epoch_key(
        VaultId(VAULT),
        epoch,
        osm_vault_sync::DeviceId(node(device).public_key),
        hpke(device).public(),
        &[epoch as u8; 32],
    )
    .unwrap()
    .to_bytes()
    .to_vec()
}

/// One entry of the log, described so that it can be made valid against
/// the state it meets. A number picks among the devices that state makes
/// likely: a requester among the members, a device to remove among the
/// voters, one to give keys to among the voters and the removed devices.
#[derive(Clone, Debug)]
enum Step {
    /// A membership entry naming these voters, signed by nobody.
    Voters(Vec<DeviceId>),
    /// The membership entry that makes a pending change take effect, as a
    /// leader writes it: its target voters, with the members without a vote
    /// that stay as learners.
    Settle,
    Genesis {
        by: usize,
        forged: bool,
        epoch: u64,
    },
    Enroll {
        by: usize,
        forged: bool,
        device: usize,
        id: u8,
        votes: bool,
    },
    Remove {
        by: usize,
        forged: bool,
        device: usize,
        id: u8,
        sound: bool,
    },
    Cancel {
        by: usize,
        forged: bool,
        pending: bool,
        id: u8,
    },
    Grant {
        by: usize,
        forged: bool,
        device: usize,
        id: u8,
    },
    Complete {
        pending: bool,
        id: u8,
    },
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let forged = prop::bool::weighted(0.15);
    let step = prop_oneof![
        2 => prop::sample::subsequence(DEVICES.to_vec(), 1..=5).prop_map(Step::Voters),
        4 => Just(Step::Settle),
        1 => (any::<usize>(), forged, 1_u64..3).prop_map(|(by, forged, epoch)| Step::Genesis { by, forged, epoch }),
        3 => (any::<usize>(), forged, any::<usize>(), any::<u8>(), any::<bool>())
            .prop_map(|(by, forged, device, id, votes)| Step::Enroll { by, forged, device, id, votes }),
        3 => (any::<usize>(), forged, any::<usize>(), any::<u8>(), prop::bool::weighted(0.8))
            .prop_map(|(by, forged, device, id, sound)| Step::Remove { by, forged, device, id, sound }),
        1 => (any::<usize>(), forged, any::<bool>(), any::<u8>())
            .prop_map(|(by, forged, pending, id)| Step::Cancel { by, forged, pending, id }),
        3 => (any::<usize>(), forged, any::<usize>(), any::<u8>())
            .prop_map(|(by, forged, device, id)| Step::Grant { by, forged, device, id }),
        4 => (prop::bool::weighted(0.9), any::<u8>()).prop_map(|(pending, id)| Step::Complete { pending, id }),
    ];
    // Founded first, by device 1, so that most cases reach a running
    // control plane; what follows is anything.
    prop::collection::vec(step, 1..80).prop_map(|rest| {
        [
            vec![
                Step::Voters(vec![1]),
                Step::Genesis {
                    by: 0,
                    forged: false,
                    epoch: 1,
                },
            ],
            rest,
        ]
        .concat()
    })
}

fn pick(among: &BTreeSet<DeviceId>, index: usize) -> DeviceId {
    let among: Vec<DeviceId> = if among.is_empty() {
        DEVICES.to_vec()
    } else {
        among.iter().copied().collect()
    };
    among[index % among.len()]
}

/// The entry a step stands for, against the state it meets, and who signed
/// it if it is a request.
fn entry(state: &ControlState, step: &Step) -> (EntryPayload<ControlConfig>, Option<DeviceId>) {
    let requester = |by: usize| pick(&state.members(), by);
    let signed = |by: DeviceId, forged: bool, id: u8, request: ControlRequest| {
        let signer = if forged { by % 5 + 1 } else { by };
        let key = KeySigner {
            device: signer,
            key: key(signer),
        };
        let mut request = SignedRequest::sign(&VAULT, [id; 16], signer, request, &key);
        request.requester = by;
        (
            EntryPayload::Normal(ControlEntry::Request(request)),
            Some(signer),
        )
    };
    let pending = state.pending.as_ref().map(|pending| pending.request_id);
    let membership = |voters: BTreeSet<DeviceId>, nodes: BTreeSet<DeviceId>| {
        (
            EntryPayload::Membership(Membership::new(
                vec![voters],
                nodes
                    .iter()
                    .map(|device| (*device, node(*device)))
                    .collect::<BTreeMap<_, _>>(),
            )),
            None,
        )
    };
    match step {
        // Anything: every device is in it, the ones not named as learners.
        Step::Voters(voters) => membership(
            voters.iter().copied().collect(),
            DEVICES.iter().copied().collect(),
        ),
        Step::Settle => {
            let voters = state
                .pending
                .as_ref()
                .map(|pending| pending.target_voters.clone())
                .unwrap_or_else(|| state.voters());
            let mut nodes: BTreeSet<DeviceId> =
                voters.iter().chain(&state.without_vote).copied().collect();
            match state
                .pending
                .as_ref()
                .map(|pending| (&pending.change, pending.cancelled))
            {
                Some((MembershipChange::Enroll { device, .. }, false)) => {
                    nodes.insert(*device);
                }
                Some((MembershipChange::Remove { device, .. }, _)) => {
                    nodes.remove(device);
                }
                _ => {}
            }
            membership(voters, nodes)
        }
        Step::Genesis { by, forged, epoch } => signed(
            pick(&state.voters(), *by),
            *forged,
            0,
            ControlRequest::Genesis {
                epoch: *epoch,
                checks: (1..=*epoch).map(|epoch| [epoch as u8; 32]).collect(),
                authors: Vec::new(),
            },
        ),
        Step::Enroll {
            by,
            forged,
            device,
            id,
            votes,
        } => {
            let outside: BTreeSet<DeviceId> = DEVICES
                .iter()
                .copied()
                .filter(|device| !state.voters().contains(device))
                .collect();
            let device = pick(&outside, *device);
            signed(
                requester(*by),
                *forged,
                *id,
                ControlRequest::ProposeChange(MembershipChange::Enroll {
                    device,
                    node: node(device),
                    votes: *votes,
                }),
            )
        }
        Step::Remove {
            by,
            forged,
            device,
            id,
            sound,
        } => {
            let device = pick(&state.members(), *device);
            let epoch = state.epoch + 1;
            let remaining: Vec<DeviceId> = state
                .members()
                .into_iter()
                .filter(|member| *member != device)
                .collect();
            let mut envelopes: Vec<(DeviceId, Vec<u8>)> = remaining
                .iter()
                .map(|member| (*member, envelope(*member, epoch)))
                .collect();
            if !sound {
                // Sealed to the device being removed as well.
                envelopes.push((device, envelope(device, epoch)));
            }
            signed(
                requester(*by),
                *forged,
                *id,
                ControlRequest::ProposeChange(MembershipChange::Remove {
                    device,
                    rotation: Rotation {
                        epoch,
                        check: [epoch as u8; 32],
                        envelopes,
                    },
                }),
            )
        }
        Step::Cancel {
            by,
            forged,
            pending: name_it,
            id,
        } => signed(
            requester(*by),
            *forged,
            *id,
            ControlRequest::CancelEnrollment {
                request_id: pending.filter(|_| *name_it).unwrap_or([*id; 16]),
            },
        ),
        Step::Grant {
            by,
            forged,
            device,
            id,
        } => {
            let candidates: BTreeSet<DeviceId> = state
                .voters()
                .into_iter()
                .chain(state.without_vote.iter().copied())
                .chain(state.removed.keys().copied())
                .collect();
            let device = pick(&candidates, *device);
            let mut epochs = state.missing_epochs(device);
            if epochs.is_empty() {
                epochs.push(state.epoch.max(1));
            }
            signed(
                requester(*by),
                *forged,
                *id,
                ControlRequest::GrantKeys {
                    device,
                    envelopes: epochs
                        .iter()
                        .map(|epoch| envelope(device, *epoch))
                        .collect(),
                },
            )
        }
        Step::Complete {
            pending: name_it,
            id,
        } => (
            EntryPayload::Normal(ControlEntry::Complete {
                request_id: pending.filter(|_| *name_it).unwrap_or([*id; 16]),
            }),
            None,
        ),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn keys_and_authority_follow_signed_enrollment_whatever_the_log_holds(steps in steps()) {
        let mut state = ControlState::new(VAULT);
        for (index, step) in steps.iter().enumerate() {
            let before = state.clone();
            let (payload, signer) = entry(&state, step);
            let log_id = LogId::new(CommittedLeaderId::new(1, 1), index as u64 + 1);
            let outcome = state.apply(log_id, &payload);

            // A request takes effect only from an enrolled member, voting
            // or not, or before genesis from a voter, and never from a
            // device that was removed.
            if let (EntryPayload::Normal(ControlEntry::Request(request)), Outcome::Accepted) = (&payload, &outcome) {
                let by = request.requester;
                if before.epoch == 0 {
                    prop_assert!(before.voters().contains(&by), "{step:?} before genesis from a non-voter");
                } else {
                    prop_assert!(before.is_enrolled(by), "{step:?} from a device not enrolled");
                }
                prop_assert!(!before.removed.contains_key(&by), "{step:?} accepted from a removed device");
                prop_assert_eq!(Some(by), signer, "a request signed by another device was accepted");
            }
            // A change in progress leads to a membership with a voter: Raft
            // makes no change to one without, so it would never complete.
            if let Some(pending) = &state.pending {
                prop_assert!(!pending.target_voters.is_empty(), "{step:?} left a change leading to no voter");
            }

            // The epoch only moves on, one at a time, with a check for each.
            prop_assert!(state.epoch == before.epoch || state.epoch == before.epoch + 1 || before.epoch == 0);
            if state.epoch > 0 {
                prop_assert_eq!(
                    state.epoch_checks.keys().copied().collect::<Vec<_>>(),
                    (1..=state.epoch).collect::<Vec<_>>()
                );
            }
            // Authors and removals are never taken back, and an author's key
            // never changes.
            for (device, author) in &before.authors {
                prop_assert_eq!(state.authors.get(device), Some(author));
            }
            for (device, by) in &before.removed {
                prop_assert_eq!(state.removed.get(device), Some(by));
            }
            // A removed device holds no key: not the ones it had, which are
            // forgotten at its removal, and none given after.
            for device in state.removed.keys() {
                prop_assert!(!state.keys_held.contains_key(device), "removed device {device} was given keys at {step:?}");
                prop_assert!(!state.envelopes.contains_key(device), "removed device {device} has envelopes at {step:?}");
                prop_assert!(!state.members().contains(device), "removed device {device} counts as a member at {step:?}");
            }
            for held in state.keys_held.values() {
                prop_assert!(held.iter().all(|epoch| (1..=state.epoch).contains(epoch)));
            }
            // Only a completed, signed enrollment without a vote makes a
            // device a member without one, and only its completed removal
            // ends that; no membership entry does either.
            if state.without_vote != before.without_vote {
                let completed = matches!(&payload, EntryPayload::Normal(ControlEntry::Complete { .. }))
                    && outcome == Outcome::Accepted;
                prop_assert!(completed, "{step:?} changed the members without a vote");
                let change = before.pending.as_ref().map(|pending| (&pending.change, pending.cancelled));
                for added in state.without_vote.difference(&before.without_vote) {
                    prop_assert!(
                        matches!(change, Some((MembershipChange::Enroll { device, votes: false, .. }, false)) if device == added),
                        "{added} became a member without a vote at {step:?}"
                    );
                }
                for gone in before.without_vote.difference(&state.without_vote) {
                    prop_assert!(
                        matches!(change, Some((MembershipChange::Remove { device, .. }, _)) if device == gone),
                        "{gone} stopped being a member without a vote at {step:?}"
                    );
                }
            }
        }
    }
}

/// The attack the property above found before it was fixed: someone with a
/// voter's transport identity writes membership entries, which carry no
/// signature, and puts a removed device back among the voters. It must get
/// no key and no say: not from the grants every member makes for voters
/// that lack keys, and not by signing requests of its own.
#[test]
fn a_removed_device_put_back_among_the_voters_gets_no_keys_and_no_say() {
    let mut state = ControlState::new(VAULT);
    let mut index = 0;
    let mut apply = |state: &mut ControlState, payload: EntryPayload<ControlConfig>| {
        index += 1;
        state.apply(LogId::new(CommittedLeaderId::new(1, 1), index), &payload)
    };
    let voters = |voters: &[DeviceId]| {
        EntryPayload::Membership(Membership::new(
            vec![voters.iter().copied().collect()],
            DEVICES
                .iter()
                .map(|device| (*device, node(*device)))
                .collect::<BTreeMap<_, _>>(),
        ))
    };
    let request = |by: DeviceId, id: u8, request: ControlRequest| {
        EntryPayload::Normal(ControlEntry::Request(SignedRequest::sign(
            &VAULT,
            [id; 16],
            by,
            request,
            &KeySigner {
                device: by,
                key: key(by),
            },
        )))
    };
    let complete = |id: u8| {
        EntryPayload::Normal(ControlEntry::Complete {
            request_id: [id; 16],
        })
    };

    // Device 1 founds the vault, enrolls device 2, and then removes it.
    apply(&mut state, voters(&[1]));
    let genesis = request(
        1,
        0,
        ControlRequest::Genesis {
            epoch: 1,
            checks: vec![[1; 32]],
            authors: Vec::new(),
        },
    );
    assert_eq!(apply(&mut state, genesis), Outcome::Accepted);
    let enroll = request(
        1,
        1,
        ControlRequest::ProposeChange(MembershipChange::Enroll {
            device: 2,
            node: node(2),
            votes: true,
        }),
    );
    assert_eq!(apply(&mut state, enroll), Outcome::Accepted);
    apply(&mut state, voters(&[1, 2]));
    assert_eq!(apply(&mut state, complete(1)), Outcome::Accepted);
    let remove = request(
        1,
        2,
        ControlRequest::ProposeChange(MembershipChange::Remove {
            device: 2,
            rotation: Rotation {
                epoch: 2,
                check: [2; 32],
                envelopes: vec![(1, envelope(1, 2))],
            },
        }),
    );
    assert_eq!(apply(&mut state, remove), Outcome::Accepted);
    apply(&mut state, voters(&[1]));
    assert_eq!(apply(&mut state, complete(2)), Outcome::Accepted);
    assert_eq!(state.removed.get(&2), Some(&1));

    // An unsigned entry makes it a voter again.
    apply(&mut state, voters(&[1, 2]));
    assert!(state.voters().contains(&2));
    assert!(!state.is_enrolled(2));
    assert_eq!(state.members(), [1].into());
    assert!(state.missing_epochs(2).contains(&2));
    // No member's grant reaches it, and nothing it signs counts.
    let grant = request(
        1,
        3,
        ControlRequest::GrantKeys {
            device: 2,
            envelopes: vec![envelope(2, 2)],
        },
    );
    assert!(matches!(apply(&mut state, grant), Outcome::Rejected(_)));
    let its_own = request(
        2,
        4,
        ControlRequest::ProposeChange(MembershipChange::Enroll {
            device: 3,
            node: node(3),
            votes: true,
        }),
    );
    assert!(matches!(apply(&mut state, its_own), Outcome::Rejected(_)));
    assert!(!state.keys_held.contains_key(&2));

    // Removing it again takes it out of the voters; its first removal is
    // what is recorded.
    let again = request(
        1,
        5,
        ControlRequest::ProposeChange(MembershipChange::Remove {
            device: 2,
            rotation: Rotation {
                epoch: 3,
                check: [3; 32],
                envelopes: vec![(1, envelope(1, 3))],
            },
        }),
    );
    assert_eq!(apply(&mut state, again), Outcome::Accepted);
    apply(&mut state, voters(&[1]));
    assert_eq!(apply(&mut state, complete(5)), Outcome::Accepted);
    assert_eq!(state.removed.get(&2), Some(&1));
    assert_eq!(state.voters(), [1].into());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A control-plane database that something wrote into opens to an error
    /// or to a state, never to a crash. What it holds is not authenticated:
    /// it is this device's own record, and the log it came from is
    /// replicated from the others.
    #[test]
    fn a_damaged_control_database_opens_to_an_error_or_a_state(
        flips in prop::collection::vec((any::<prop::sample::Index>(), 1_u8..=255), 1..16),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sqlite3");
        let mut bytes = std::fs::read(super::fixtures::folder().join("control.sqlite3")).unwrap();
        for (at, with) in &flips {
            let at = at.index(bytes.len());
            bytes[at] ^= with;
        }
        std::fs::write(&path, &bytes).unwrap();
        if let Ok((_log, machine)) = crate::store::open(&path, VAULT, crate::CrashPlan::default()) {
            let state = machine.state_handle().lock().unwrap().clone();
            prop_assert_eq!(state.vault_id, VAULT);
        }
    }
}
