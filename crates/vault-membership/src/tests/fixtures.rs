//! The frozen control-plane formats: a node's database as a real cluster
//! left it (`fixtures/control.sqlite3`, with the state it held in
//! `control-state.json`), and the bytes that requests are signed over and
//! stored as (`vectors.json`). A test here that fails means this build no
//! longer reads, or no longer writes, what an earlier one did.
//!
//! The files are never made again. To add one for a new layout, run the
//! ignored test below, or the vector test with `OSM_WRITE_NEW_FIXTURES=1`,
//! while the file does not exist.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use openraft::{Entry, LogId, SnapshotMeta, Vote};
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{fast_config, Cluster, VAULT};
use crate::{
    device_id_from_bytes, device_id_to_bytes, store, ControlConfig, ControlEntry, ControlNode,
    ControlReply, ControlRequest, ControlRpc, ControlState, CrashPlan, DeviceId, DeviceNode,
    KeySigner, MembershipChange, NodeOptions, Outcome, Rejection, Rotation, SignedRequest,
    SubmitRefusal,
};

/// This crate's fixtures, in this crate's folder: where it was built, or
/// `OSM_TEST_CRATE_DIR` when the tests run on another machine with a copy
/// of the crate's files, as on a phone (`scripts/test-on-android.sh`).
pub(super) fn folder() -> PathBuf {
    std::env::var_os("OSM_TEST_CRATE_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("fixtures")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A copy of the frozen database that a test may open, which writes to it.
fn copy() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sqlite3");
    std::fs::copy(folder().join("control.sqlite3"), &path).unwrap();
    (dir, path)
}

/// The state the founding device held, as the fixture's writer recorded it.
fn frozen_state() -> String {
    std::fs::read_to_string(folder().join("control-state.json")).unwrap()
}

fn as_recorded(state: &ControlState) -> String {
    serde_json::to_string_pretty(state).unwrap() + "\n"
}

/// Runs a cluster through a founding, two enrollments with their key
/// grants, a removal with its rotation, a cancelled enrollment, and a
/// snapshot, and keeps the founding device's database.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "writes a new fixture; it refuses to replace one"]
async fn write_the_control_database_fixture() {
    let destination = folder().join("control.sqlite3");
    assert!(!destination.exists(), "a frozen file is never made again");

    let mut cluster = Cluster::new(4);
    for device in [1, 2, 3] {
        cluster.start(device, CrashPlan::default()).await;
    }
    cluster.bootstrap(&[1]).await;
    let accept = |request: SignedRequest| {
        let node = &cluster.running[&1];
        async move { assert_eq!(node.submit(request).await.unwrap(), Outcome::Accepted) }
    };
    accept(cluster.enroll(1, 1, 2)).await;
    cluster.settle(&[1, 2], &[1, 2]).await;
    accept(cluster.grant(1, 2, 2, &[1])).await;
    accept(cluster.enroll(1, 3, 3)).await;
    cluster.settle(&[1, 2, 3], &[1, 2, 3]).await;
    accept(cluster.grant(1, 4, 3, &[1])).await;
    accept(cluster.remove(1, 5, 3)).await;
    cluster.settle(&[1, 2], &[1, 2]).await;
    // A device that never appears, and its enrollment given up.
    accept(cluster.enroll(1, 6, 4)).await;
    accept(cluster.request(
        1,
        7,
        ControlRequest::CancelEnrollment {
            request_id: [6; 16],
        },
    ))
    .await;
    cluster.settle(&[1, 2], &[1, 2]).await;
    cluster.learners_removed(1).await;

    let raft = cluster.running[&1].raft();
    raft.trigger().snapshot().await.unwrap();
    let mut metrics = raft.metrics();
    while metrics.borrow().snapshot.is_none() {
        metrics.changed().await.unwrap();
    }
    let state = cluster.running[&1].state();
    for device in [1, 2, 3] {
        cluster.crash(device).await;
    }

    let source = cluster.dir.path().join("1.sqlite3");
    // Everything into the one file: the store keeps a write-ahead log.
    Connection::open(&source)
        .unwrap()
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    std::fs::copy(&source, &destination).unwrap();
    std::fs::write(folder().join("control-state.json"), as_recorded(&state)).unwrap();
}

#[test]
fn the_frozen_control_database_is_the_one_that_was_committed() {
    let sums = std::fs::read_to_string(folder().join("SHA256SUMS")).unwrap();
    let (sum, name) = sums.trim_end().split_once("  ").unwrap();
    assert_eq!(name, "control.sqlite3");
    // Opening the database where it lies would write to it; tests copy it.
    assert_eq!(
        hex(&Sha256::digest(std::fs::read(folder().join(name)).unwrap())),
        sum
    );
}

/// Reads a stored JSON text as `T` and checks that this build writes the
/// same text back. Texts are compared, not parsed values: a device ID is a
/// number too large for most JSON readers to hold.
fn round_trip<T: DeserializeOwned + Serialize>(stored: &str) -> T {
    let parsed: T = serde_json::from_str(stored).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(), stored);
    parsed
}

#[test]
fn every_row_of_the_frozen_control_database_reads_and_writes_back_the_same() {
    let (_dir, path) = copy();
    let connection = Connection::open(&path).unwrap();
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
    let text = |sql: &str| -> String { connection.query_row(sql, [], |row| row.get(0)).unwrap() };

    let vote: Vote<DeviceId> = round_trip(&text("SELECT vote FROM raft_vote"));
    assert!(vote.is_committed());
    let committed: Option<LogId<DeviceId>> = round_trip(&text("SELECT committed FROM raft_meta"));
    let state: ControlState = round_trip(&text("SELECT state FROM control_state"));
    assert_eq!(committed, state.last_applied);
    assert_eq!(as_recorded(&state), frozen_state());

    // The log: every kind of entry the control plane writes.
    let mut statement = connection
        .prepare("SELECT idx, entry FROM raft_log ORDER BY idx")
        .unwrap();
    let rows: Vec<(u64, String)> = statement
        .query_map([], |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let (mut requests, mut completions, mut memberships) = (Vec::new(), 0, 0);
    for (index, stored) in &rows {
        let entry: Entry<ControlConfig> = round_trip(stored);
        assert_eq!(entry.log_id.index, *index);
        match entry.payload {
            openraft::EntryPayload::Normal(ControlEntry::Request(request)) => {
                requests.push(request.request_id[0]);
                // Signed by the founding device, whose key the cluster's
                // tests make from its number.
                let key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
                assert!(request.verify(&VAULT, &key));
            }
            openraft::EntryPayload::Normal(ControlEntry::Complete { .. }) => completions += 1,
            openraft::EntryPayload::Membership(_) => memberships += 1,
            openraft::EntryPayload::Blank => {}
        }
    }
    assert_eq!(requests, [0, 1, 2, 3, 4, 5, 6, 7]);
    // Two enrollments, a removal, and the cancelled enrollment.
    assert_eq!(completions, 4);
    assert!(memberships >= 7, "{memberships}");

    // The snapshot is the state as JSON, with what it covers beside it.
    let meta: SnapshotMeta<DeviceId, DeviceNode> =
        round_trip(&text("SELECT meta FROM control_snapshot"));
    let data: Vec<u8> = connection
        .query_row("SELECT data FROM control_snapshot", [], |row| row.get(0))
        .unwrap();
    let snapshot: ControlState = round_trip(std::str::from_utf8(&data).unwrap());
    assert_eq!(meta.last_log_id, snapshot.last_applied);
    assert_eq!(snapshot.vault_id, VAULT);
}

#[test]
fn the_store_opens_the_frozen_database_with_the_state_it_held() {
    let (_dir, path) = copy();
    let (_log, machine) = store::open(&path, VAULT, CrashPlan::default()).unwrap();
    let state = machine.state_handle().lock().unwrap().clone();
    assert_eq!(as_recorded(&state), frozen_state());

    // What the cluster decided, as this build understands it.
    assert_eq!(state.vault_id, VAULT);
    assert_eq!(state.epoch, 2);
    assert_eq!(state.voters(), [1, 2].into());
    assert!(state.is_uniform() && state.pending.is_none());
    assert_eq!(state.removed, [(3, 1)].into());
    assert_eq!(state.removed_pins, [(3, [3; 32])].into());
    assert_eq!(state.authors.keys().copied().collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(
        state.epoch_checks.keys().copied().collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(state.keys_held[&2], [1, 2].into());
    for id in 0..=7 {
        assert_eq!(
            state.outcome_of(&[id; 16]),
            Some(&Outcome::Accepted),
            "request {id}"
        );
    }
    // A database belongs to one vault.
    drop(machine);
    assert!(store::open(&path, [7; 32], CrashPlan::default()).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_starts_from_the_frozen_database() {
    let (_dir, path) = copy();
    let router = crate::Router::default();
    let node = ControlNode::start(
        &path,
        1,
        VAULT,
        router.dialer(1),
        NodeOptions {
            config: fast_config(),
            write_timeout: std::time::Duration::from_secs(3),
            crash: CrashPlan::default(),
        },
    )
    .await
    .unwrap();
    assert_eq!(as_recorded(&node.state()), frozen_state());
    node.shutdown().await;
}

#[test]
fn a_control_database_marked_by_a_later_build_is_refused_and_an_unmarked_one_is_the_first_layout() {
    let (_dir, path) = copy();
    let mark = |version: u32| {
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "user_version", version)
            .unwrap();
        connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
    };
    mark(2);
    let before = std::fs::read(&path).unwrap();
    assert!(store::open(&path, VAULT, CrashPlan::default()).is_err());
    assert!(std::fs::read(&path).unwrap() == before);

    // Databases written before the mark existed say nothing.
    mark(0);
    let (_log, machine) = store::open(&path, VAULT, CrashPlan::default()).unwrap();
    assert_eq!(machine.state_handle().lock().unwrap().epoch, 2);
    drop((_log, machine));
    let version: u32 = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
}

/// `N` bytes counting up from `first`.
fn counting<const N: usize>(first: u8) -> [u8; N] {
    std::array::from_fn(|index| first.wrapping_add(index as u8))
}

/// What a request is signed over, its signature, and how it is stored.
fn request_vector(
    signer: &KeySigner,
    vault_id: &[u8; 32],
    id: u8,
    request: ControlRequest,
) -> Value {
    let signed = SignedRequest::sign(vault_id, [id; 16], signer.device, request, signer);
    assert!(signed.verify(vault_id, &signer.key.verifying_key().to_bytes()));
    assert!(!signed.verify(&[0; 32], &signer.key.verifying_key().to_bytes()));
    json!({
        "signed_message": hex(&signed.signed_message(vault_id)),
        "signature": hex(&signed.signature),
        "as_log_entry": serde_json::to_string(&ControlEntry::Request(signed.clone())).unwrap(),
        "as_submit_rpc": serde_json::to_string(&ControlRpc::Submit(signed)).unwrap(),
    })
}

fn vectors() -> Value {
    let vault_id: [u8; 32] = counting(0x10);
    // A device ID as devices have them: sixteen random bytes, here a
    // pattern, read as one big-endian number.
    let device_bytes: [u8; 16] = counting(0xf0);
    let device = device_id_from_bytes(device_bytes);
    assert_eq!(device_id_to_bytes(device), device_bytes);
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
    // A request is signed over its envelopes as bytes, whatever they hold.
    let envelope = |first: u8| -> Vec<u8> { counting::<40>(first).to_vec() };
    let rotation = Rotation {
        epoch: 3,
        check: counting(0x80),
        envelopes: vec![(device, envelope(0xa0)), (other, envelope(0xb0))],
    };

    json!({
        "about": "What control requests are signed over and how they are stored and sent. Bytes are lowercase hexadecimal. The signature is Ed25519, with the key made from signing_seed, over osm-control-signature-v1, a zero byte, and signed_message. A device ID is its sixteen bytes read as one big-endian number, which JSON here writes as an integer of up to 39 digits and as a decimal string where it is a key.",
        "inputs": {
            "vault_id": hex(&vault_id),
            "device_id_bytes": hex(&device_bytes),
            "device_id": device.to_string(),
            "other_device_id": other.to_string(),
            "signing_seed": hex(&counting::<32>(0x60)),
            "public_key": hex(&signer.key.verifying_key().to_bytes()),
            "signature_domain": hex(crate::SIGNATURE_DOMAIN),
        },
        "requests": {
            "genesis": request_vector(&signer, &vault_id, 1, ControlRequest::Genesis {
                epoch: 2,
                checks: vec![counting(0x80), counting(0x90)],
                authors: vec![(device, counting(0x01)), (other, counting(0x02))],
            }),
            "enroll": request_vector(&signer, &vault_id, 2, ControlRequest::ProposeChange(
                MembershipChange::Enroll { device: other, node: node.clone() },
            )),
            "remove": request_vector(&signer, &vault_id, 3, ControlRequest::ProposeChange(
                MembershipChange::Remove { device: other, rotation },
            )),
            "cancel_enrollment": request_vector(&signer, &vault_id, 4, ControlRequest::CancelEnrollment {
                request_id: [2; 16],
            }),
            "grant_keys": request_vector(&signer, &vault_id, 5, ControlRequest::GrantKeys {
                device: other,
                envelopes: vec![envelope(0xa0), envelope(0xb0)],
            }),
        },
        "stored_and_sent": {
            "completion_log_entry": serde_json::to_string(&ControlEntry::Complete { request_id: [3; 16] }).unwrap(),
            "device_node": serde_json::to_string(&node).unwrap(),
            "outcomes": [
                serde_json::to_string(&Outcome::Recorded).unwrap(),
                serde_json::to_string(&Outcome::Accepted).unwrap(),
                serde_json::to_string(&Outcome::AlreadyApplied(Box::new(Outcome::Accepted))).unwrap(),
                serde_json::to_string(&Outcome::Rejected(Rejection::Unauthorized)).unwrap(),
                serde_json::to_string(&Outcome::Rejected(Rejection::BadSignature)).unwrap(),
                serde_json::to_string(&Outcome::Rejected(Rejection::NotInitialized)).unwrap(),
                serde_json::to_string(&Outcome::Rejected(Rejection::ChangeInProgress)).unwrap(),
                serde_json::to_string(&Outcome::Rejected(Rejection::NotPending)).unwrap(),
                serde_json::to_string(&Outcome::Rejected(Rejection::InvalidChange("why".into()))).unwrap(),
            ],
            "replies": [
                serde_json::to_string(&ControlReply::Submit(Ok(Outcome::Accepted))).unwrap(),
                serde_json::to_string(&ControlReply::Submit(Err(SubmitRefusal::NotLeader(Some(other))))).unwrap(),
                serde_json::to_string(&ControlReply::Submit(Err(SubmitRefusal::NotLeader(None)))).unwrap(),
                serde_json::to_string(&ControlReply::Submit(Err(SubmitRefusal::QuorumUnavailable))).unwrap(),
                serde_json::to_string(&ControlReply::Submit(Err(SubmitRefusal::Failed("why".into())))).unwrap(),
                serde_json::to_string(&ControlReply::Refused).unwrap(),
            ],
        },
    })
}

/// Says where two values differ, so that a failure names the encoding.
fn differences(path: &str, frozen: &Value, made: &Value, found: &mut Vec<String>) {
    match (frozen, made) {
        (Value::Object(frozen), Value::Object(made)) => {
            for name in frozen.keys().chain(made.keys()) {
                match (frozen.get(name), made.get(name)) {
                    (Some(left), Some(right)) => {
                        differences(&format!("{path}.{name}"), left, right, found)
                    }
                    _ => found.push(format!("{path}.{name} is in one and not the other")),
                }
            }
        }
        _ if frozen != made => found.push(path.to_owned()),
        _ => {}
    }
}

#[test]
fn control_requests_are_signed_stored_and_sent_as_frozen() {
    let path = folder().join("vectors.json");
    let made = vectors();
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&made).unwrap() + "\n").unwrap();
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found = Vec::new();
    differences("vectors", &frozen, &made, &mut found);
    found.sort();
    found.dedup();
    assert!(
        found.is_empty(),
        "these no longer match the frozen values: {found:#?}"
    );

    // And back: the frozen texts read as what they were.
    for name in [
        "genesis",
        "enroll",
        "remove",
        "cancel_enrollment",
        "grant_keys",
    ] {
        let stored = frozen["requests"][name]["as_log_entry"].as_str().unwrap();
        let ControlEntry::Request(request) = round_trip::<ControlEntry>(stored) else {
            panic!("{name} is not a request");
        };
        assert_eq!(
            hex(&request.signed_message(&counting(0x10))),
            frozen["requests"][name]["signed_message"]
        );
        let sent = frozen["requests"][name]["as_submit_rpc"].as_str().unwrap();
        assert!(
            matches!(round_trip::<ControlRpc>(sent), ControlRpc::Submit(sent) if sent == request)
        );
    }
    for stored in frozen["stored_and_sent"]["outcomes"].as_array().unwrap() {
        round_trip::<Outcome>(stored.as_str().unwrap());
    }
    for stored in frozen["stored_and_sent"]["replies"].as_array().unwrap() {
        round_trip::<ControlReply>(stored.as_str().unwrap());
    }
}
