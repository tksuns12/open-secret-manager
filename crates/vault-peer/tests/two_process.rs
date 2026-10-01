//! Pairs and syncs two vaults running in separate `osm-peer` processes over
//! TLS on localhost. Everything persists on disk between processes.

use std::path::Path;

mod common;
use common::{osm_peer, path, run, Running};

fn items(vault: &str) -> Vec<String> {
    let mut items: Vec<String> = run(&["list", vault])
        .into_iter()
        .filter_map(|line| line.strip_prefix("ITEM ").map(str::to_owned))
        .collect();
    items.sort();
    items
}

#[test]
fn two_processes_pair_and_sync_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (a, a_peers) = (path(dir.path(), "a.db"), path(dir.path(), "a-peers.db"));
    let (b, b_peers) = (path(dir.path(), "b.db"), path(dir.path(), "b-peers.db"));
    run(&["create", &a]);
    run(&["add", &a, "Mail"]);
    run(&["add", &a, "Bank"]);

    // Pair: both processes show the code; the owner compares, then confirms.
    let mut inviter = Running::start(&["invite", &a, &a_peers, "127.0.0.1:0"]);
    inviter.expect("LISTEN");
    let code = inviter.expect("INVITE");
    let mut joiner = Running::start(&["join", &code, &b, &b_peers]);
    let code_on_b = joiner.expect("SAS");
    let code_on_a = inviter.expect("SAS");
    assert_eq!(code_on_a, code_on_b);
    inviter.answer("y");
    joiner.answer("y");
    inviter.expect("PAIRED");
    joiner.expect("JOINED");
    inviter.succeed();
    joiner.succeed();

    // A serves, B dials: B receives the vault.
    let server = Running::start(&["serve", &a, &a_peers, "127.0.0.1:0"]);
    let address = server.expect("LISTEN");
    let synced = run(&["sync", &b, &b_peers, &address]);
    assert!(synced
        .iter()
        .any(|line| line.starts_with("SYNCED sent=0 received=2 applied=2")));
    server.succeed();
    assert_eq!(items(&b), ["Bank", "Mail"]);

    // B edits, then B serves and A dials in a new pair of processes.
    run(&["add", &b, "Wifi"]);
    let server = Running::start(&["serve", &b, &b_peers, "127.0.0.1:0"]);
    let address = server.expect("LISTEN");
    let synced = run(&["sync", &a, &a_peers, &address]);
    assert!(synced
        .iter()
        .any(|line| line.starts_with("SYNCED sent=0 received=1 applied=1")));
    server.succeed();
    assert_eq!(items(&a), ["Bank", "Mail", "Wifi"]);
    assert_eq!(items(&b), items(&a));

    // B receives while locked: its process never has the password, so it
    // can only stage ciphertext.
    run(&["add", &a, "Locker"]);
    let server = Running::start_without_password(&["serve-locked", &b, &b_peers, "127.0.0.1:0"]);
    let address = server.expect("LISTEN");
    run(&["sync", &a, &a_peers, &address]);
    let received = server.expect("SYNCED");
    assert!(received.contains("received=1 applied=0"), "{received}");
    assert!(received.ends_with("pending=1"), "{received}");
    server.succeed();

    // The next unlock verifies and applies it.
    let listed = run(&["list", &b]);
    assert!(listed.contains(&"PROCESSED applied=1 quarantined=0 rejected=0 pending=0".to_owned()));
    assert_eq!(items(&b), ["Bank", "Locker", "Mail", "Wifi"]);
}

#[test]
fn a_declined_code_pairs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (a, a_peers) = (path(dir.path(), "a.db"), path(dir.path(), "a-peers.db"));
    let (b, b_peers) = (path(dir.path(), "b.db"), path(dir.path(), "b-peers.db"));
    run(&["create", &a]);

    let mut inviter = Running::start(&["invite", &a, &a_peers, "127.0.0.1:0"]);
    let code = inviter.expect("INVITE");
    let mut joiner = Running::start(&["join", &code, &b, &b_peers]);
    joiner.expect("SAS");
    inviter.expect("SAS");
    // The owner sees a mismatch on the inviter and declines.
    inviter.answer("n");
    joiner.answer("y");
    assert!(!inviter.child.wait().unwrap().success());
    assert!(!joiner.child.wait().unwrap().success());
    assert!(!Path::new(&b).exists());

    // Neither side recorded a peer, so A has no one to sync with.
    let output = osm_peer()
        .args(["sync", &a, &a_peers, "127.0.0.1:1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no paired device"));
}
