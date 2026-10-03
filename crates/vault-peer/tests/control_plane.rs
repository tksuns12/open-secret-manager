//! Devices of one vault, each a separate `osm-peer device` process with its
//! own vault file, peer store, control-plane database, and listener on
//! localhost. They enroll through the control plane, sync with one another,
//! remove a device, lose quorum, and take part while locked.

use std::{path::Path, thread, time::Duration};

mod common;
use common::{path, run, Running};

/// Enrollment and catching up include elections at production timeouts.
const SLOW: Duration = Duration::from_secs(120);

/// One device's files.
struct Files {
    vault: String,
    peers: String,
    control: String,
}

impl Files {
    fn new(dir: &Path, name: &str) -> Self {
        Self {
            vault: path(dir, &format!("{name}.db")),
            peers: path(dir, &format!("{name}-peers.db")),
            control: path(dir, &format!("{name}-control.db")),
        }
    }

    /// Starts the device on an existing vault. `listen` is an address, or
    /// `-` to dial out only.
    fn start(&self, listen: &str) -> (Running, String) {
        let device = Running::start(&["device", &self.vault, &self.peers, &self.control, listen]);
        let id = device.expect("READY");
        (device, id)
    }
}

fn command(device: &mut Running, text: &str, done: &str) -> String {
    device.answer(text);
    device.expect_within(done, SLOW)
}

/// Pairs a new device with `inviter`: both show the short code, the owner
/// confirms on each, and the new device is enrolled by the vault's devices.
fn join(inviter: &mut Running, files: &Files) -> (Running, String) {
    join_with(inviter, files, "invite")
}

/// As [`join`], with the inviter's command: `invite`, or `invite
/// without-vote`.
fn join_with(inviter: &mut Running, files: &Files, invite: &str) -> (Running, String) {
    let code = command(inviter, invite, "INVITE");
    let mut joiner = Running::start(&[
        "join-device",
        &code,
        &files.vault,
        &files.peers,
        &files.control,
        "127.0.0.1:0",
    ]);
    let code_on_joiner = joiner.expect("SAS");
    let code_on_inviter = inviter.expect("SAS");
    assert_eq!(code_on_inviter, code_on_joiner);
    inviter.answer("y");
    joiner.answer("y");
    let enrolled = inviter.expect_within("ENROLLED", SLOW);
    let id = joiner.expect_within("JOINED", SLOW);
    assert_eq!(enrolled, id);
    joiner.expect("READY");
    (joiner, id)
}

fn items(device: &mut Running) -> Vec<String> {
    device.answer("list");
    let mut items = device.collect("ITEM ", "LISTED");
    items.sort();
    items
}

/// Syncs with every member the device knows, or with one device, and
/// returns the outcome lines.
fn sync(device: &mut Running, only: Option<&str>) -> Vec<String> {
    device.answer(&match only {
        Some(id) => format!("sync {id}"),
        None => "sync".to_owned(),
    });
    device.collect("SYNC", "SYNC-DONE")
}

/// Polls `status` until the line contains every one of `wanted`.
fn wait_status(device: &mut Running, wanted: &[&str]) -> String {
    let mut last = String::new();
    for _ in 0..400 {
        last = command(device, "status", "STATUS");
        if wanted.iter().all(|part| last.contains(part)) {
            return last;
        }
        thread::sleep(Duration::from_millis(300));
    }
    panic!("status never showed {wanted:?}; last: {last}");
}

fn quit(mut device: Running) {
    device.answer("quit");
    device.succeed();
}

#[test]
fn devices_enroll_sync_remove_and_lose_quorum_across_processes() {
    let dir = tempfile::tempdir().unwrap();
    let files = |name| Files::new(dir.path(), name);
    let (a_files, b_files, c_files, d_files) = (files("a"), files("b"), files("c"), files("d"));

    // A creates the vault and founds its control plane.
    run(&["create", &a_files.vault]);
    let (mut a, a_id) = a_files.start("127.0.0.1:0");
    command(&mut a, "found", "FOUNDED");
    command(&mut a, "add Mail", "ADDED");

    // B joins through A; C through B, a follower, which passes the proposal
    // to the leader; D through A.
    let (mut b, b_id) = join(&mut a, &b_files);
    let (mut c, _c_id) = join(&mut b, &c_files);
    let (mut d, d_id) = join(&mut a, &d_files);
    for device in [&mut a, &mut b, &mut c, &mut d] {
        wait_status(device, &["epoch=1", "members=4"]);
    }

    // Every device syncs with every other member, not one paired peer.
    for device in [&mut b, &mut c, &mut d] {
        let outcomes = sync(device, None);
        assert_eq!(outcomes.len(), 3, "{outcomes:?}");
        assert!(outcomes.iter().all(|line| line.starts_with("ED ")));
        assert_eq!(items(device), ["Mail"]);
    }
    command(&mut c, "add Wifi", "ADDED");
    sync(&mut c, None);
    for device in [&mut a, &mut b, &mut d] {
        assert_eq!(items(device), ["Mail", "Wifi"]);
    }

    // C goes away. A removes D, which still completes: A and B are a
    // majority of the three that remain.
    quit(c);
    command(&mut a, &format!("remove {d_id}"), "REMOVED");
    for device in [&mut a, &mut b] {
        wait_status(
            device,
            &["epoch=2", "vault_epoch=2", "members=3", "removed=false"],
        );
    }
    command(&mut a, "add After-removal", "ADDED");
    let outcomes = sync(&mut a, None);
    assert!(
        outcomes
            .iter()
            .any(|line| line.starts_with(&format!("ED device={b_id}"))),
        "{outcomes:?}"
    );
    // D is no longer someone A syncs with.
    assert!(!outcomes.iter().any(|line| line.contains(&d_id)));
    assert_eq!(items(&mut b), ["After-removal", "Mail", "Wifi"]);

    // The members refuse D and tell it why. It has neither the new key nor
    // the new revision.
    let outcomes = sync(&mut d, Some(&a_id));
    assert_eq!(outcomes.len(), 1);
    assert!(
        outcomes[0].contains("this device was removed from the vault"),
        "{outcomes:?}"
    );
    wait_status(&mut d, &["vault_epoch=1", "removed=true"]);
    assert_eq!(items(&mut d), ["Mail", "Wifi"]);

    // D keeps writing. C returns, but only dials out: the leader cannot
    // reach it, so it has not learned of the removal and still takes D's
    // edit.
    command(&mut d, "add Late-edit", "ADDED");
    let (mut c, _) = c_files.start("-");
    wait_status(&mut c, &["epoch=1", "members=4"]);
    let outcomes = sync(&mut c, Some(&d_id));
    assert!(outcomes[0].contains("applied=1"), "{outcomes:?}");

    // When C passes that edit on, A, which knows of the removal, holds it
    // for review instead of merging it. What A sends back is under the new
    // epoch: C stores it but cannot read it yet.
    let outcomes = sync(&mut c, Some(&a_id));
    assert!(outcomes[0].contains("sent=1"), "{outcomes:?}");
    assert!(outcomes[0].contains("applied=0"), "{outcomes:?}");
    wait_status(&mut a, &["held=1"]);
    assert_eq!(items(&mut a), ["After-removal", "Mail", "Wifi"]);
    assert_eq!(items(&mut c), ["Late-edit", "Mail", "Wifi"]);
    wait_status(&mut c, &["vault_epoch=1", "staged=1"]);

    // Once C can be reached again it catches up: it learns of the removal,
    // opens its envelope for the new epoch, and reads what was waiting.
    command(&mut c, "listen 127.0.0.1:0", "LISTEN");
    wait_status(
        &mut c,
        &["epoch=2", "vault_epoch=2", "members=3", "staged=0"],
    );
    assert_eq!(
        items(&mut c),
        ["After-removal", "Late-edit", "Mail", "Wifi"]
    );
    // B hears of D's late edit from C and holds it too.
    sync(&mut b, None);
    wait_status(&mut b, &["held=1"]);
    assert_eq!(items(&mut b), ["After-removal", "Mail", "Wifi"]);

    // With B and C gone, A is a minority of three: it cannot remove
    // anyone, and nothing changes.
    quit(b);
    quit(c);
    quit(d);
    a.answer(&format!("remove {b_id}"));
    let failure = a.expect_within("FAILED", SLOW);
    assert!(
        failure.contains("not enough devices are reachable"),
        "{failure}"
    );
    wait_status(&mut a, &["epoch=2", "vault_epoch=2", "members=3"]);
    quit(a);
}

#[test]
fn a_declined_code_enrolls_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (a_files, b_files) = (Files::new(dir.path(), "a"), Files::new(dir.path(), "b"));
    run(&["create", &a_files.vault]);
    let (mut a, _) = a_files.start("127.0.0.1:0");
    command(&mut a, "found", "FOUNDED");

    let code = command(&mut a, "invite", "INVITE");
    let mut joiner = Running::start(&[
        "join-device",
        &code,
        &b_files.vault,
        &b_files.peers,
        &b_files.control,
        "127.0.0.1:0",
    ]);
    joiner.expect("SAS");
    a.expect("SAS");
    // The owner sees a mismatch on the inviter and declines.
    a.answer("n");
    joiner.answer("y");
    let failure = a.expect("FAILED");
    assert!(failure.contains("declined"), "{failure}");
    assert!(!joiner.child.wait().unwrap().success());
    assert!(!Path::new(&b_files.vault).exists());
    // Nothing was proposed: A is still the only member, with nothing pending.
    wait_status(&mut a, &["epoch=1", "members=1"]);
    quit(a);
}

#[test]
fn a_locked_device_takes_part_and_receives_without_its_password() {
    let dir = tempfile::tempdir().unwrap();
    let files = |name| Files::new(dir.path(), name);
    let (a_files, b_files, c_files) = (files("a"), files("b"), files("c"));
    run(&["create", &a_files.vault]);
    let (mut a, _) = a_files.start("127.0.0.1:0");
    command(&mut a, "found", "FOUNDED");
    command(&mut a, "add Mail", "ADDED");
    let (mut b, b_id) = join(&mut a, &b_files);
    sync(&mut b, None);
    assert_eq!(items(&mut b), ["Mail"]);
    quit(b);

    // B runs again as an app that is open but locked: this process never
    // has the password.
    let mut b = Running::start_without_password(&[
        "device-locked",
        &b_files.vault,
        &b_files.peers,
        &b_files.control,
        "127.0.0.1:0",
    ]);
    assert_eq!(b.expect("READY"), b_id);
    b.answer("list");
    assert!(b.expect("FAILED").contains("locked"));

    // With two voters every change needs both. A third device enrolls, so
    // B's node voted and replicated while locked.
    let (mut c, _) = join(&mut a, &c_files);
    for device in [&mut a, &mut b, &mut c] {
        wait_status(device, &["epoch=1", "members=3"]);
    }

    // A's edit reaches B, which can only store the ciphertext.
    command(&mut a, "add Locker", "ADDED");
    let outcomes = sync(&mut a, Some(&b_id));
    assert!(outcomes[0].contains("sent=1"), "{outcomes:?}");
    wait_status(&mut b, &["staged=1", "held=locked"]);
    quit(b);

    // Unlocked again, B verifies and applies it.
    let (mut b, _) = b_files.start("127.0.0.1:0");
    wait_status(&mut b, &["staged=0", "held=0"]);
    assert_eq!(items(&mut b), ["Locker", "Mail"]);
    for device in [a, b, c] {
        quit(device);
    }
}

#[test]
fn a_phone_joins_without_a_vote_and_the_one_voter_removes_it_while_it_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let files = |name| Files::new(dir.path(), name);
    let (a_files, phone_files) = (files("a"), files("phone"));
    run(&["create", &a_files.vault]);
    let (mut a, _) = a_files.start("127.0.0.1:0");
    command(&mut a, "found", "FOUNDED");
    command(&mut a, "add Mail", "ADDED");

    // The phone joins as a member without a vote and syncs like any other.
    let (mut phone, phone_id) = join_with(&mut a, &phone_files, "invite without-vote");
    for device in [&mut a, &mut phone] {
        wait_status(device, &["epoch=1", "members=2", "voters=1"]);
    }
    sync(&mut phone, None);
    assert_eq!(items(&mut phone), ["Mail"]);

    // The phone is off. With two voters A could not remove it; as the one
    // voter it does so alone.
    quit(phone);
    command(&mut a, &format!("remove {phone_id}"), "REMOVED");
    wait_status(
        &mut a,
        &["epoch=2", "vault_epoch=2", "members=1", "voters=1"],
    );
    quit(a);
}
