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
    join_listening_at(inviter, files, invite, "127.0.0.1:0")
}

/// As [`join_with`], with the address the new device listens at, or `-`.
fn join_listening_at(
    inviter: &mut Running,
    files: &Files,
    invite: &str,
    listen: &str,
) -> (Running, String) {
    let code = command(inviter, invite, "INVITE");
    let mut joiner = Running::start(&[
        "join-device",
        &code,
        &files.vault,
        &files.peers,
        &files.control,
        listen,
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

/// Two computers that never sync with each other, and a phone that dials
/// each in turn: what one wrote reaches the other by way of the phone, in
/// both directions. The phone only dials (it listens nowhere), as on a real
/// one, so it does not relay for anyone; it carries.
#[test]
fn a_phone_that_visits_two_computers_carries_each_ones_items_to_the_other() {
    let dir = tempfile::tempdir().unwrap();
    let files = |name| Files::new(dir.path(), name);
    let (a_files, b_files, phone_files) = (files("a"), files("b"), files("phone"));
    run(&["create", &a_files.vault]);
    let (mut a, a_id) = a_files.start("127.0.0.1:0");
    command(&mut a, "found", "FOUNDED");

    // B, a second computer with a vote, and the phone, without one, both
    // join through A while the three can reach each other.
    let (mut b, b_id) = join(&mut a, &b_files);
    let (phone, _) = join_with(&mut a, &phone_files, "invite without-vote");
    for device in [&mut a, &mut b] {
        wait_status(device, &["epoch=1", "members=3", "voters=2"]);
    }
    // The phone goes on dialling out only.
    quit(phone);
    let (mut phone, _) = phone_files.start("-");
    wait_status(&mut phone, &["epoch=1", "members=3"]);

    // From here A and B never sync with each other. Each writes alone.
    command(&mut a, "add From-A", "ADDED");
    command(&mut b, "add From-B", "ADDED");
    assert_eq!(items(&mut a), ["From-A"]);
    assert_eq!(items(&mut b), ["From-B"]);

    // The phone visits A: it takes A's item. It visits B: it brings it, and
    // takes B's.
    let outcomes = sync(&mut phone, Some(&a_id));
    assert!(outcomes[0].starts_with("ED "), "{outcomes:?}");
    assert_eq!(items(&mut phone), ["From-A"]);
    let outcomes = sync(&mut phone, Some(&b_id));
    assert!(outcomes[0].starts_with("ED "), "{outcomes:?}");
    assert_eq!(items(&mut phone), ["From-A", "From-B"]);
    assert_eq!(items(&mut b), ["From-A", "From-B"]);

    // A has still heard nothing of B's item, from B or from anyone.
    assert_eq!(items(&mut a), ["From-A"]);
    // Back at A, it brings B's.
    sync(&mut phone, Some(&a_id));
    assert_eq!(items(&mut a), ["From-A", "From-B"]);
    for device in [phone, a, b] {
        quit(device);
    }
}

/// A free port on this machine, for a relay to listen on.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A device that is on none of the inviter's networks (it listens nowhere,
/// and the invitation names no address) joins through the vault's relay and
/// then syncs both ways (the sync itself may go direct, as the device has
/// by then learned the inviter's address; the join and the catching up
/// cannot).
#[test]
fn a_device_away_from_every_network_joins_and_syncs_through_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let files = |name| Files::new(dir.path(), name);
    let (a_files, away_files) = (files("a"), files("away"));
    let relay_address = format!("127.0.0.1:{}", free_port());
    let relay_folder = path(dir.path(), "relay");
    let relay = Running::start_relay(&relay_folder, &relay_address);
    let relay_code = relay.expect("RELAY-CODE");

    run(&["create", &a_files.vault]);
    let (mut a, _) = a_files.start("127.0.0.1:0");
    command(&mut a, "found", "FOUNDED");
    command(&mut a, "add From-A", "ADDED");
    a.answer(&format!("relay {relay_code}"));
    a.expect("RELAY-CONNECTED");

    // The invitation names the relay and no address; the new device listens
    // nowhere.
    let (mut away, _) = join_listening_at(&mut a, &away_files, "invite away", "-");
    wait_status(&mut away, &["epoch=1", "members=2"]);
    let outcomes = sync(&mut away, None);
    assert!(
        outcomes.iter().all(|line| line.starts_with("ED ")),
        "{outcomes:?}"
    );
    assert_eq!(items(&mut away), ["From-A"]);
    command(&mut away, "add From-away", "ADDED");
    sync(&mut away, None);
    assert_eq!(items(&mut a), ["From-A", "From-away"]);
    for device in [away, a] {
        quit(device);
    }
    drop(relay);
}
