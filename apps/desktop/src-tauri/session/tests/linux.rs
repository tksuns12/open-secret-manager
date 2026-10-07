//! What the session crate hears from logind, against a stand-in on a bus
//! of the test's own, and what it puts on the clipboard, as another
//! program reads it. Run in a Linux container by `scripts/test-linux.sh`,
//! with `dbus-daemon`, a virtual display, and `xclip`.

#![cfg(target_os = "linux")]

#[path = "support/logind.rs"]
mod logind;

use std::{
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use logind::{impostor_lock, Bus, Say, StandIn};
use osm_desktop_session::{clear_if_unchanged, clear_last_secret, copy_secret, watch_bus, Away};

fn heard_on(bus: &Bus) -> mpsc::Receiver<Away> {
    let (heard, hear) = mpsc::channel();
    assert!(watch_bus(&bus.address, move |away| {
        let _ = heard.send(away);
    }));
    hear
}

fn next(hear: &mpsc::Receiver<Away>) -> Option<Away> {
    hear.recv_timeout(Duration::from_secs(5)).ok()
}

fn nothing_more(hear: &mpsc::Receiver<Away>) {
    assert_eq!(hear.recv_timeout(Duration::from_millis(700)).ok(), None);
}

#[test]
fn logind_tells_of_sleep_a_lock_and_switching_away_and_of_nothing_else() {
    let bus = Bus::start();
    let logind = StandIn::serve(&bus.address, true);
    let hear = heard_on(&bus);

    // Each is heard once, for what it is; what follows something that must
    // not count comes next, so that it did not.
    logind.say(Say::Sleep(true));
    assert_eq!(next(&hear), Some(Away::Sleep));
    logind.say(Say::Sleep(false));
    logind.say(Say::Lock);
    assert_eq!(next(&hear), Some(Away::ScreenLocked));
    impostor_lock(&bus.address);
    logind.say(Say::LockedHint(false));
    logind.say(Say::LockedHint(true));
    assert_eq!(next(&hear), Some(Away::ScreenLocked));
    logind.say(Say::Active(true));
    logind.say(Say::Active(false));
    assert_eq!(next(&hear), Some(Away::SwitchedOut));
    nothing_more(&hear);
}

#[test]
fn a_program_outside_any_session_watches_its_users_graphical_one() {
    std::env::remove_var("XDG_SESSION_ID");
    let bus = Bus::start();
    let logind = StandIn::serve(&bus.address, false);
    let hear = heard_on(&bus);
    logind.say(Say::Lock);
    assert_eq!(next(&hear), Some(Away::ScreenLocked));
    nothing_more(&hear);
}

/// What another program pastes from the clipboard, or None if nothing is
/// there to paste.
fn xclip(arguments: &[&str]) -> Option<String> {
    let output = Command::new("xclip")
        .args(["-selection", "clipboard"])
        .args(arguments)
        .stderr(Stdio::null())
        .output()
        .expect("xclip runs these tests");
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).unwrap())
}

fn pasted() -> Option<String> {
    xclip(&["-o"])
}

/// One test, since the clipboard is one for the whole display.
#[test]
fn a_secret_stays_to_paste_marked_for_password_managers_until_it_comes_off() {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "these run on a display"
    );

    // Another program pastes it after the copy returned, and sees the mark
    // clipboard managers honor.
    let copied = copy_secret("first secret").unwrap();
    assert_eq!(pasted().as_deref(), Some("first secret"));
    let targets = xclip(&["-t", "TARGETS", "-o"]).unwrap();
    assert!(
        targets
            .lines()
            .any(|target| target == "x-kde-passwordManagerHint"),
        "{targets}"
    );
    assert_eq!(
        xclip(&["-t", "x-kde-passwordManagerHint", "-o"]).as_deref(),
        Some("secret")
    );
    // Its time up, it comes off.
    clear_if_unchanged(copied);
    assert_eq!(pasted(), None);

    // An earlier copy's time does not take off a later one.
    let earlier = copy_secret("one").unwrap();
    let later = copy_secret("two").unwrap();
    clear_if_unchanged(earlier);
    assert_eq!(pasted().as_deref(), Some("two"));
    clear_if_unchanged(later);
    assert_eq!(pasted(), None);

    // What another program copied since stays, at the time and at a lock.
    let copied = copy_secret("three").unwrap();
    let mut other = Command::new("xclip")
        .args(["-selection", "clipboard", "-i"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    other
        .stdin
        .take()
        .unwrap()
        .write_all(b"not a secret")
        .unwrap();
    other.wait().unwrap();
    assert_eq!(pasted().as_deref(), Some("not a secret"));
    clear_if_unchanged(copied);
    clear_last_secret();
    assert_eq!(pasted().as_deref(), Some("not a secret"));

    // A lock takes a secret off.
    copy_secret("four").unwrap();
    assert_eq!(pasted().as_deref(), Some("four"));
    clear_last_secret();
    assert_eq!(pasted(), None);
}
