//! What the session crate puts on the clipboard under a Wayland compositor
//! that offers the data-control protocol (wlroots, KDE), as a Wayland
//! program pastes it. Through Xwayland, Wayland programs were given nothing
//! the app copied. Run by `scripts/test-linux.sh` under a headless Sway with
//! `OSM_TEST_WAYLAND` set and no X11 display, so a copy can only go through
//! Wayland; elsewhere it says so and tries nothing.

#![cfg(target_os = "linux")]

use std::{
    io::Write,
    process::{Command, Stdio},
};

use osm_desktop_session::{clear_if_unchanged, clear_last_secret, copy_secret};

/// What a Wayland program pastes, or None if nothing is there to paste.
fn wl_paste(arguments: &[&str]) -> Option<String> {
    let output = Command::new("wl-paste")
        .arg("--no-newline")
        .args(arguments)
        .stderr(Stdio::null())
        .output()
        .expect("wl-paste runs this test");
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).unwrap())
}

fn pasted() -> Option<String> {
    wl_paste(&[])
}

/// One test, since the clipboard is one for the whole compositor.
#[test]
fn under_wayland_a_secret_is_pasted_there_marked_for_password_managers_until_it_comes_off() {
    if std::env::var_os("OSM_TEST_WAYLAND").is_none() {
        eprintln!("not under the test's Wayland compositor (OSM_TEST_WAYLAND): nothing tried");
        return;
    }
    assert!(
        std::env::var_os("WAYLAND_DISPLAY").is_some(),
        "this runs under Wayland"
    );
    assert!(
        std::env::var_os("DISPLAY").is_none(),
        "with no X11 to fall back on"
    );

    // A Wayland program pastes it, and sees the mark clipboard managers honor.
    let copied = copy_secret("first secret").expect("copied through Wayland");
    assert_eq!(pasted().as_deref(), Some("first secret"));
    let types = wl_paste(&["--list-types"]).unwrap();
    assert!(
        types
            .lines()
            .any(|kind| kind == "x-kde-passwordManagerHint"),
        "{types}"
    );
    assert_eq!(
        wl_paste(&["--type", "x-kde-passwordManagerHint"]).as_deref(),
        Some("secret")
    );
    // Its time up, it comes off.
    clear_if_unchanged(copied);
    assert_eq!(pasted(), None);

    // What another program copied since stays, at the time and at a lock.
    let copied = copy_secret("second secret").unwrap();
    let mut other = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
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
    copy_secret("third secret").unwrap();
    assert_eq!(pasted().as_deref(), Some("third secret"));
    clear_last_secret();
    assert_eq!(pasted(), None);
}
