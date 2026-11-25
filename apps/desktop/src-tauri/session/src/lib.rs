//! What the desktop app needs from the system that Tauri does not give it:
//! notice that the owner's session went away from the app (the computer
//! sleeping, the displays sleeping, the screen locking, the screen saver
//! starting, another user taking the screen), a clipboard entry that
//! clipboard managers leave alone, and that comes off again, and on macOS
//! the system's check that the owner is there (Touch ID or the Mac's
//! password), for a passkey.
//!
//! On macOS from the system's notifications, and an entry that also stays on
//! this Mac. On Linux (since Phase 10) from logind over the system bus: the
//! computer going to sleep, the session told to lock or its screen locker
//! saying it locked, and the session leaving the seat to another; and an
//! entry marked as a password manager's, which this process keeps serving
//! until it is taken off. Elsewhere [`watch`] watches nothing and
//! [`copy_secret`] declines, and the app does without.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Why the owner's session went away from the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Away {
    /// The computer is going to sleep.
    Sleep,
    /// The displays went to sleep.
    ScreensSleep,
    /// The screen locked.
    ScreenLocked,
    /// The screen saver started.
    ScreenSaver,
    /// Another user's session took the screen.
    SwitchedOut,
}

impl Away {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sleep => "sleep",
            Self::ScreensSleep => "screens_sleep",
            Self::ScreenLocked => "screen_locked",
            Self::ScreenSaver => "screen_saver",
            Self::SwitchedOut => "switched_out",
        }
    }
}

/// Calls `on_away` whenever the session goes away, for as long as the
/// process runs. Says whether this system tells.
pub fn watch(on_away: impl Fn(Away) + Send + Sync + 'static) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::watch(std::sync::Arc::new(on_away));
        true
    }
    #[cfg(target_os = "linux")]
    {
        linux::watch(std::sync::Arc::new(on_away))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = on_away;
        false
    }
}

/// Watches logind on the bus at `address` instead of the system bus. For
/// tests only, which serve a stand-in for logind on a bus of their own.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn watch_bus(address: &str, on_away: impl Fn(Away) + Send + Sync + 'static) -> bool {
    linux::watch_bus(address, std::sync::Arc::new(on_away))
}

/// The names a stand-in for logind answers to, for tests.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub mod logind {
    pub use crate::linux::{LOGIND, MANAGER, MANAGER_PATH, SESSION, USER};
}

/// Calls `on_away` with `away` whenever the system-wide notification `name`
/// is posted. For tests only: the system's own notifications reach every
/// process of the user, so a test posts one of its own.
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn watch_system_notification(
    name: &str,
    away: Away,
    on_away: impl Fn(Away) + Send + Sync + 'static,
) {
    macos::observe_system(name, away, std::sync::Arc::new(on_away));
}

/// Whether this system can check that the owner is at the computer, for a
/// site that asks a passkey to verify its user: on macOS, Touch ID or the
/// Mac's password, as the system chooses. Elsewhere it cannot, and the app
/// asks for the vault's password.
pub fn can_check_owner() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::can_check_owner()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Handle to an in-flight system owner check. Dropping or cancelling it
/// invalidates the underlying OS prompt (e.g. `LAContext::invalidate()` on
/// macOS) if the request ends before the owner finishes verifying.
pub struct OwnerCheck {
    #[cfg(target_os = "macos")]
    cancel: Option<Box<dyn FnOnce() + Send>>,
}

impl OwnerCheck {
    /// Cancels the in-flight owner verification prompt, if still pending.
    pub fn cancel(mut self) {
        #[cfg(target_os = "macos")]
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = &mut self;
        }
    }
}

impl Drop for OwnerCheck {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

/// Asks the system to check the owner, telling them `reason`; `done` is
/// called once, on a thread of the system's, with whether the check
/// passed. Where [`can_check_owner`] says no, at once with `false`.
/// Dropping the returned [`OwnerCheck`] cancels an unfinished prompt.
pub fn check_owner(reason: &str, done: impl FnOnce(bool) + Send + 'static) -> OwnerCheck {
    #[cfg(target_os = "macos")]
    {
        OwnerCheck {
            cancel: Some(macos::check_owner(reason, Box::new(done))),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        done(false);
        OwnerCheck {}
    }
}

/// A secret put on the clipboard, to be taken off again later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Copied {
    /// What the clipboard counted when the secret was put there; it counts
    /// every change. On Linux and Windows, this process's own count of the
    /// secrets it put there.
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux", target_os = "windows")),
        allow(dead_code)
    )]
    change: isize,
}

/// Puts `text` on the clipboard, marked for clipboard history apps to leave
/// out: on macOS as concealed and transient, and for this Mac only (not for
/// the owner's other devices); on Linux with `x-kde-passwordManagerHint`; on
/// Windows excluded from monitoring, clipboard history, and cloud clipboard.
/// `None` where this system cannot.
pub fn copy_secret(text: &str) -> Option<Copied> {
    #[cfg(target_os = "macos")]
    {
        macos::copy_secret(&objc2_app_kit::NSPasteboard::generalPasteboard(), text)
            .map(|change| Copied { change })
    }
    #[cfg(target_os = "linux")]
    {
        linux::copy_secret(text).map(|change| Copied { change })
    }
    #[cfg(target_os = "windows")]
    {
        windows::copy_secret(text).map(|change| Copied { change })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = text;
        None
    }
}

/// Clears the clipboard if it still holds the last secret [`copy_secret`]
/// put there.
pub fn clear_last_secret() {
    #[cfg(target_os = "macos")]
    macos::clear_last(&objc2_app_kit::NSPasteboard::generalPasteboard());
    #[cfg(target_os = "linux")]
    linux::clear(None);
    #[cfg(target_os = "windows")]
    windows::clear(None);
}

/// Clears the clipboard if nothing was put there since `copied`.
pub fn clear_if_unchanged(copied: Copied) {
    #[cfg(target_os = "macos")]
    macos::clear_if_unchanged(
        &objc2_app_kit::NSPasteboard::generalPasteboard(),
        copied.change,
    );
    #[cfg(target_os = "linux")]
    linux::clear(Some(copied.change));
    #[cfg(target_os = "windows")]
    windows::clear(Some(copied.change));
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = copied;
}
