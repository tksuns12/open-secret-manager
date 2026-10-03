//! What the desktop app needs from macOS that Tauri does not give it:
//! notice that the owner's session went away from the app (the computer
//! sleeping, the displays sleeping, the screen locking, the screen saver
//! starting, another user taking the screen), and a clipboard entry that
//! stays on this Mac, that clipboard managers leave alone, and that comes
//! off again.
//!
//! Only macOS is done. Elsewhere [`watch`] watches nothing and
//! [`copy_secret`] declines, and the app does without.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "macos")]
mod macos;

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
    #[cfg(not(target_os = "macos"))]
    {
        let _ = on_away;
        false
    }
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

/// A secret put on the clipboard, to be taken off again later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Copied {
    /// What the clipboard counted when the secret was put there; it counts
    /// every change.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    change: isize,
}

/// Puts `text` on the clipboard for this Mac only (not for the owner's
/// other devices), marked as concealed and transient for clipboard history
/// apps. `None` where this system cannot.
pub fn copy_secret(text: &str) -> Option<Copied> {
    #[cfg(target_os = "macos")]
    {
        macos::copy_secret(&objc2_app_kit::NSPasteboard::generalPasteboard(), text)
            .map(|change| Copied { change })
    }
    #[cfg(not(target_os = "macos"))]
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
}

/// Clears the clipboard if nothing was put there since `copied`.
pub fn clear_if_unchanged(copied: Copied) {
    #[cfg(target_os = "macos")]
    macos::clear_if_unchanged(
        &objc2_app_kit::NSPasteboard::generalPasteboard(),
        copied.change,
    );
    #[cfg(not(target_os = "macos"))]
    let _ = copied;
}
