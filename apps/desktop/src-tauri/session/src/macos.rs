use std::{
    ptr::NonNull,
    sync::{Arc, Mutex},
};

use block2::RcBlock;
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSPasteboard, NSPasteboardContentsOptions, NSWorkspace};
use objc2_foundation::{
    NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSString,
};

use crate::Away;

type OnAway = Arc<dyn Fn(Away) + Send + Sync>;

/// What the workspace's own notification center posts in this process.
/// A notification's name is the text of its constant's name.
pub(crate) const FROM_WORKSPACE: [(&str, Away); 3] = [
    ("NSWorkspaceWillSleepNotification", Away::Sleep),
    ("NSWorkspaceScreensDidSleepNotification", Away::ScreensSleep),
    (
        "NSWorkspaceSessionDidResignActiveNotification",
        Away::SwitchedOut,
    ),
];

/// What the system posts to every process.
pub(crate) const FROM_SYSTEM: [(&str, Away); 2] = [
    ("com.apple.screenIsLocked", Away::ScreenLocked),
    ("com.apple.screensaver.didstart", Away::ScreenSaver),
];

const TEXT: &str = "public.utf8-plain-text";
/// The community markers clipboard history apps honor; see nspasteboard.org.
const MARKERS: [&str; 2] = [
    "org.nspasteboard.ConcealedType",
    "org.nspasteboard.TransientType",
];

pub(crate) fn watch(on_away: OnAway) {
    let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
    let system = NSDistributedNotificationCenter::defaultCenter();
    for (name, away) in FROM_WORKSPACE {
        observe(&workspace, name, away, on_away.clone());
    }
    for (name, away) in FROM_SYSTEM {
        observe(&system, name, away, on_away.clone());
    }
}

/// The system posts its notifications to every process of the user, so a
/// test cannot post one of them; it watches one of its own instead.
pub(crate) fn observe_system(name: &str, away: Away, on_away: OnAway) {
    observe(
        &NSDistributedNotificationCenter::defaultCenter(),
        name,
        away,
        on_away,
    );
}

pub(crate) fn observe(center: &NSNotificationCenter, name: &str, away: Away, on_away: OnAway) {
    let name = NSString::from_str(name);
    let block = RcBlock::new(move |_: NonNull<NSNotification>| on_away(away));
    // SAFETY: the method requires a block that may be sent to and run on
    // the thread the center posts from. This one only calls `on_away`,
    // which is `Send` and `Sync`, and holds nothing else.
    let observer = unsafe {
        center.addObserverForName_object_queue_usingBlock(Some(&name), None, None, &block)
    };
    // The center keeps the registration until it is removed, which is
    // never: it lasts as long as the process.
    std::mem::forget(observer);
}

/// The clipboard's count when this process last put a secret there.
static LAST: Mutex<Option<isize>> = Mutex::new(None);

pub(crate) fn copy_secret(pasteboard: &NSPasteboard, text: &str) -> Option<isize> {
    // Callers run on threads that live as long as the process: nothing
    // these calls leave for later may pile up on them.
    autoreleasepool(|_| {
        pasteboard.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
        if !pasteboard.setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT)) {
            return None;
        }
        for marker in MARKERS {
            pasteboard.setString_forType(&NSString::from_str(""), &NSString::from_str(marker));
        }
        let change = pasteboard.changeCount();
        *LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(change);
        Some(change)
    })
}

pub(crate) fn clear_if_unchanged(pasteboard: &NSPasteboard, change: isize) {
    autoreleasepool(|_| {
        if pasteboard.changeCount() == change {
            pasteboard.clearContents();
        }
    });
}

pub(crate) fn clear_last(pasteboard: &NSPasteboard) {
    if let Some(change) = LAST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        clear_if_unchanged(pasteboard, change);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Collects what the callback is told.
    fn collector() -> (Arc<Mutex<Vec<Away>>>, OnAway) {
        let heard = Arc::new(Mutex::new(Vec::new()));
        let into = heard.clone();
        (heard, Arc::new(move |away| into.lock().unwrap().push(away)))
    }

    #[test]
    fn each_notification_of_the_workspace_says_why_the_session_went_away() {
        // A center of its own, so that nothing else in the process hears
        // the notifications posted here.
        let center = NSNotificationCenter::new();
        let (heard, on_away) = collector();
        for (name, away) in FROM_WORKSPACE {
            observe(&center, name, away, on_away.clone());
        }
        for (name, _) in FROM_WORKSPACE {
            // SAFETY: no object goes with the notification.
            unsafe { center.postNotificationName_object(&NSString::from_str(name), None) };
        }
        // Another notification says nothing.
        // SAFETY: as above.
        unsafe {
            center.postNotificationName_object(
                &NSString::from_str("NSWorkspaceDidWakeNotification"),
                None,
            )
        };
        assert_eq!(
            *heard.lock().unwrap(),
            [Away::Sleep, Away::ScreensSleep, Away::SwitchedOut]
        );
    }

    #[test]
    fn a_secret_stays_on_this_mac_marked_for_clipboard_managers_and_comes_off_unless_replaced() {
        // A pasteboard of the test's own, not the owner's clipboard.
        let pasteboard = NSPasteboard::pasteboardWithUniqueName();
        let types = |pasteboard: &NSPasteboard| -> Vec<String> {
            pasteboard
                .types()
                .map(|types| types.to_vec().iter().map(|kind| kind.to_string()).collect())
                .unwrap_or_default()
        };
        let change = copy_secret(&pasteboard, "123456").unwrap();
        assert_eq!(
            pasteboard
                .stringForType(&NSString::from_str(TEXT))
                .unwrap()
                .to_string(),
            "123456"
        );
        for marker in MARKERS {
            assert!(
                types(&pasteboard).contains(&marker.to_owned()),
                "{:?}",
                types(&pasteboard)
            );
        }
        clear_if_unchanged(&pasteboard, change);
        assert!(pasteboard
            .stringForType(&NSString::from_str(TEXT))
            .is_none());

        // Something the owner copied since is left alone.
        let change = copy_secret(&pasteboard, "654321").unwrap();
        pasteboard.clearContents();
        pasteboard.setString_forType(
            &NSString::from_str("the owner's own"),
            &NSString::from_str(TEXT),
        );
        clear_if_unchanged(&pasteboard, change);
        assert_eq!(
            pasteboard
                .stringForType(&NSString::from_str(TEXT))
                .unwrap()
                .to_string(),
            "the owner's own"
        );
        clear_last(&pasteboard);
        assert_eq!(
            pasteboard
                .stringForType(&NSString::from_str(TEXT))
                .unwrap()
                .to_string(),
            "the owner's own"
        );

        // The last secret comes off when the session goes away.
        copy_secret(&pasteboard, "111111").unwrap();
        clear_last(&pasteboard);
        assert!(pasteboard
            .stringForType(&NSString::from_str(TEXT))
            .is_none());
        // Nothing is left in the system's pasteboard server. The bindings
        // leave this method out.
        // SAFETY: `releaseGlobally` takes nothing and returns nothing.
        unsafe { objc2::msg_send![&*pasteboard, releaseGlobally] }
    }
}
