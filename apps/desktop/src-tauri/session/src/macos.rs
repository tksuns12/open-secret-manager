use std::{
    ptr::NonNull,
    sync::{Arc, Mutex},
};

use block2::RcBlock;
use objc2::{rc::autoreleasepool, runtime::ProtocolObject};
use objc2_app_kit::{
    NSPasteboard, NSPasteboardContentsOptions, NSPasteboardItem, NSPasteboardWriting, NSWorkspace,
};
use objc2_foundation::{
    NSArray, NSDistributedNotificationCenter, NSNotification, NSNotificationCenter, NSString,
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
    // Serialize clipboard writes and clears against `LAST`, and publish the
    // text together with Concealed/Transient markers in a single atomic
    // `NSPasteboardItem` so clipboard watchers never see an unmarked copy.
    let mut last = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    autoreleasepool(|_| {
        let item = NSPasteboardItem::new();
        if !item.setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT)) {
            return None;
        }
        for marker in MARKERS {
            if !item.setString_forType(&NSString::from_str(""), &NSString::from_str(marker)) {
                return None;
            }
        }
        pasteboard.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
        let writing: &ProtocolObject<dyn NSPasteboardWriting> = ProtocolObject::from_ref(&*item);
        let objects = NSArray::from_slice(&[writing]);
        if !pasteboard.writeObjects(&objects) {
            return None;
        }
        let change = pasteboard.changeCount();
        *last = Some(change);
        Some(change)
    })
}

pub(crate) fn clear_if_unchanged(pasteboard: &NSPasteboard, change: isize) {
    let mut last = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    autoreleasepool(|_| {
        if pasteboard.changeCount() == change {
            pasteboard.clearContents();
            if *last == Some(change) {
                *last = None;
            }
        }
    });
}

pub(crate) fn clear_last(pasteboard: &NSPasteboard) {
    let mut last = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(change) = last.take() {
        autoreleasepool(|_| {
            if pasteboard.changeCount() == change {
                pasteboard.clearContents();
            }
        });
    }
}

/// Whether the system can check the owner here: Touch ID, or the Mac's
/// password, as the system chooses.
pub(crate) fn can_check_owner() -> bool {
    use objc2_local_authentication::{LAContext, LAPolicy};
    // SAFETY: a new context, asked one question on this thread.
    unsafe { LAContext::new().canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }.is_ok()
}

/// Wrapper allowing `LAContext` to be invalidated from another thread when a
/// waiting passkey request ends before verification finishes.
struct SendContext(objc2::rc::Retained<objc2_local_authentication::LAContext>);

// SAFETY: Apple documents `LAContext::invalidate()` as thread-safe and valid to
// call from any thread while an evaluation is in progress.
unsafe impl Send for SendContext {}

/// Asks the system to check the owner, saying `reason`; `done` is called
/// once, on a thread of the system's, with whether the check passed. Returns a
/// cancellation closure that invalidates the `LAContext` if still pending.
pub(crate) fn check_owner(
    reason: &str,
    done: Box<dyn FnOnce(bool) + Send>,
) -> Box<dyn FnOnce() + Send> {
    use objc2::runtime::Bool;
    use objc2_foundation::NSError;
    use objc2_local_authentication::{LAContext, LAPolicy};
    // SAFETY: a new context, used for this one check.
    let context = unsafe { LAContext::new() };
    let done = Arc::new(Mutex::new(Some(done)));
    let kept = Arc::new(Mutex::new(Some(SendContext(context.clone()))));
    let reply_done = done.clone();
    let reply_kept = kept.clone();
    let reply = RcBlock::new(move |passed: Bool, _: *mut NSError| {
        if let Some(done) = reply_done.lock().ok().and_then(|mut done| done.take()) {
            done(passed.as_bool());
        }
        drop(reply_kept.lock().ok().and_then(|mut kept| kept.take()));
    });
    // SAFETY: the system runs the block on a queue of its own; the block
    // only calls `done`, which is `Send`, and lets go of the context.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &NSString::from_str(reason),
            &reply,
        )
    };
    Box::new(move || {
        if let Some(ctx) = kept.lock().ok().and_then(|mut kept| kept.take()) {
            // SAFETY: `LAContext::invalidate` cancels any pending evaluation
            // and is safe to invoke from any thread.
            unsafe { ctx.0.invalidate() };
        }
        if let Some(done) = done.lock().ok().and_then(|mut done| done.take()) {
            done(false);
        }
    })
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
