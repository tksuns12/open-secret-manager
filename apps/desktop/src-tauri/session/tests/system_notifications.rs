//! The system's notifications reach a process through its main thread's
//! run loop, which the app's windowing runs. The test harness runs tests on
//! other threads, so this test is a program of its own, on the main thread.

fn main() {
    #[cfg(target_os = "macos")]
    macos::a_system_notification_reaches_the_process_through_its_main_run_loop();
    println!("system notifications: ok");
}

#[cfg(target_os = "macos")]
mod macos {
    use std::sync::{Arc, Mutex};

    use objc2_foundation::{NSDate, NSDistributedNotificationCenter, NSRunLoop, NSString};
    use osm_desktop_session::{watch_system_notification, Away};

    pub fn a_system_notification_reaches_the_process_through_its_main_run_loop() {
        // A name of this test's own, so that nothing else hears it.
        let name = format!("org.opensecretmanager.test.{}", std::process::id());
        let heard = Arc::new(Mutex::new(Vec::new()));
        let into = heard.clone();
        watch_system_notification(&name, Away::ScreenLocked, move |away| {
            into.lock().unwrap().push(away)
        });
        // SAFETY: no object or details go with the notification.
        unsafe {
            NSDistributedNotificationCenter::defaultCenter()
                .postNotificationName_object_userInfo_deliverImmediately(
                    &NSString::from_str(&name),
                    None,
                    None,
                    true,
                );
        }
        for _ in 0..100 {
            if !heard.lock().unwrap().is_empty() {
                break;
            }
            NSRunLoop::currentRunLoop().runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.1));
        }
        assert_eq!(*heard.lock().unwrap(), [Away::ScreenLocked]);
    }
}
