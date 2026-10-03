//! Prints each time the session goes away, as the desktop app would hear
//! it, until stopped or for the number of seconds given. For checking what
//! a real lock, sleep, or user switch sends on a given Mac:
//!
//!   cargo run -p osm-desktop-session --example listen -- [seconds]

fn main() {
    let seconds: f64 = std::env::args()
        .nth(1)
        .map_or(f64::MAX, |text| text.parse().expect("seconds"));
    let start = std::time::Instant::now();
    let told = osm_desktop_session::watch(move |away| {
        println!("{:>8.1}s {}", start.elapsed().as_secs_f64(), away.as_str());
    });
    println!("listening: {told}");
    #[cfg(target_os = "macos")]
    {
        use objc2_foundation::{NSDate, NSRunLoop};
        // The notifications arrive through this thread's run loop.
        while start.elapsed().as_secs_f64() < seconds {
            NSRunLoop::currentRunLoop().runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(1.0));
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = seconds;
}
