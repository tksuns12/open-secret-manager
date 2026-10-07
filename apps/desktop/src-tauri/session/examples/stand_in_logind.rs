//! A stand-in for logind, for trying the desktop app's locking where no
//! logind runs, as in a container. Start a bus, run this on it, and start
//! the app with that bus as its system bus:
//!
//!   address=$(dbus-daemon --session --fork --print-address=1)
//!   stand_in_logind "$address"
//!   DBUS_SYSTEM_BUS_ADDRESS="$address" open-secret-manager
//!
//! Then each line on standard input sends what logind would: `sleep`,
//! `wake`, `lock`, `locked`, `unlocked`, `away` (the session leaves the
//! seat), or `back`. Linux only.

#[cfg(target_os = "linux")]
#[path = "../tests/support/logind.rs"]
#[allow(dead_code)] // what only the tests use
mod logind;

fn main() {
    #[cfg(target_os = "linux")]
    {
        use logind::{Say, StandIn};
        let address = std::env::args().nth(1).expect("the bus's address");
        let stand_in = StandIn::serve(&address, true);
        println!("serving as logind");
        for line in std::io::stdin().lines() {
            let say = match line.unwrap().trim() {
                "sleep" => Say::Sleep(true),
                "wake" => Say::Sleep(false),
                "lock" => Say::Lock,
                "locked" => Say::LockedHint(true),
                "unlocked" => Say::LockedHint(false),
                "away" => Say::Active(false),
                "back" => Say::Active(true),
                other => {
                    eprintln!("not something logind says: {other}");
                    continue;
                }
            };
            stand_in.say(say);
            println!("said {say:?}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("logind is Linux's");
}
