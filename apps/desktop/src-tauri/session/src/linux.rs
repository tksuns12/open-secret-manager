use std::{
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use dbus::{
    arg::prop_cast,
    blocking::{
        stdintf::org_freedesktop_dbus::{Properties, PropertiesPropertiesChanged},
        Connection,
    },
    message::{MatchRule, SignalArgs},
    Path,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Away;

type OnAway = Arc<dyn Fn(Away) + Send + Sync>;

pub const LOGIND: &str = "org.freedesktop.login1";
pub const MANAGER_PATH: &str = "/org/freedesktop/login1";
pub const MANAGER: &str = "org.freedesktop.login1.Manager";
pub const SESSION: &str = "org.freedesktop.login1.Session";
pub const USER: &str = "org.freedesktop.login1.User";
const ASKING: Duration = Duration::from_secs(5);

/// Watches logind on the system bus, reconnecting with bounded exponential
/// backoff if the bus restarts or drops the connection. Returns `false` if
/// there is no system bus or no session matches could be installed initially.
pub(crate) fn watch(on_away: OnAway) -> bool {
    let Ok(connection) = Connection::new_system() else {
        return false;
    };
    if !register_matches(&connection, &on_away) {
        return false;
    }
    std::thread::Builder::new()
        .name("osm-session".into())
        .spawn(move || {
            let mut active = Some(connection);
            let mut backoff = Duration::from_secs(1);
            loop {
                if let Some(conn) = active.take() {
                    let started = std::time::Instant::now();
                    while conn.process(Duration::from_secs(60)).is_ok() {}
                    if started.elapsed() >= Duration::from_secs(30) {
                        backoff = Duration::from_secs(1);
                    }
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(30));
                if let Ok(conn) = Connection::new_system() {
                    if register_matches(&conn, &on_away) {
                        active = Some(conn);
                    }
                }
            }
        })
        .is_ok()
}

/// The same on the bus at `address`, for tests (single-session, no reconnect).
pub(crate) fn watch_bus(address: &str, on_away: OnAway) -> bool {
    let Ok(mut channel) = dbus::channel::Channel::open_private(address) else {
        return false;
    };
    if channel.register().is_err() {
        return false;
    }
    let connection = Connection::from(channel);
    if !register_matches(&connection, &on_away) {
        return false;
    }
    std::thread::Builder::new()
        .name("osm-session".into())
        .spawn(
            move || {
                while connection.process(Duration::from_secs(60)).is_ok() {}
            },
        )
        .is_ok()
}

/// Registers logind sleep, lock, and seat-change match rules on `connection`.
/// Returns `false` if this process's session cannot be located or any match
/// rule fails, rather than silently pretending session locking is active.
fn register_matches(connection: &Connection, on_away: &OnAway) -> bool {
    let tell = |away| {
        let on_away = on_away.clone();
        move || on_away(away)
    };
    let sleep = tell(Away::Sleep);
    if connection
        .add_match(
            MatchRule::new_signal(MANAGER, "PrepareForSleep")
                .with_sender(LOGIND)
                .with_path(MANAGER_PATH),
            move |(going,): (bool,), _: &Connection, _: &dbus::Message| {
                // It says so again, false, on waking.
                if going {
                    sleep();
                }
                true
            },
        )
        .is_err()
    {
        return false;
    }
    let Some(session) = our_session(connection) else {
        return false;
    };
    let locked = tell(Away::ScreenLocked);
    if connection
        .add_match(
            MatchRule::new_signal(SESSION, "Lock")
                .with_sender(LOGIND)
                .with_path(session.clone()),
            move |_: (), _: &Connection, _: &dbus::Message| {
                locked();
                true
            },
        )
        .is_err()
    {
        return false;
    }
    let (locked, switched) = (tell(Away::ScreenLocked), tell(Away::SwitchedOut));
    connection
        .add_match(
            PropertiesPropertiesChanged::match_rule(
                Some(&dbus::strings::BusName::from(LOGIND)),
                Some(&session),
            )
            .static_clone(),
            move |changed: PropertiesPropertiesChanged, _: &Connection, _: &dbus::Message| {
                if changed.interface_name == SESSION {
                    let properties = &changed.changed_properties;
                    if prop_cast::<bool>(properties, "LockedHint") == Some(&true) {
                        locked();
                    }
                    if prop_cast::<bool>(properties, "Active") == Some(&false) {
                        switched();
                    }
                }
                true
            },
        )
        .is_ok()
}

/// The logind session this program runs in: the one its process belongs
/// to; failing that, the one its environment names; failing that, the
/// graphical session of its user, since a program a desktop starts may run
/// outside any session.
fn our_session(connection: &Connection) -> Option<Path<'static>> {
    let manager = connection.with_proxy(LOGIND, MANAGER_PATH, ASKING);
    let by_pid: Result<(Path<'static>,), _> =
        manager.method_call(MANAGER, "GetSessionByPID", (std::process::id(),));
    if let Ok((path,)) = by_pid {
        return Some(path);
    }
    if let Ok(id) = std::env::var("XDG_SESSION_ID") {
        let named: Result<(Path<'static>,), _> = manager.method_call(MANAGER, "GetSession", (id,));
        if let Ok((path,)) = named {
            return Some(path);
        }
    }
    let uid = std::fs::metadata("/proc/self").ok()?.uid();
    let (user,): (Path<'static>,) = manager.method_call(MANAGER, "GetUser", (uid,)).ok()?;
    let (_, display): (String, Path<'static>) = connection
        .with_proxy(LOGIND, user, ASKING)
        .get(USER, "Display")
        .ok()?;
    (&*display != "/").then_some(display)
}

/// The clipboard as this process serves it. On Linux the program that put
/// something on the clipboard hands it to whoever pastes, for as long as it
/// runs, so this one stays open; the clipboard library takes what it holds
/// away with it otherwise.
struct Served {
    clipboard: arboard::Clipboard,
    /// Per-process random key so no copied secret is retained in plaintext.
    key: [u8; 32],
    copies: isize,
    /// Keyed SHA-256 digest of the last secret put there, and which copy it was.
    last: Option<(isize, [u8; 32])>,
}

static SERVED: Mutex<Option<Served>> = Mutex::new(None);

fn keyed_digest(key: &[u8; 32], text: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"osm-clipboard-v1");
    hasher.update(key);
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// Puts `text` on the clipboard with the hint that clipboard managers
/// honor (`x-kde-passwordManagerHint`: `secret`), so that they keep it out
/// of their history. Says which copy it was.
pub(crate) fn copy_secret(text: &str) -> Option<isize> {
    let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
    if served.is_none() {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).ok()?;
        *served = Some(Served {
            clipboard: arboard::Clipboard::new().ok()?,
            key,
            copies: 0,
            last: None,
        });
    }
    let served = served.as_mut()?;
    use arboard::SetExtLinux;
    served
        .clipboard
        .set()
        .exclude_from_history()
        .text(text.to_owned())
        .ok()?;
    served.copies += 1;
    let digest = keyed_digest(&served.key, text);
    served.last = Some((served.copies, digest));
    Some(served.copies)
}

/// Clears the clipboard if it still holds the last secret, and, given
/// `copy`, only if that secret was that copy.
pub(crate) fn clear(copy: Option<isize>) {
    let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(served) = served.as_mut() else {
        return;
    };
    let Some((last, expected)) = served.last else {
        return;
    };
    if copy.is_some_and(|copy| copy != last) {
        return;
    }
    // Something copied since, by this program or another, stays; if reading the
    // clipboard fails, clear defensively so a secret is never left behind.
    match served.clipboard.get_text() {
        Ok(current) => {
            let current = Zeroizing::new(current);
            if keyed_digest(&served.key, &current) == expected {
                let _ = served.clipboard.clear();
            }
        }
        Err(_) => {
            let _ = served.clipboard.clear();
        }
    }
    served.last = None;
}
