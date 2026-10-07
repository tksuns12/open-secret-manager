//! A stand-in for logind on a bus of a test's own. It holds logind's name,
//! answers what the session crate asks (which session a process is in, the
//! session a name or a user leads to), and sends, when told, what logind
//! sends: the computer going to sleep or waking, a session told to lock,
//! and a session's locked hint or being active changing.

use std::{ffi::CString, sync::mpsc, time::Duration};

use dbus::{
    arg::{PropMap, RefArg, Variant},
    blocking::{stdintf::org_freedesktop_dbus::PropertiesPropertiesChanged, Connection},
    channel::{Channel, MatchingReceiver, Sender},
    message::{MatchRule, SignalArgs},
    strings::ErrorName,
    Message, Path,
};
use osm_desktop_session::logind::{LOGIND, MANAGER, MANAGER_PATH, SESSION, USER};

pub const SESSION_PATH: &str = "/org/freedesktop/login1/session/_3";
pub const USER_PATH: &str = "/org/freedesktop/login1/user/_1000";

/// What the stand-in sends.
#[derive(Clone, Copy, Debug)]
pub enum Say {
    /// `PrepareForSleep`: true before sleeping, false on waking.
    Sleep(bool),
    /// The session's `Lock`.
    Lock,
    /// The session's `LockedHint` changed.
    LockedHint(bool),
    /// The session's `Active` changed.
    Active(bool),
}

pub struct StandIn {
    tell: mpsc::Sender<Say>,
}

impl StandIn {
    /// Serves on the bus at `address`. With `in_session` false, no process
    /// is in a session, as for a program a desktop starts outside its
    /// session: the session is then found through the user.
    pub fn serve(address: &str, in_session: bool) -> StandIn {
        let connection = connect(address);
        connection.request_name(LOGIND, false, true, true).unwrap();
        connection.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |call, connection| {
                let _ = connection.send(answer(&call, in_session));
                true
            }),
        );
        let (tell, told) = mpsc::channel();
        std::thread::spawn(move || loop {
            if connection.process(Duration::from_millis(20)).is_err() {
                return;
            }
            while let Ok(say) = told.try_recv() {
                let _ = connection.send(signal(say));
            }
        });
        StandIn { tell }
    }

    pub fn say(&self, say: Say) {
        self.tell.send(say).unwrap();
    }
}

/// Sends a session's `Lock` as logind would, from a connection that does
/// not hold logind's name: anyone on a bus can.
pub fn impostor_lock(address: &str) {
    let connection = connect(address);
    connection.channel().send(signal(Say::Lock)).unwrap();
    connection.channel().flush();
}

fn connect(address: &str) -> Connection {
    let mut channel = Channel::open_private(address).unwrap();
    channel.register().unwrap();
    Connection::from(channel)
}

fn answer(call: &Message, in_session: bool) -> Message {
    let failed =
        |name: &str, text: &str| call.error(&ErrorName::from(name), &CString::new(text).unwrap());
    let interface = call
        .interface()
        .map(|name| name.to_string())
        .unwrap_or_default();
    let member = call
        .member()
        .map(|name| name.to_string())
        .unwrap_or_default();
    match (interface.as_str(), member.as_str()) {
        (MANAGER, "GetSessionByPID") if in_session => {
            call.method_return().append1(Path::from(SESSION_PATH))
        }
        (MANAGER, "GetSessionByPID") => failed(
            "org.freedesktop.login1.NoSessionForPID",
            "PID does not belong to any known session",
        ),
        (MANAGER, "GetSession") if in_session => {
            call.method_return().append1(Path::from(SESSION_PATH))
        }
        (MANAGER, "GetSession") => failed(
            "org.freedesktop.login1.NoSuchSession",
            "No session by that ID",
        ),
        (MANAGER, "GetUser") => call.method_return().append1(Path::from(USER_PATH)),
        ("org.freedesktop.DBus.Properties", "Get")
            if call.path().as_deref() == Some(USER_PATH)
                && call.read2::<&str, &str>().ok() == Some((USER, "Display")) =>
        {
            call.method_return()
                .append1(Variant(("3".to_owned(), Path::from(SESSION_PATH))))
        }
        _ => failed(
            "org.freedesktop.DBus.Error.UnknownMethod",
            "not in the stand-in",
        ),
    }
}

fn signal(say: Say) -> Message {
    let changed = |name: &str, value: bool| {
        let mut properties = PropMap::new();
        properties.insert(name.to_owned(), Variant(Box::new(value) as Box<dyn RefArg>));
        PropertiesPropertiesChanged {
            interface_name: SESSION.to_owned(),
            changed_properties: properties,
            invalidated_properties: Vec::new(),
        }
        .to_emit_message(&Path::from(SESSION_PATH))
    };
    match say {
        Say::Sleep(going) => Message::new_signal(MANAGER_PATH, MANAGER, "PrepareForSleep")
            .unwrap()
            .append1(going),
        Say::Lock => Message::new_signal(SESSION_PATH, SESSION, "Lock").unwrap(),
        Say::LockedHint(locked) => changed("LockedHint", locked),
        Say::Active(active) => changed("Active", active),
    }
}

/// A bus of the test's own: a `dbus-daemon` with the session bus's rules,
/// under which anyone may hold any name, stopped when dropped.
pub struct Bus {
    daemon: std::process::Child,
    pub address: String,
}

impl Bus {
    pub fn start() -> Bus {
        use std::io::BufRead;
        let mut daemon = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("dbus-daemon, from the dbus package, runs these tests");
        let mut address = String::new();
        std::io::BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Bus {
            daemon,
            address: address.trim().to_owned(),
        }
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}
