//! Runs the native messaging host as a process, as a browser would: framed
//! JSON on its standard input and output, the extension named on its
//! command line. The desktop session it talks to is either a stand-in that
//! misbehaves on purpose or the real desk serving a real vault.

#![cfg(unix)]

use std::{
    io::Write,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use osm_browser_link::{
    endpoint,
    frame::{Prefix, MAX_FRAME},
    Caller, Forwarded, CHROMIUM_EXTENSION_ID, FIREFOX_EXTENSION_ID,
};
use osm_vault_browser::{bind, serve, Choices, Config, Desk, Refused};
use osm_vault_core::{Item, Vault};
use serde_json::{json, Value};

const PASSWORD: &str = "correct horse battery staple";
const PATIENCE: Duration = Duration::from_secs(30);
const A_WHILE: Duration = Duration::from_millis(300);

/// A home folder with a path short enough for a socket inside it.
fn home() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("osm")
        .tempdir_in("/tmp")
        .unwrap()
}

/// Where the desktop session of the account with this home folder listens.
fn socket(home: &Path) -> PathBuf {
    let data = if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else {
        home.join(".local").join("share")
    };
    endpoint::socket_in(&data.join(endpoint::APP_FOLDER))
}

fn extension() -> String {
    format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")
}

/// The host, started as a browser starts it.
struct Host {
    child: Child,
    stdin: Option<ChildStdin>,
    answers: mpsc::Receiver<Vec<u8>>,
}

impl Drop for Host {
    /// A failed test must not leave the process running.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Host {
    /// Starts the host for the account whose home folder is `home`, with
    /// the arguments a browser would give it.
    fn start(home: &Path, arguments: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_osm-native-host"))
            .args(arguments)
            .env("HOME", home)
            .env_remove("XDG_DATA_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let (sender, answers) = mpsc::channel();
        thread::spawn(move || {
            while let Ok(Some(body)) = Prefix::Browser.read(&mut stdout) {
                if sender.send(body.to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            answers,
        }
    }

    /// Started by the allowed Chromium extension.
    fn of_extension(home: &Path) -> Self {
        Self::start(home, &[&extension()])
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    fn send(&mut self, message: &Value) {
        let body = serde_json::to_vec(message).unwrap();
        self.send_bytes(&Prefix::Browser.frame(&body).unwrap());
    }

    /// The next message the extension would get; `None` once the host has
    /// closed its output.
    fn next(&mut self) -> Option<Value> {
        match self.answers.recv_timeout(PATIENCE) {
            Ok(body) => Some(serde_json::from_slice(&body).unwrap()),
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!(
                "the host neither answers nor ends (exit status so far: {:?})",
                self.child.try_wait()
            ),
        }
    }

    /// The next message that is not a reminder that the owner has yet to
    /// decide.
    fn next_decided(&mut self) -> Option<Value> {
        loop {
            match self.next() {
                Some(message) if message["type"] == "waiting" => {}
                other => return other,
            }
        }
    }

    /// Asserts that the extension gets nothing for a while.
    fn is_quiet(&self) {
        assert_eq!(
            self.answers
                .recv_timeout(A_WHILE)
                .map(|body| String::from_utf8_lossy(&body).into_owned()),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
    }

    /// The browser closes the port. Returns how the host ended.
    fn close(&mut self) -> ExitStatus {
        self.stdin = None;
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(started.elapsed() < PATIENCE, "the host does not end");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn fill(id: &str, origin: &str) -> Value {
    json!({
        "type": "fill_request",
        "version": 1,
        "requestId": id,
        "tabId": 9,
        "frameId": 0,
        "documentId": format!("document-of-{id}"),
        "origin": origin,
    })
}

fn cancel(id: &str) -> Value {
    json!({ "type": "cancel", "version": 1, "requestId": id })
}

fn error(id: &str, code: &str) -> Option<Value> {
    Some(json!({ "type": "error", "requestId": id, "code": code }))
}

fn waiting(id: &str) -> Option<Value> {
    Some(json!({ "type": "waiting", "requestId": id }))
}

/// A stand-in for the desktop session: it listens where the session would
/// and says whatever the test tells it to.
struct StandIn(UnixListener);

impl StandIn {
    fn listen(home: &Path) -> Self {
        let path = socket(home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self(listener)
    }

    fn accepted(&self, within: Duration) -> Option<Connection> {
        let started = Instant::now();
        loop {
            match self.0.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(PATIENCE)).unwrap();
                    return Some(Connection(stream));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if started.elapsed() > within {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        }
    }

    /// The next connection, with the request it brought.
    fn request(&self) -> (Connection, Forwarded) {
        let mut connection = self.accepted(PATIENCE).expect("the host connects");
        let body = Prefix::Socket.read(&mut connection.0).unwrap().unwrap();
        let forwarded = serde_json::from_slice(&body).unwrap();
        (connection, forwarded)
    }

    fn sees_nobody(&self) {
        assert!(self.accepted(A_WHILE).is_none(), "the host connected");
    }
}

/// The stand-in's end of one connection from the host.
struct Connection(UnixStream);

impl Connection {
    fn say(&mut self, message: &Value) {
        let body = serde_json::to_vec(message).unwrap();
        self.say_bytes(&Prefix::Socket.frame(&body).unwrap());
    }

    fn say_bytes(&mut self, bytes: &[u8]) {
        // The host may have hung up already; that is for the test to see.
        let _ = self.0.write_all(bytes);
    }

    /// Whether the host closed the connection without sending more.
    fn is_closed(&mut self) -> bool {
        matches!(Prefix::Socket.read(&mut self.0), Ok(None))
    }
}

#[test]
fn without_a_desktop_session_nothing_is_released() {
    let home = home();
    let mut host = Host::of_extension(home.path());

    // Nothing listens: there is no app folder at all.
    host.send(&fill("a", "https://example.com"));
    assert_eq!(host.next(), error("a", "desktop_session_unavailable"));

    // What is not a request of this protocol is refused before any session
    // is looked for.
    host.send_bytes(&Prefix::Browser.frame(b"not json").unwrap());
    assert_eq!(
        host.next(),
        Some(json!({ "type": "error", "requestId": null, "code": "invalid_message" }))
    );
    host.send(&json!({ "type": "list_logins", "version": 1, "requestId": "b" }));
    assert_eq!(host.next(), error("b", "unsupported_message"));
    let mut newer = fill("c", "https://example.com");
    newer["version"] = json!(2);
    host.send(&newer);
    assert_eq!(host.next(), error("c", "unsupported_version"));
    let mut choosing = fill("d", "https://example.com");
    choosing["recordId"] = json!("5a0e");
    host.send(&choosing);
    assert_eq!(host.next(), error("d", "invalid_message"));
    let mut typed = fill("e", "https://example.com");
    typed["password"] = json!("hunter2");
    host.send(&typed);
    assert_eq!(host.next(), error("e", "invalid_message"));
    for origin in [
        "http://example.com",
        "https://example.com/",
        "https://example.com/login",
        "https://user@example.com",
        "https://EXAMPLE.com",
        "file://",
        "null",
    ] {
        host.send(&fill("f", origin));
        assert_eq!(host.next(), error("f", "origin_rejected"), "{origin}");
    }
    let mut framed = fill("g", "https://example.com");
    framed["frameId"] = json!(3);
    host.send(&framed);
    assert_eq!(host.next(), error("g", "frame_rejected"));
    // Withdrawing a request that is not waiting says nothing.
    host.send(&cancel("a"));
    host.is_quiet();

    // A file in the socket's place is not a session, and neither is a
    // socket nobody listens on any more.
    let path = socket(home.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"").unwrap();
    host.send(&fill("h", "https://example.com"));
    assert_eq!(host.next(), error("h", "desktop_session_unavailable"));
    std::fs::remove_file(&path).unwrap();
    drop(UnixListener::bind(&path).unwrap());
    host.send(&fill("i", "https://example.com"));
    assert_eq!(host.next(), error("i", "desktop_session_unavailable"));

    // The browser closing the port ends the host.
    assert!(host.close().success());
    assert_eq!(host.next(), None);
}

#[test]
fn malformed_framing_ends_the_host_without_an_answer() {
    let home = home();
    let too_long = ((MAX_FRAME + 1) as u32).to_ne_bytes();
    let mut cut_short = 50_u32.to_ne_bytes().to_vec();
    cut_short.extend_from_slice(b"{\"type\":");
    for bytes in [
        // No length, too much length, half a prefix, half a message.
        vec![0, 0, 0, 0],
        too_long.to_vec(),
        vec![7, 0],
        cut_short,
    ] {
        let mut host = Host::of_extension(home.path());
        host.send_bytes(&bytes);
        let status = host.close();
        assert!(!status.success(), "{bytes:?}");
        assert_eq!(host.next(), None, "{bytes:?}");
    }

    // The longest frame there may be is read, and answered.
    let mut host = Host::of_extension(home.path());
    let mut longest = br#"{"type":"fill_request","version":1,"requestId":"a","pad":""#.to_vec();
    longest.resize(MAX_FRAME - 2, b'x');
    longest.extend_from_slice(b"\"}");
    host.send_bytes(&Prefix::Browser.frame(&longest).unwrap());
    assert_eq!(host.next(), error("a", "invalid_message"));
    assert!(host.close().success());
}

#[test]
fn only_the_allowed_extension_reaches_the_desktop_session() {
    let home = home();
    let session = StandIn::listen(home.path());
    let manifest = "/path/to/org.opensecretmanager.native.json";

    let forged: [&[&str]; 6] = [
        // Started by hand.
        &[],
        // Another extension, in each browser.
        &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"],
        &[manifest, "another@example.org"],
        // Names that only resemble the allowed ones.
        &["chrome-extension://hjgekjgkjnakgmiopldddikdkcjhnmge.evil.test/"],
        &[FIREFOX_EXTENSION_ID],
        &["https://example.com/", CHROMIUM_EXTENSION_ID],
    ];
    for arguments in forged {
        let mut host = Host::start(home.path(), arguments);
        host.send(&fill("a", "https://example.com"));
        assert_eq!(
            host.next(),
            error("a", "extension_not_allowed"),
            "{arguments:?}"
        );
        assert!(host.close().success());
    }
    session.sees_nobody();

    // The allowed extension of each browser is passed on, and named.
    let asked = fill("a", "https://example.com");
    let mut host = Host::of_extension(home.path());
    host.send(&asked);
    let (_connection, forwarded) = session.request();
    assert_eq!(forwarded.caller, Caller::Chromium(extension()));
    assert_eq!(
        serde_json::to_value(&forwarded.request).unwrap(),
        // The request, without the word that says what kind of message it is.
        json!({
            "version": 1,
            "requestId": "a",
            "tabId": 9,
            "frameId": 0,
            "documentId": "document-of-a",
            "origin": "https://example.com",
        })
    );

    let mut host = Host::start(home.path(), &[manifest, FIREFOX_EXTENSION_ID]);
    host.send(&asked);
    let (_connection, forwarded) = session.request();
    assert_eq!(
        forwarded.caller,
        Caller::Firefox(FIREFOX_EXTENSION_ID.into())
    );
}

#[test]
fn only_an_answer_to_the_request_is_handed_on() {
    let home = home();
    let session = StandIn::listen(home.path());
    let mut host = Host::of_extension(home.path());
    let reply_to = |id: &str| {
        json!({
            "type": "fill_reply",
            "requestId": id,
            "tabId": 9,
            "frameId": 0,
            "documentId": format!("document-of-{id}"),
            "origin": "https://example.com",
            "username": "alice",
            "password": "correct horse",
        })
    };

    // What answers the request goes to the extension as it is.
    host.send(&fill("a", "https://example.com"));
    let (mut connection, _) = session.request();
    connection.say(&json!({ "type": "waiting", "requestId": "a" }));
    assert_eq!(host.next(), waiting("a"));
    connection.say(&reply_to("a"));
    assert_eq!(host.next(), Some(reply_to("a")));
    assert!(connection.is_closed());
    host.is_quiet();

    // What does not is never handed on: the request ends as if there were
    // no session, and the connection is closed.
    let changed = |field: &str, value: Value| {
        let mut reply = reply_to("b");
        reply[field] = value;
        reply
    };
    let wrong = [
        reply_to("a"),
        changed("origin", json!("https://example.com:8443")),
        changed("origin", json!("https://www.example.com")),
        changed("tabId", json!(10)),
        changed("frameId", json!(1)),
        changed("documentId", json!("document-of-a")),
        changed("extra", json!(true)),
        changed("password", json!(null)),
        json!({ "type": "waiting", "requestId": "a" }),
        json!({ "type": "error", "requestId": "a", "code": "denied" }),
        json!({ "type": "error", "requestId": null, "code": "denied" }),
        json!({ "type": "error", "requestId": "b", "code": "no_such_code" }),
        json!({ "type": "fill_request" }),
        json!("fill_reply"),
    ];
    for answer in &wrong {
        host.send(&fill("b", "https://example.com"));
        let (mut connection, _) = session.request();
        connection.say(answer);
        assert_eq!(
            host.next(),
            error("b", "desktop_session_unavailable"),
            "{answer}"
        );
        assert!(connection.is_closed(), "{answer}");
        // A right answer after the wrong one comes too late.
        connection.say(&reply_to("b"));
        host.is_quiet();
    }
    let too_long = ((MAX_FRAME + 1) as u32).to_be_bytes();
    for bytes in [
        Prefix::Socket.frame(b"not json").unwrap().to_vec(),
        too_long.to_vec(),
        vec![0, 0, 0, 0],
        // Closing without an answer.
        Vec::new(),
    ] {
        host.send(&fill("c", "https://example.com"));
        let (mut connection, _) = session.request();
        connection.say_bytes(&bytes);
        drop(connection);
        assert_eq!(
            host.next(),
            error("c", "desktop_session_unavailable"),
            "{bytes:?}"
        );
    }
    host.is_quiet();
}

#[test]
fn withdrawing_a_request_closes_its_connection() {
    let home = home();
    let session = StandIn::listen(home.path());
    let mut host = Host::of_extension(home.path());

    host.send(&fill("a", "https://example.com"));
    let (mut connection, _) = session.request();
    connection.say(&json!({ "type": "waiting", "requestId": "a" }));
    assert_eq!(host.next(), waiting("a"));
    // The same request again, while it waits, is refused by the host.
    host.send(&fill("a", "https://example.com"));
    assert_eq!(host.next(), error("a", "replayed"));
    session.sees_nobody();

    // The page went away.
    host.send(&cancel("a"));
    assert_eq!(host.next(), error("a", "cancelled"));
    assert!(connection.is_closed());
    // An answer the session sends now reaches nobody.
    connection.say(&json!({
        "type": "fill_reply", "requestId": "a", "tabId": 9, "frameId": 0,
        "documentId": "document-of-a", "origin": "https://example.com",
        "username": "alice", "password": "correct horse",
    }));
    host.is_quiet();
    // Withdrawing it twice says nothing more.
    host.send(&cancel("a"));
    host.is_quiet();

    // The host holds only so many requests open; the session decides which
    // of them waits for the owner.
    let mut open = Vec::new();
    for id in ["b", "c", "d", "e"] {
        host.send(&fill(id, "https://example.com"));
        open.push(session.request().0);
    }
    host.send(&fill("f", "https://example.com"));
    assert_eq!(host.next(), error("f", "busy"));
    session.sees_nobody();
    // One ends, and there is room for another.
    open[0].say(&json!({ "type": "error", "requestId": "b", "code": "busy" }));
    assert_eq!(host.next(), error("b", "busy"));
    host.send(&fill("f", "https://example.com"));
    open.push(session.request().0);

    // The browser closes the port: every request still waiting is
    // withdrawn with it.
    assert!(host.close().success());
    for connection in &mut open[1..] {
        assert!(connection.is_closed());
    }
}

/// The real desk, serving the socket of the account with this home folder.
struct Session {
    desk: Arc<Desk>,
    runtime: tokio::runtime::Runtime,
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Session {
    fn start(home: &Path, config: Config) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let desk = Desk::new(config);
        let bound = bind(&socket(home)).unwrap();
        let serving = runtime.spawn(serve(bound, desk.clone()));
        Self {
            desk,
            runtime,
            serving,
        }
    }

    /// The request the owner is asked about, once it is `request`.
    fn asked(&self, request: &str, vault: &Vault) -> Choices {
        let started = Instant::now();
        loop {
            match self.desk.choices(Some(vault)).unwrap() {
                Some(choices) if choices.request_id == request => return choices,
                _ => assert!(started.elapsed() < PATIENCE, "{request} does not arrive"),
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits until no request is waiting.
    fn idle(&self) {
        let started = Instant::now();
        while self.desk.choices(None).unwrap().is_some() {
            assert!(started.elapsed() < PATIENCE, "the request does not end");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The app quits.
    fn stop(self) {
        self.serving.abort();
        let _ = self.runtime.block_on(self.serving);
    }
}

#[test]
fn a_fill_goes_from_the_vault_to_the_extension_only_on_the_owners_choice() {
    let home = home();
    let session = Session::start(home.path(), Config::default());
    let (mut vault, _) = Vault::create(home.path().join("vault.sqlite3"), PASSWORD).unwrap();
    let mut login = Item::new("Example");
    login.username = "alice@example.test".into();
    login.password = "correct horse".into();
    login.url = "https://example.com/login".into();
    login.notes = "never leaves the vault".into();
    login.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    vault.put(login.clone()).unwrap();
    let mut elsewhere = Item::new("Elsewhere");
    elsewhere.password = "another password".into();
    elsewhere.url = "https://login.example.com/".into();
    vault.put(elsewhere.clone()).unwrap();

    let mut host = Host::of_extension(home.path());

    // The owner picks the login: the extension gets its user name and
    // password, bound to the request, and nothing else of it.
    host.send(&fill("a", "https://example.com"));
    assert_eq!(host.next(), waiting("a"));
    let choices = session.asked("a", &vault);
    assert_eq!(choices.origin, "https://example.com");
    assert_eq!(choices.browser, "Chromium");
    assert_eq!(choices.logins.len(), 1);
    host.is_quiet();
    let unlock = choices.session.unwrap();
    session
        .desk
        .approve("a", &login.id, unlock, &vault)
        .unwrap();
    assert_eq!(
        host.next(),
        Some(json!({
            "type": "fill_reply",
            "requestId": "a",
            "tabId": 9,
            "frameId": 0,
            "documentId": "document-of-a",
            "origin": "https://example.com",
            "username": "alice@example.test",
            "password": "correct horse",
        }))
    );
    host.is_quiet();
    // The same request again gets nothing.
    host.send(&fill("a", "https://example.com"));
    assert_eq!(host.next(), error("a", "replayed"));

    // A page on a subdomain is not offered that login, and cannot be given
    // it.
    host.send(&fill("b", "https://www.example.com"));
    assert_eq!(host.next(), waiting("b"));
    let choices = session.asked("b", &vault);
    assert!(choices.logins.is_empty());
    for item in [&login, &elsewhere] {
        assert!(matches!(
            session.desk.approve("b", &item.id, unlock, &vault),
            Err(Refused::NotForThisPage)
        ));
    }
    host.is_quiet();
    assert!(session.desk.deny("b"));
    assert_eq!(host.next(), error("b", "denied"));

    // The vault locks between the owner's choice and its taking effect:
    // nothing is released, under that unlock or the next.
    host.send(&fill("c", "https://example.com"));
    assert_eq!(host.next(), waiting("c"));
    let choices = session.asked("c", &vault);
    vault.lock();
    assert!(matches!(
        session
            .desk
            .approve("c", &login.id, choices.session.unwrap(), &vault),
        Err(Refused::Locked)
    ));
    vault.unlock(PASSWORD).unwrap();
    assert!(matches!(
        session
            .desk
            .approve("c", &login.id, choices.session.unwrap(), &vault),
        Err(Refused::Locked)
    ));
    host.is_quiet();

    // The page goes away while the request waits: a choice made after
    // that releases nothing.
    let choices = session.asked("c", &vault);
    host.send(&cancel("c"));
    assert_eq!(host.next(), error("c", "cancelled"));
    session.idle();
    assert!(matches!(
        session
            .desk
            .approve("c", &login.id, choices.session.unwrap(), &vault),
        Err(Refused::NotPending)
    ));
    host.is_quiet();

    // The app quits while a request waits.
    host.send(&fill("d", "https://example.com"));
    assert_eq!(host.next(), waiting("d"));
    let choices = session.asked("d", &vault);
    let desk = session.desk.clone();
    session.stop();
    assert_eq!(host.next(), error("d", "desktop_session_unavailable"));
    assert!(matches!(
        desk.approve("d", &login.id, choices.session.unwrap(), &vault),
        Err(Refused::NotPending)
    ));
    host.send(&fill("e", "https://example.com"));
    assert_eq!(host.next(), error("e", "desktop_session_unavailable"));
    host.is_quiet();
    assert!(host.close().success());
}

#[test]
fn a_request_the_owner_leaves_undecided_expires() {
    let home = home();
    let session = Session::start(
        home.path(),
        Config {
            decide_within: Duration::from_millis(900),
            remind_every: Duration::from_millis(200),
            ..Config::default()
        },
    );
    let mut host = Host::of_extension(home.path());
    host.send(&fill("a", "https://example.com"));
    // The extension hears that the session is waiting, more than once.
    assert_eq!(host.next(), waiting("a"));
    assert_eq!(host.next(), waiting("a"));
    assert_eq!(host.next_decided(), error("a", "expired"));
    session.idle();
    assert!(!session.desk.deny("a"));
    host.is_quiet();

    // While one request waits, the session turns the next away.
    host.send(&fill("b", "https://example.com"));
    assert_eq!(host.next(), waiting("b"));
    host.send(&fill("c", "https://example.com"));
    assert_eq!(host.next_decided(), error("c", "busy"));
}
