//! Runs the native messaging host as a process on Windows, as a browser
//! would, against the real desk serving a real named pipe.
//!
//! The host finds the pipe through the account's real data folder, which no
//! environment variable moves, so this is one test, and it leaves the folder
//! as it found it.

#![cfg(windows)]

use std::{
    io::Write,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use osm_browser_link::{endpoint, frame::Prefix, CHROMIUM_EXTENSION_ID};
use osm_vault_browser::{bind, serve, Config, Desk};
use osm_vault_core::{Item, Vault};
use serde_json::{json, Value};

const PASSWORD: &str = "correct horse battery staple";
const PATIENCE: Duration = Duration::from_secs(60);
const A_WHILE: Duration = Duration::from_millis(300);

/// The host, started as Chrome starts it on Windows: the extension's origin,
/// then the handle of the window it was asked from.
struct Host {
    child: Child,
    stdin: Option<ChildStdin>,
    answers: mpsc::Receiver<Vec<u8>>,
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Host {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_osm-native-host"))
            .arg(format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/"))
            .arg("--parent-window=0")
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

    fn send(&mut self, message: &Value) {
        let body = serde_json::to_vec(message).unwrap();
        let stdin = self.stdin.as_mut().unwrap();
        stdin
            .write_all(&Prefix::Browser.frame(&body).unwrap())
            .unwrap();
        stdin.flush().unwrap();
    }

    fn next(&mut self) -> Value {
        match self.answers.recv_timeout(PATIENCE) {
            Ok(body) => serde_json::from_slice(&body).unwrap(),
            Err(error) => panic!(
                "the host does not answer: {error} ({:?})",
                self.child.try_wait()
            ),
        }
    }

    fn is_quiet(&self) {
        assert!(self.answers.recv_timeout(A_WHILE).is_err());
    }

    /// The browser closes the port.
    fn close(&mut self) {
        self.stdin = None;
        let started = Instant::now();
        while self.child.try_wait().unwrap().is_none() {
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

fn error(id: &str, code: &str) -> Value {
    json!({ "type": "error", "requestId": id, "code": code })
}

fn waiting(id: &str) -> Value {
    json!({ "type": "waiting", "requestId": id })
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < PATIENCE, "{what}");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_fill_goes_over_the_pipe_only_on_the_owners_choice() {
    let file = endpoint::pipe_file_path().unwrap();
    let _ = std::fs::remove_file(&file);

    // No session: nothing names a pipe, and a file naming one nobody
    // listens on, or not a pipe of this app at all, is no better.
    let mut host = Host::start();
    host.send(&fill("a", "https://example.com"));
    assert_eq!(host.next(), error("a", "desktop_session_unavailable"));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, endpoint::new_pipe_name().unwrap()).unwrap();
    host.send(&fill("b", "https://example.com"));
    assert_eq!(host.next(), error("b", "desktop_session_unavailable"));
    std::fs::write(&file, r"\\.\pipe\somebody-else").unwrap();
    host.send(&fill("c", "https://example.com"));
    assert_eq!(host.next(), error("c", "desktop_session_unavailable"));
    let _ = std::fs::remove_file(&file);

    // The app starts.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let desk = Desk::new(Config::default());
    let bound = bind(&file).unwrap();
    let serving = runtime.spawn(serve(bound, desk.clone()));
    wait_until("the pipe is named", || file.exists());

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = Vault::create(dir.path().join("vault.sqlite3"), PASSWORD).unwrap();
    let mut login = Item::new("Example");
    login.username = "alice@example.test".into();
    login.password = "correct horse".into();
    login.url = "https://example.com/login".into();
    vault.put(login.clone()).unwrap();
    let asked = |request: &str, vault: &Vault| {
        let mut found = None;
        wait_until("the request arrives", || {
            found = desk
                .choices(Some(vault))
                .unwrap()
                .filter(|choices| choices.request_id == request);
            found.is_some()
        });
        found.unwrap()
    };

    // The owner picks the login: the extension gets its user name and
    // password, bound to the request.
    host.send(&fill("d", "https://example.com"));
    assert_eq!(host.next(), waiting("d"));
    let choices = asked("d", &vault);
    assert_eq!(choices.origin, "https://example.com");
    assert_eq!(choices.logins.len(), 1);
    host.is_quiet();
    desk.approve("d", &login.id, choices.session.unwrap(), &vault)
        .unwrap();
    assert_eq!(
        host.next(),
        json!({
            "type": "fill_reply",
            "requestId": "d",
            "tabId": 9,
            "frameId": 0,
            "documentId": "document-of-d",
            "origin": "https://example.com",
            "username": "alice@example.test",
            "password": "correct horse",
        })
    );

    // The owner turns one down.
    host.send(&fill("e", "https://example.com"));
    assert_eq!(host.next(), waiting("e"));
    asked("e", &vault);
    assert!(desk.deny("e"));
    assert_eq!(host.next(), error("e", "denied"));

    // The extension withdraws one: the host says so, and the app forgets it.
    host.send(&fill("f", "https://example.com"));
    assert_eq!(host.next(), waiting("f"));
    asked("f", &vault);
    host.send(&json!({ "type": "cancel", "version": 1, "requestId": "f" }));
    assert_eq!(host.next(), error("f", "cancelled"));
    wait_until("the request ends", || desk.choices(None).unwrap().is_none());

    // The browser closes the port with one waiting: the app forgets it too.
    host.send(&fill("g", "https://example.com"));
    assert_eq!(host.next(), waiting("g"));
    asked("g", &vault);
    host.close();
    wait_until("the request ends", || desk.choices(None).unwrap().is_none());

    // When the app quits, nothing names its pipe any more.
    serving.abort();
    let _ = runtime.block_on(serving);
    wait_until("the file is removed", || !file.exists());
}
