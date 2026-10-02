//! Runs `osm-fill`, the stand-in for the desktop app, as a process and
//! brings it requests over its socket as the native messaging host would.

#![cfg(unix)]

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use osm_browser_link::{
    endpoint, frame::Prefix, Caller, FillRequest, Forwarded, Refusal, Response,
    FIREFOX_EXTENSION_ID, VERSION,
};

const PASSWORD: &str = "correct horse battery staple";
const PATIENCE: Duration = Duration::from_secs(60);

fn osm_fill() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_osm-fill"));
    command.env("OSM_PASSWORD", PASSWORD);
    command
}

/// Runs a command to completion and returns its output lines.
fn run(args: &[&str]) -> Vec<String> {
    let output = osm_fill().args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Adds a login and returns its item ID.
fn add(vault: &str, title: &str, address: &str) -> String {
    let user = format!("{title}@example.test");
    let lines = run(&[
        "add",
        vault,
        title,
        &user,
        &format!("{title} password"),
        address,
    ]);
    lines[0].strip_prefix("ADDED ").unwrap().to_owned()
}

/// A running `osm-fill serve` whose stdout lines arrive on a channel.
struct Serving {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
}

impl Drop for Serving {
    /// A failed test must not leave the process running.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Serving {
    fn start(args: &[&str]) -> Self {
        let mut child = osm_fill()
            .arg("serve")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
        }
    }

    /// The next line, whatever it is.
    fn line(&self) -> String {
        self.lines.recv_timeout(PATIENCE).expect("another line")
    }

    fn say(&mut self, command: &str) {
        writeln!(self.stdin, "{command}").unwrap();
        self.stdin.flush().unwrap();
    }
}

fn request(id: &str, origin: &str) -> Forwarded {
    Forwarded {
        caller: Caller::Firefox(FIREFOX_EXTENSION_ID.into()),
        request: FillRequest {
            version: VERSION,
            request_id: id.into(),
            tab_id: 5,
            frame_id: 0,
            document_id: "document".into(),
            origin: origin.into(),
        },
    }
}

/// Brings a request as the host would and returns the connection.
fn bring(socket: &Path, forwarded: &Forwarded) -> UnixStream {
    let mut connection = endpoint::connect(socket).unwrap();
    connection.set_read_timeout(Some(PATIENCE)).unwrap();
    Prefix::Socket.write(&mut connection, forwarded).unwrap();
    connection
}

/// The response that ends a request, after any number of reminders.
fn last(connection: &mut UnixStream) -> Option<Response> {
    loop {
        let body = Prefix::Socket.read(connection).unwrap()?;
        match serde_json::from_slice(&body).unwrap() {
            Response::Waiting(_) => {}
            other => return Some(other),
        }
    }
}

/// A folder with a path short enough for a socket.
fn folder() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("osm")
        .tempdir_in("/tmp")
        .unwrap()
}

#[test]
fn the_stand_in_fills_denies_and_follows_the_lock() {
    let dir = folder();
    let vault = dir.path().join("vault.sqlite3");
    let vault = vault.to_str().unwrap();
    let socket = endpoint::socket_in(dir.path());
    assert_eq!(run(&["create", vault]), ["CREATED"]);
    let first = add(vault, "first", "https://example.com/login");
    let second = add(vault, "second", "https://example.com/");
    let other = add(vault, "other", "https://other.test/");

    // Left to itself it fills with the first login offered, and turns down
    // a request for a page it has no login for.
    let serving = Serving::start(&[vault, socket.to_str().unwrap(), "first"]);
    assert_eq!(serving.line(), format!("LISTENING {}", socket.display()));
    let asked = request("a", "https://example.com");
    let mut connection = bring(&socket, &asked);
    assert_eq!(serving.line(), "REQUEST a https://example.com Firefox 2");
    let offered = [serving.line(), serving.line()];
    assert!(
        offered.contains(&format!("LOGIN {first} first")),
        "{offered:?}"
    );
    assert!(
        offered.contains(&format!("LOGIN {second} second")),
        "{offered:?}"
    );
    let chosen = offered[0].split(' ').nth(1).unwrap().to_owned();
    assert_eq!(serving.line(), format!("FILLED a {chosen}"));
    let Some(Response::FillReply(reply)) = last(&mut connection) else {
        panic!("a reply")
    };
    assert!(reply.answers(&asked.request));
    let title = if chosen == first { "first" } else { "second" };
    assert_eq!(reply.username, format!("{title}@example.test"));
    assert_eq!(reply.password, format!("{title} password"));

    let mut connection = bring(&socket, &request("b", "https://nothing.test"));
    assert_eq!(serving.line(), "REQUEST b https://nothing.test Firefox 0");
    assert_eq!(serving.line(), "DENIED b");
    assert_eq!(
        last(&mut connection),
        Some(Response::refusal("b", Refusal::Denied))
    );
    drop(serving);

    // Told to ask, it waits for commands, and starts locked if told to.
    let mut serving = Serving::start(&[vault, socket.to_str().unwrap(), "ask", "locked"]);
    assert_eq!(serving.line(), format!("LISTENING {}", socket.display()));
    let asked = request("c", "https://other.test");
    let mut connection = bring(&socket, &asked);
    assert_eq!(
        serving.line(),
        "REQUEST c https://other.test Firefox locked"
    );
    serving.say(&format!("approve {other}"));
    assert_eq!(serving.line(), "REFUSED locked");

    serving.say("unlock");
    assert_eq!(serving.line(), "UNLOCKED");
    assert_eq!(serving.line(), "REQUEST c https://other.test Firefox 1");
    assert_eq!(serving.line(), format!("LOGIN {other} other"));
    // A login for another page is not released for this one.
    serving.say(&format!("approve {first}"));
    assert_eq!(serving.line(), "REFUSED not-for-this-page");

    // Locking takes the offer back; the request keeps waiting.
    serving.say("lock");
    assert_eq!(serving.line(), "LOCKED");
    assert_eq!(
        serving.line(),
        "REQUEST c https://other.test Firefox locked"
    );
    serving.say(&format!("approve {other}"));
    assert_eq!(serving.line(), "REFUSED locked");
    serving.say("unlock");
    assert_eq!(serving.line(), "UNLOCKED");
    assert_eq!(serving.line(), "REQUEST c https://other.test Firefox 1");
    assert_eq!(serving.line(), format!("LOGIN {other} other"));
    serving.say(&format!("approve {other}"));
    assert_eq!(serving.line(), format!("FILLED c {other}"));
    let Some(Response::FillReply(reply)) = last(&mut connection) else {
        panic!("a reply")
    };
    assert!(reply.answers(&asked.request));
    assert_eq!(reply.password, "other password");

    // A request withdrawn while it waits is reported as ended.
    let connection = bring(&socket, &request("d", "https://other.test"));
    assert_eq!(serving.line(), "REQUEST d https://other.test Firefox 1");
    assert_eq!(serving.line(), format!("LOGIN {other} other"));
    drop(connection);
    assert_eq!(serving.line(), "ENDED d");
    serving.say("deny");
    assert_eq!(serving.line(), "REFUSED not-pending");

    // Quitting stops the session and takes the socket away.
    serving.say("quit");
    assert!(serving.child.wait().unwrap().success());
    assert!(!socket.exists());
}
