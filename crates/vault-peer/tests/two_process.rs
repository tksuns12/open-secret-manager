//! Pairs and syncs two vaults running in separate `osm-peer` processes over
//! TLS on localhost. Everything persists on disk between processes.

use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

const PASSWORD: &str = "correct horse battery staple";

fn osm_peer() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_osm-peer"));
    command.env("OSM_PASSWORD", PASSWORD);
    command
}

/// Runs a command to completion and returns its output lines.
fn run(args: &[&str]) -> Vec<String> {
    let output = osm_peer().args(args).output().unwrap();
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

/// A running process whose stdout lines arrive on a channel.
struct Running {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
}

impl Running {
    fn start(args: &[&str]) -> Self {
        let mut child = osm_peer()
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

    /// Returns the rest of the next line starting with `keyword`.
    fn expect(&self, keyword: &str) -> String {
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(60))
                .unwrap_or_else(|_| panic!("no {keyword} line"));
            if let Some(rest) = line.strip_prefix(&format!("{keyword} ")) {
                return rest.to_owned();
            }
            if line == keyword {
                return String::new();
            }
        }
    }

    fn answer(&mut self, text: &str) {
        writeln!(self.stdin, "{text}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn succeed(mut self) {
        assert!(self.child.wait().unwrap().success());
    }
}

fn path(dir: &Path, name: &str) -> String {
    dir.join(name).to_str().unwrap().to_owned()
}

fn items(vault: &str) -> Vec<String> {
    let mut items: Vec<String> = run(&["list", vault])
        .into_iter()
        .filter_map(|line| line.strip_prefix("ITEM ").map(str::to_owned))
        .collect();
    items.sort();
    items
}

#[test]
fn two_processes_pair_and_sync_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (a, a_peers) = (path(dir.path(), "a.db"), path(dir.path(), "a-peers.db"));
    let (b, b_peers) = (path(dir.path(), "b.db"), path(dir.path(), "b-peers.db"));
    run(&["create", &a]);
    run(&["add", &a, "Mail"]);
    run(&["add", &a, "Bank"]);

    // Pair: both processes show the code; the owner compares, then confirms.
    let mut inviter = Running::start(&["invite", &a, &a_peers, "127.0.0.1:0"]);
    inviter.expect("LISTEN");
    let code = inviter.expect("INVITE");
    let mut joiner = Running::start(&["join", &code, &b, &b_peers]);
    let code_on_b = joiner.expect("SAS");
    let code_on_a = inviter.expect("SAS");
    assert_eq!(code_on_a, code_on_b);
    inviter.answer("y");
    joiner.answer("y");
    inviter.expect("PAIRED");
    joiner.expect("JOINED");
    inviter.succeed();
    joiner.succeed();

    // A serves, B dials: B receives the vault.
    let server = Running::start(&["serve", &a, &a_peers, "127.0.0.1:0"]);
    let address = server.expect("LISTEN");
    let synced = run(&["sync", &b, &b_peers, &address]);
    assert!(synced
        .iter()
        .any(|line| line.starts_with("SYNCED sent=0 applied=2")));
    server.succeed();
    assert_eq!(items(&b), ["Bank", "Mail"]);

    // B edits, then B serves and A dials in a new pair of processes.
    run(&["add", &b, "Wifi"]);
    let server = Running::start(&["serve", &b, &b_peers, "127.0.0.1:0"]);
    let address = server.expect("LISTEN");
    let synced = run(&["sync", &a, &a_peers, &address]);
    assert!(synced
        .iter()
        .any(|line| line.starts_with("SYNCED sent=0 applied=1")));
    server.succeed();
    assert_eq!(items(&a), ["Bank", "Mail", "Wifi"]);
    assert_eq!(items(&b), items(&a));
}

#[test]
fn a_declined_code_pairs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (a, a_peers) = (path(dir.path(), "a.db"), path(dir.path(), "a-peers.db"));
    let (b, b_peers) = (path(dir.path(), "b.db"), path(dir.path(), "b-peers.db"));
    run(&["create", &a]);

    let mut inviter = Running::start(&["invite", &a, &a_peers, "127.0.0.1:0"]);
    let code = inviter.expect("INVITE");
    let mut joiner = Running::start(&["join", &code, &b, &b_peers]);
    joiner.expect("SAS");
    inviter.expect("SAS");
    // The owner sees a mismatch on the inviter and declines.
    inviter.answer("n");
    joiner.answer("y");
    assert!(!inviter.child.wait().unwrap().success());
    assert!(!joiner.child.wait().unwrap().success());
    assert!(!Path::new(&b).exists());

    // Neither side recorded a peer, so A has no one to sync with.
    let output = osm_peer()
        .args(["sync", &a, &a_peers, "127.0.0.1:1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no paired device"));
}
