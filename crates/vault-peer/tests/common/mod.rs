//! Runs `osm-peer` processes and follows their keyword output lines.

#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

pub const PASSWORD: &str = "correct horse battery staple";

/// The `osm-peer` program: where it was built, or in `OSM_TEST_CRATE_DIR`
/// when the tests run on another machine with a copy of the crate's
/// programs, as on a phone (`scripts/test-on-android.sh`).
pub fn osm_peer() -> Command {
    let program = std::env::var_os("OSM_TEST_CRATE_DIR").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_BIN_EXE_osm-peer")),
        |folder| std::path::Path::new(&folder).join("osm-peer"),
    );
    let mut command = Command::new(program);
    command.env("OSM_PASSWORD", PASSWORD);
    command
}

/// Runs a command to completion and returns its output lines.
pub fn run(args: &[&str]) -> Vec<String> {
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
pub struct Running {
    pub child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
}

impl Drop for Running {
    /// A failed test must not leave device processes running.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    pub fn start(args: &[&str]) -> Self {
        Self::spawn(osm_peer(), args)
    }

    /// Starts `osm-relay` on `address`, which devices reach it at too, with
    /// its files in `folder`. Its output line `RELAY-CODE` is the next to
    /// [`expect`](Self::expect).
    pub fn start_relay(folder: &str, address: &str) -> Self {
        let program = std::env::var_os("OSM_TEST_CRATE_DIR").map_or_else(
            || std::path::PathBuf::from(env!("CARGO_BIN_EXE_osm-relay")),
            |folder| std::path::Path::new(&folder).join("osm-relay"),
        );
        Self::spawn(Command::new(program), &[folder, address, address])
    }

    /// Starts a process that has no way to learn the vault password.
    pub fn start_without_password(args: &[&str]) -> Self {
        let mut command = osm_peer();
        command.env_remove("OSM_PASSWORD");
        Self::spawn(command, args)
    }

    fn spawn(mut command: Command, args: &[&str]) -> Self {
        let mut child = command
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
    pub fn expect(&self, keyword: &str) -> String {
        self.expect_within(keyword, Duration::from_secs(60))
    }

    /// As [`Self::expect`], waiting up to `limit` for each line.
    pub fn expect_within(&self, keyword: &str, limit: Duration) -> String {
        loop {
            let line = self
                .lines
                .recv_timeout(limit)
                .unwrap_or_else(|_| panic!("no {keyword} line"));
            if let Some(rest) = line.strip_prefix(&format!("{keyword} ")) {
                return rest.to_owned();
            }
            if line == keyword {
                return String::new();
            }
        }
    }

    /// The lines starting with `prefix`, up to a line that is `end`.
    pub fn collect(&self, prefix: &str, end: &str) -> Vec<String> {
        let mut collected = Vec::new();
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(60))
                .unwrap_or_else(|_| panic!("no {end} line"));
            if line == end {
                return collected;
            }
            if let Some(rest) = line.strip_prefix(prefix) {
                collected.push(rest.to_owned());
            }
        }
    }

    pub fn answer(&mut self, text: &str) {
        writeln!(self.stdin, "{text}").unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn succeed(mut self) {
        assert!(self.child.wait().unwrap().success());
    }
}

pub fn path(dir: &Path, name: &str) -> String {
    dir.join(name).to_str().unwrap().to_owned()
}
