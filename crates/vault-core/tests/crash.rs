//! Crashes: a process using a vault is killed at a moment nobody chose, and
//! the vault must open afterwards, consistent, with everything that had been
//! reported done still there.
//!
//! The killed process is this test binary started again as a worker (the
//! ignored test `worker`). It writes what it has finished to its output; the
//! test reads that, kills it with SIGKILL after a random time, and checks the
//! vault. `OSM_CRASH_ROUNDS` sets how many kills each test makes.

#![cfg(unix)]

use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use osm_vault_core::{Item, Vault};
use rusqlite::{Connection, OpenFlags};

/// Not secrets: these open only the vaults these tests make.
const PASSWORDS: [&str; 2] = ["crash test password one", "crash test password two"];
const SECOND_PASSWORD: &str = "crash test second device";

fn rounds(default: usize) -> usize {
    std::env::var("OSM_CRASH_ROUNDS")
        .ok()
        .and_then(|rounds| rounds.parse().ok())
        .unwrap_or(default)
}

/// A small generator, so that a worker's choices follow from its seed.
struct Choices(u64);

impl Choices {
    fn next(&mut self, below: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % below.max(1)
    }
}

/// The worker: does what `OSM_CRASH_WORK` says until it is killed, and says
/// what it has finished, one line at a time.
#[test]
#[ignore = "started by the other tests, which kill it"]
fn worker() {
    let Ok(work) = std::env::var("OSM_CRASH_WORK") else {
        return;
    };
    let folder = PathBuf::from(std::env::var("OSM_CRASH_FOLDER").unwrap());
    let seed: u64 = std::env::var("OSM_CRASH_SEED").unwrap().parse().unwrap();
    let say = |line: String| println!("ACK {line}");
    match work.as_str() {
        "create" => {
            for n in seed.. {
                Vault::create(folder.join(format!("{n}.sqlite3")), PASSWORDS[0]).unwrap();
                say(format!("CREATED {n}"));
            }
        }
        "write" => write_until_killed(&folder, seed, say),
        other => panic!("{other}"),
    }
}

fn write_until_killed(folder: &Path, seed: u64, say: impl Fn(String)) {
    let mut choices = Choices(seed | 1);
    let mut password = std::env::var("OSM_CRASH_PASSWORD").unwrap();
    let mut vault = Vault::open(folder.join("vault.sqlite3")).unwrap();
    vault.unlock(&password).unwrap();
    let mut second = Vault::open(folder.join("second.sqlite3")).unwrap();
    second.unlock(SECOND_PASSWORD).unwrap();
    let mut stranger = Vault::open(folder.join("stranger.sqlite3")).unwrap();
    stranger.unlock(SECOND_PASSWORD).unwrap();
    say("READY".into());
    for step in 0_u64.. {
        let name = format!("{seed}-{step}");
        match choices.next(9) {
            // An item of its own, an edit, and a deletion.
            0 | 1 => {
                let mut item = Item::new(format!("Item {name}"));
                item.id = format!("crash-{name}");
                item.password = name.clone();
                say(format!("REVISION {}", vault.put(item).unwrap().revision));
            }
            2 | 3 => {
                let items = vault.list().unwrap();
                if let Some(summary) = items.get(choices.next(items.len() as u64) as usize) {
                    let found = vault.get(&summary.id).unwrap();
                    if !found.conflict {
                        let mut item = found.item.clone();
                        item.notes = format!("edited at {name}");
                        say(format!(
                            "REVISION {}",
                            vault.update(item, &found.revision).unwrap().revision
                        ));
                    }
                }
            }
            4 => {
                let items = vault.list().unwrap();
                if let Some(summary) = items.get(choices.next(items.len() as u64) as usize) {
                    let found = vault.get(&summary.id).unwrap();
                    if !found.conflict {
                        say(format!(
                            "REVISION {}",
                            vault.delete(&summary.id, &found.revision).unwrap().revision
                        ));
                    }
                }
            }
            // From the other device: taken in at once, or received while
            // locked and processed at the next unlock.
            5 | 6 => {
                let mut item = Item::new(format!("From the second device {name}"));
                item.id = format!("second-{name}");
                let written = second.put(item).unwrap().revision;
                let revision = second
                    .revisions_by_id(std::slice::from_ref(&written))
                    .unwrap()
                    .remove(0);
                if step % 2 == 0 {
                    vault.apply_encrypted_revision(revision).unwrap();
                } else {
                    vault.lock();
                    vault.stage_revision(revision).unwrap();
                    say(format!("STAGED {written}"));
                    vault.unlock(&password).unwrap();
                    vault.process_staged().unwrap();
                }
                say(format!("REVISION {written}"));
            }
            // From a device the vault does not know: held for review, and
            // now and then accepted.
            7 => {
                let mut item = Item::new(format!("From an unknown device {name}"));
                item.id = format!("stranger-{name}");
                let written = stranger.put(item).unwrap().revision;
                let revision = stranger
                    .revisions_by_id(std::slice::from_ref(&written))
                    .unwrap()
                    .remove(0);
                assert!(vault.apply_encrypted_revision(revision).is_err());
                say(format!("HELD {written}"));
                if let Some(held) = vault.quarantined().unwrap().first() {
                    if step % 3 == 0 {
                        // Accepting a revision from a device the vault does
                        // not know writes its content anew and lets the
                        // held one go.
                        say(format!("ACCEPTING {}", held.revision));
                        let accepted = vault.accept_quarantined(&held.revision).unwrap();
                        say(format!("REVISION {}", accepted.revision));
                    }
                }
            }
            // A new password.
            _ => {
                let next = if password == PASSWORDS[0] {
                    PASSWORDS[1]
                } else {
                    PASSWORDS[0]
                };
                vault.change_password(&password, next).unwrap();
                password = next.to_owned();
                say(format!("PASSWORD {password}"));
            }
        }
    }
}

/// A worker, started, with what it has said so far.
struct Worker {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Drop for Worker {
    /// A failed test must not leave a worker writing.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Worker {
    fn start(work: &str, folder: &Path, seed: u64, password: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "worker",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("OSM_CRASH_WORK", work)
            .env("OSM_CRASH_FOLDER", folder)
            .env("OSM_CRASH_SEED", seed.to_string())
            .env("OSM_CRASH_PASSWORD", password)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            // The test harness writes the test's name on the line where the
            // worker's first words start.
            for line in output.lines().map_while(Result::ok) {
                if let Some((_, said)) = line.split_once("ACK ") {
                    if sender.send(said.to_owned()).is_err() {
                        break;
                    }
                }
            }
        });
        Self { child, lines }
    }

    /// What it says until `deadline`, or until it says `until`.
    fn listen(&self, deadline: Instant, until: Option<&str>) -> Vec<String> {
        let mut heard = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let done = Some(line.as_str()) == until;
                    heard.push(line);
                    if done {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        heard
    }

    /// Kills it as a crash would, and returns everything it said.
    fn kill(mut self, mut heard: Vec<String>) -> Vec<String> {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        // Lines already written before the kill.
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(200)) {
            heard.push(line);
        }
        heard
    }
}

/// Long, because macOS can hold a program's start while it checks it.
const START_PATIENCE: Duration = Duration::from_secs(90);

/// Checks what SQLite can say about the file, and that the stored state is
/// one the vault could have been left in: heads are exactly the revisions
/// no other revision of the item names, every parent is stored, and no
/// revision is in two places at once.
fn assert_consistent(path: &Path) {
    // Opened for writing, as anything that uses the vault opens it: a kill
    // during a commit leaves its journal behind, which SQLite rolls back
    // before the first read, and a read-only connection cannot.
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
    let check: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(check, "ok");
    let rows = |sql: &str| -> BTreeSet<String> {
        let mut statement = connection.prepare(sql).unwrap();
        let found = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        found
    };
    let heads = rows("SELECT revision FROM heads");
    let derived = rows(
        "SELECT r.revision FROM revisions r WHERE NOT EXISTS (
             SELECT 1 FROM revisions c
             WHERE c.item_id = r.item_id AND instr(c.parents, r.revision) > 0)",
    );
    assert_eq!(heads, derived, "the heads are not those the revisions make");
    let missing: i64 = connection
        .query_row(
            "WITH RECURSIVE split(parent, rest) AS (
                 SELECT '', parents FROM revisions
                 UNION ALL
                 SELECT substr(rest, 1, 64), substr(rest, 65) FROM split WHERE rest <> '')
             SELECT COUNT(*) FROM split
             WHERE parent <> '' AND parent NOT IN (SELECT revision FROM revisions)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        missing, 0,
        "a stored revision names a parent that is not stored"
    );
    let stored = rows("SELECT revision FROM revisions");
    let staged = rows("SELECT revision FROM ingress");
    let held = rows("SELECT revision FROM quarantine");
    assert!(
        stored.is_disjoint(&staged),
        "a revision is both stored and staged"
    );
    assert!(
        stored.is_disjoint(&held),
        "a revision is both stored and held"
    );
    assert!(
        staged.is_disjoint(&held),
        "a revision is both staged and held"
    );
}

/// Makes the vault the writing worker uses, a second device it takes
/// revisions from, and a device it does not know.
fn prepared() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite3");
    let (mut vault, recovery) = Vault::create(&path, PASSWORDS[0]).unwrap();
    vault.put(Item::new("There from the start")).unwrap();
    vault.export_backup(dir.path().join("backup.json")).unwrap();
    for name in ["second.sqlite3", "stranger.sqlite3"] {
        Vault::restore_backup(
            dir.path().join("backup.json"),
            dir.path().join(name),
            &recovery,
            SECOND_PASSWORD,
        )
        .unwrap();
    }
    let second = Vault::open(dir.path().join("second.sqlite3")).unwrap();
    vault
        .authorize_device(
            second.device_id().unwrap(),
            second.device_public_key().unwrap(),
        )
        .unwrap();
    (dir, path)
}

#[test]
fn a_vault_written_to_by_a_process_that_is_killed_opens_consistent_with_nothing_reported_lost() {
    let (dir, path) = prepared();
    let mut password = PASSWORDS[0].to_owned();
    let mut done = BTreeSet::new();
    let mut held_done = BTreeSet::new();
    let mut kills_while_writing = 0;
    for round in 0..rounds(8) {
        let worker = Worker::start("write", dir.path(), 1000 + round as u64, &password);
        let ready = worker.listen(Instant::now() + START_PATIENCE, Some("READY"));
        assert_eq!(
            ready.last().map(String::as_str),
            Some("READY"),
            "the worker never started"
        );
        // Writes go on for a while that nobody chose.
        let run = Duration::from_millis(50 + (round as u64 * 137) % 900);
        let heard = worker.listen(Instant::now() + run, None);
        let heard = worker.kill(heard);
        kills_while_writing += usize::from(!heard.is_empty());

        // A password reported changed is the one that opens it; if the
        // change was under way, one of the two does.
        for line in &heard {
            if let Some(next) = line.strip_prefix("PASSWORD ") {
                password = next.to_owned();
            }
        }
        assert_consistent(&path);
        let mut vault = Vault::open(&path).unwrap();
        if vault.unlock(&password).is_err() {
            password = PASSWORDS
                .iter()
                .find(|other| **other != password)
                .unwrap()
                .to_string();
            vault
                .unlock(&password)
                .expect("neither password opens the vault");
        }
        // The seal is written in the same transaction as the rows it
        // covers, so a kill never leaves the two apart.
        assert!(
            !vault.rows_changed(),
            "a kill left the rows and their seal apart"
        );

        // Everything it reported done is there.
        for line in &heard {
            if let Some(id) = line.strip_prefix("REVISION ") {
                done.insert(id.to_owned());
            }
            if let Some(id) = line.strip_prefix("HELD ") {
                held_done.insert(id.to_owned());
            }
            if let Some(id) = line.strip_prefix("ACCEPTING ") {
                held_done.remove(id);
            }
        }
        let stored: BTreeSet<String> = vault.revision_ids().unwrap().into_iter().collect();
        assert!(
            done.is_subset(&stored),
            "a revision reported written is missing after round {round}"
        );
        let held: BTreeSet<String> = vault
            .quarantined()
            .unwrap()
            .into_iter()
            .map(|held| held.revision)
            .collect();
        for id in &held_done {
            assert!(
                held.contains(id) || stored.contains(id),
                "a held revision is missing after round {round}"
            );
        }
        // And every item reads, verified.
        for summary in vault.list().unwrap() {
            vault.get(&summary.id).unwrap();
            vault.versions(&summary.id).unwrap();
        }
        vault.process_staged().unwrap();
    }
    assert!(kills_while_writing > 0);
    assert!(!done.is_empty());
}

#[test]
fn a_vault_being_made_when_its_process_is_killed_is_either_there_whole_or_not_there() {
    let dir = tempfile::tempdir().unwrap();
    let mut next = 0_u64;
    for round in 0..rounds(6) {
        let worker = Worker::start("create", dir.path(), next, PASSWORDS[0]);
        // Long enough to start and make one, and then a while that nobody
        // chose.
        let first = worker.listen(
            Instant::now() + START_PATIENCE,
            Some(&format!("CREATED {next}")),
        );
        let more = worker.listen(
            Instant::now() + Duration::from_millis(30 + (round as u64 * 89) % 400),
            None,
        );
        let heard = worker.kill([first, more].concat());
        let made: Vec<u64> = heard
            .iter()
            .filter_map(|line| line.strip_prefix("CREATED "))
            .map(|n| n.parse().unwrap())
            .collect();
        assert!(!made.is_empty(), "the worker never made a vault");
        for n in &made {
            let mut vault = Vault::open(dir.path().join(format!("{n}.sqlite3"))).unwrap();
            vault.unlock(PASSWORDS[0]).unwrap();
            assert!(!vault.rows_changed());
        }
        // The one under way when it was killed is whole or absent, and a new
        // one can be made in its place either way.
        let interrupted = made.iter().max().unwrap() + 1;
        let path = dir.path().join(format!("{interrupted}.sqlite3"));
        if path.exists() {
            let mut vault = Vault::open(&path).expect("a half-made vault was left in place");
            vault.unlock(PASSWORDS[0]).unwrap();
            assert!(!vault.rows_changed());
        } else {
            Vault::create(&path, PASSWORDS[0])
                .expect("what the crash left blocks making the vault");
        }
        next = interrupted + 1;
    }
}
