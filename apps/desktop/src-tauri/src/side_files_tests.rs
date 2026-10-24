//! The files the desktop app keeps beside the vault, and the names of its
//! archive folders, against what anyone able to write to its data folder
//! could leave there: frozen fixtures of the files as this code writes
//! them (`fixtures/`), and properties over any content.
//!
//! A fixture is never made again: to add one, run with
//! `OSM_WRITE_NEW_FIXTURES=1` while it does not exist.

use std::path::{Path, PathBuf};

use proptest::prelude::*;

use crate::archive::archived_at;
use crate::backup::{backup_age_at, note_backup, FIRST_REMIND_AFTER_DAYS, REMIND_AFTER_DAYS};
use crate::network::{finish_interrupted_recovery, putting_away_note, PutAway, PUTTING_AWAY};
use crate::settings::{self, GeneratorChoice, AUTO_LOCK_CHOICES};

const DAY: u64 = 86_400;
/// The vault the fixtures' backup record is for.
const VAULT_ID: [u8; 16] = [0xab; 16];
/// The time the fixtures were made at, in seconds since 1970.
const MADE_AT: u64 = 1_791_500_000;
/// The files of a vault that putting it away moves, as the tests make them.
const VAULT_FILES: [&str; 4] = [
    "vault.sqlite3",
    "control.sqlite3",
    "peers.sqlite3",
    "invitations.sqlite3",
];
/// Stands in the frozen putting-away note for the folder it was made in,
/// since the note names an absolute path.
const FOLDER: &str = "@DIR@";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/side-files")
        .join(name)
}

/// The frozen bytes of `name`, written from `made` if the file does not
/// exist and new fixtures are asked for.
fn frozen(name: &str, made: &[u8]) -> Vec<u8> {
    let path = fixture(name);
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, made).unwrap();
    }
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_settings_are_written_and_read_as_frozen() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.sqlite3");
    settings::set_auto_lock_at(&vault, 15).unwrap();
    let made = std::fs::read(dir.path().join("settings.json")).unwrap();
    let frozen = frozen("settings.json", &made);
    assert_eq!(
        String::from_utf8_lossy(&made),
        String::from_utf8_lossy(&frozen)
    );

    let other = tempfile::tempdir().unwrap();
    std::fs::write(other.path().join("settings.json"), &frozen).unwrap();
    assert_eq!(
        settings::read(&other.path().join("vault.sqlite3")).auto_lock_minutes,
        15
    );
}

/// A generator choice set (Phase 19) is written beside the wait, which an
/// earlier build reads as before, leaving what it does not know.
#[test]
fn the_generator_choice_is_written_and_read_as_frozen() {
    let digits = GeneratorChoice {
        length: 8,
        lowercase: false,
        uppercase: false,
        digits: true,
        symbols: false,
        avoid_look_alike: true,
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.sqlite3");
    settings::set_auto_lock_at(&vault, 15).unwrap();
    settings::set_generator_at(&vault, digits.clone()).unwrap();
    let made = std::fs::read(dir.path().join("settings.json")).unwrap();
    let frozen = frozen("settings-generator.json", &made);
    assert_eq!(
        String::from_utf8_lossy(&made),
        String::from_utf8_lossy(&frozen)
    );

    let other = tempfile::tempdir().unwrap();
    std::fs::write(other.path().join("settings.json"), &frozen).unwrap();
    let read = settings::read(&other.path().join("vault.sqlite3"));
    assert_eq!((read.auto_lock_minutes, read.generator), (15, digits));
    // The file of Phase 13 has no choice, which is the default.
    std::fs::write(
        other.path().join("settings.json"),
        std::fs::read(fixture("settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        settings::read(&other.path().join("vault.sqlite3")).generator,
        GeneratorChoice::default()
    );
}

#[test]
fn the_backup_record_is_written_and_read_as_frozen() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.sqlite3");
    // The device began counting a day before its first backup.
    backup_age_at(&vault, &VAULT_ID, true, MADE_AT - DAY);
    note_backup(&vault, &VAULT_ID, MADE_AT).unwrap();
    let made = std::fs::read(dir.path().join("backups.json")).unwrap();
    let frozen = frozen("backups.json", &made);
    assert_eq!(
        String::from_utf8_lossy(&made),
        String::from_utf8_lossy(&frozen)
    );

    for (days, due) in [(1, false), (REMIND_AFTER_DAYS, true)] {
        let other = tempfile::tempdir().unwrap();
        let vault = other.path().join("vault.sqlite3");
        std::fs::write(other.path().join("backups.json"), &frozen).unwrap();
        let age = backup_age_at(&vault, &VAULT_ID, true, MADE_AT + days * DAY);
        assert_eq!((age.days, age.due), (Some(days), due));
    }
}

/// A data folder with a vault's files in it, under a scratch folder that
/// also holds a folder outside it.
struct DataFolder {
    root: tempfile::TempDir,
}

impl DataFolder {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("data")).unwrap();
        std::fs::create_dir(root.path().join("outside")).unwrap();
        for name in VAULT_FILES {
            std::fs::write(root.path().join("data").join(name), name).unwrap();
        }
        Self { root }
    }

    fn data(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn vault(&self) -> PathBuf {
        self.data().join("vault.sqlite3")
    }

    /// The vault's files that are in `folder`.
    fn files_in(&self, folder: &Path) -> Vec<&'static str> {
        VAULT_FILES
            .into_iter()
            .filter(|name| folder.join(name).is_file())
            .collect()
    }
}

#[test]
fn the_putting_away_note_is_written_and_read_as_frozen() {
    let folder = DataFolder::new();
    let archive = folder.data().join(format!("archive-{MADE_AT}"));
    let made = putting_away_note(PutAway::Left, &archive)
        .replace(&*folder.data().to_string_lossy(), FOLDER);
    let frozen = String::from_utf8(frozen("putting-away", made.as_bytes())).unwrap();
    assert_eq!(made, frozen);

    // Left at an interruption, it is finished at the next launch.
    std::fs::create_dir(&archive).unwrap();
    std::fs::write(
        folder.data().join(PUTTING_AWAY),
        frozen.replace(FOLDER, &folder.data().to_string_lossy()),
    )
    .unwrap();
    finish_interrupted_recovery(&folder.vault());
    assert_eq!(folder.files_in(&archive), VAULT_FILES);
    assert!(!folder.data().join(PUTTING_AWAY).exists());
    assert_eq!(
        std::fs::read_to_string(folder.data().join(PutAway::Left.note())).unwrap(),
        archive.to_string_lossy()
    );
}

/// A link beside the vault named as an archive, leading out of the data
/// folder: the app never made it, and nothing is moved through it.
#[cfg(unix)]
#[test]
fn a_put_away_is_not_finished_through_a_link() {
    let folder = DataFolder::new();
    let link = folder.data().join("archive-1700000001");
    std::os::unix::fs::symlink(folder.root.path().join("outside"), &link).unwrap();
    std::fs::write(
        folder.data().join(PUTTING_AWAY),
        putting_away_note(PutAway::Removed, &link),
    )
    .unwrap();
    finish_interrupted_recovery(&folder.vault());
    assert_eq!(folder.files_in(&folder.data()), VAULT_FILES);
    assert!(folder
        .files_in(&folder.root.path().join("outside"))
        .is_empty());
    assert!(!folder.data().join(PUTTING_AWAY).exists());
}

/// The archive folder names worth trying: the app's own, near misses, and
/// anything.
fn archive_name() -> impl Strategy<Value = String> {
    prop_oneof![
        (any::<u64>(), proptest::option::of(any::<u64>())).prop_map(|(seconds, counter)| {
            match counter {
                Some(counter) => format!("archive-{seconds}-{counter}"),
                None => format!("archive-{seconds}"),
            }
        }),
        "archive-[0-9]{0,24}(-[0-9]{0,4}){0,2}",
        "archive-[0-9]{1,3}(/|\\\\|\\.\\.|\\.|-| |\u{0}|\n)[a-z0-9./]{0,8}",
        "(\\.\\./|/|\\./)?archive-[0-9]{1,5}",
        "[aA]rchive[-_]?[0-9]{1,5}",
        ".{0,24}",
    ]
}

/// What a `settings.json` might hold.
fn settings_bytes() -> impl Strategy<Value = Vec<u8>> {
    let minutes = prop_oneof![
        any::<u32>().prop_map(|minutes| minutes.to_string()),
        proptest::sample::select(AUTO_LOCK_CHOICES.to_vec())
            .prop_map(|minutes| minutes.to_string()),
        any::<i64>().prop_map(|minutes| minutes.to_string()),
        any::<f64>().prop_map(|minutes| format!("{minutes:?}")),
        Just("null".to_owned()),
        Just("\"5\"".to_owned()),
        Just("[5]".to_owned()),
        Just("1e400".to_owned()),
    ];
    // A generator choice as this app writes it, with any length and kinds,
    // or something else in its place.
    let generator = prop_oneof![
        (any::<u32>(), proptest::array::uniform5(any::<bool>())).prop_map(
            |(length, [lowercase, uppercase, digits, symbols, avoid])| format!(
                "{{\"length\": {length}, \"lowercase\": {lowercase}, \"uppercase\": {uppercase}, \"digits\": {digits}, \"symbols\": {symbols}, \"avoidLookAlike\": {avoid}}}"
            )
        ),
        (8u32..=64).prop_map(|length| format!("{{\"length\": {length}}}")),
        Just("null".to_owned()),
        Just("[]".to_owned()),
        ".{0,12}".prop_map(|junk| format!("{junk:?}")),
    ];
    prop_oneof![
        minutes.prop_map(|minutes| format!("{{\"autoLockMinutes\": {minutes}}}").into_bytes()),
        (any::<u32>(), ".{0,12}").prop_map(|(minutes, junk)| {
            format!("{{\"autoLockMinutes\": {minutes}, \"other\": {junk:?}}}").into_bytes()
        }),
        (
            proptest::sample::select(AUTO_LOCK_CHOICES.to_vec()),
            generator
        )
            .prop_map(|(minutes, generator)| {
                format!("{{\"autoLockMinutes\": {minutes}, \"generator\": {generator}}}")
                    .into_bytes()
            }),
        proptest::collection::vec(any::<u8>(), 0..64),
    ]
}

/// What a `backups.json` might hold: records for this vault or another,
/// with any times, and anything else.
fn backups_bytes() -> impl Strategy<Value = Vec<u8>> {
    let vault = prop_oneof![
        Just("abababababababababababababababab".to_owned()),
        "[0-9a-f]{0,40}",
    ];
    let time = prop_oneof![
        any::<u64>().prop_map(|time| time.to_string()),
        (0u64..200).prop_map(|days| (MADE_AT - days * DAY).to_string()),
        any::<i64>().prop_map(|time| time.to_string()),
        Just("null".to_owned()),
        Just("1.5".to_owned()),
    ];
    prop_oneof![
        (vault, time.clone(), time).prop_map(|(vault, since, last)| {
            format!("{{\"vault\": \"{vault}\", \"since\": {since}, \"lastBackup\": {last}}}")
                .into_bytes()
        }),
        proptest::collection::vec(any::<u8>(), 0..64),
    ]
}

/// What a `putting-away` marker might hold, with the data folder written
/// as [`FOLDER`].
fn putting_away_text() -> impl Strategy<Value = String> {
    let reason = prop_oneof![
        Just("removed".to_owned()),
        Just("left".to_owned()),
        Just("Left".to_owned()),
        Just(String::new()),
        ".{0,8}",
    ];
    let separator = prop_oneof![Just("\n"), Just("\r\n"), Just(" "), Just(""), Just("\n\n")];
    let folder = prop_oneof![
        // A real archive folder the app made.
        Just(format!("{FOLDER}/archive-1700000000")),
        Just(format!("{FOLDER}/archive-1700000000/")),
        Just(format!("{FOLDER}/./archive-1700000000")),
        Just(format!("{FOLDER}/../data/archive-1700000000")),
        Just("archive-1700000000".to_owned()),
        // A link to a folder outside, a file, a folder of another name,
        // one that is not there, the data folder, and outside it.
        Just(format!("{FOLDER}/archive-1700000001")),
        Just(format!("{FOLDER}/archive-1700000002")),
        Just(format!("{FOLDER}/notes")),
        Just(format!("{FOLDER}/archive-1700000003")),
        Just(FOLDER.to_owned()),
        Just(format!("{FOLDER}/../outside")),
        Just("/".to_owned()),
        ".{0,16}",
    ];
    let after = prop_oneof![Just(String::new()), Just("\n".to_owned()), "\n.{0,8}"];
    prop_oneof![
        4 => (reason, separator, folder, after)
            .prop_map(|(reason, separator, folder, after)| format!("{reason}{separator}{folder}{after}")),
        1 => ".{0,40}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A name is taken for an archive folder only when it is one the app
    /// gives: `archive-`, digits, and perhaps `-` and digits. Such a name
    /// is one folder beside the vault, never a path.
    #[test]
    fn only_the_apps_own_archive_names_are_taken(name in archive_name()) {
        let directory = Path::new("/data");
        match archived_at(&name) {
            Some(seconds) => {
                let rest = name.strip_prefix("archive-").unwrap();
                let mut parts = rest.split('-');
                prop_assert_eq!(parts.next().unwrap().parse::<u64>().unwrap(), seconds);
                prop_assert!(parts.next().is_none_or(|counter| !counter.is_empty() && counter.bytes().all(|byte| byte.is_ascii_digit())));
                prop_assert!(parts.next().is_none());
                let folder = directory.join(&name);
                prop_assert_eq!(folder.parent(), Some(directory));
            }
            None => {
                // The app's own names are all taken.
                if let Some(rest) = name.strip_prefix("archive-") {
                    let mut parts = rest.split('-');
                    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
                    let ours = parts.next().is_some_and(|seconds| digits(seconds) && seconds.parse::<u64>().is_ok())
                        && parts.next().is_none_or(digits)
                        && parts.next().is_none();
                    prop_assert!(!ours, "{name:?} was not taken");
                }
            }
        }
    }

    /// Whatever `settings.json` holds, the vault locks after one of the
    /// four waits, the one the file names if it names one of them.
    #[test]
    fn the_settings_always_give_one_of_the_four_waits(bytes in settings_bytes()) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), &bytes).unwrap();
        let minutes = settings::read(&dir.path().join("vault.sqlite3")).auto_lock_minutes;
        prop_assert!(AUTO_LOCK_CHOICES.contains(&minutes));
        let named = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| u32::try_from(value.get("autoLockMinutes")?.as_u64()?).ok())
            .filter(|minutes| AUTO_LOCK_CHOICES.contains(minutes));
        prop_assert_eq!(minutes, named.unwrap_or(5));
        // Whatever the generator part holds, the choice read is one the
        // generator can make.
        let generator = settings::read(&dir.path().join("vault.sqlite3")).generator;
        prop_assert!(settings::GENERATOR_LENGTHS.contains(&generator.length));
        prop_assert!(osm_vault_core::generate_password(&generator.policy()).is_ok());
    }

    /// Whatever `backups.json` holds, the window is told a number of days
    /// and whether to remind: a record for another vault, or anything that
    /// is not a record, starts the count again and reminds of nothing.
    #[test]
    fn the_backup_record_gives_an_age_whatever_it_holds(
        bytes in backups_bytes(),
        recovery in any::<bool>(),
        at in prop_oneof![Just(MADE_AT), any::<u64>()],
    ) {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.sqlite3");
        std::fs::write(dir.path().join("backups.json"), &bytes).unwrap();
        let record = serde_json::from_slice::<serde_json::Value>(&bytes).ok().filter(|value| {
            value["vault"] == "abababababababababababababababab"
                && value["since"].is_u64()
                && (value["lastBackup"].is_u64() || value["lastBackup"].is_null())
        });
        let age = backup_age_at(&vault, &VAULT_ID, recovery, at);
        prop_assert!(!age.due || recovery);
        match record {
            Some(record) => {
                let last = record["lastBackup"].as_u64();
                prop_assert_eq!(age.days, last.map(|last| at.saturating_sub(last) / DAY));
                let counted = at.saturating_sub(last.unwrap_or(record["since"].as_u64().unwrap())) / DAY;
                let after = if last.is_some() { REMIND_AFTER_DAYS } else { FIRST_REMIND_AFTER_DAYS };
                prop_assert_eq!(age.due, recovery && counted >= after);
            }
            None => {
                prop_assert_eq!((age.days, age.due), (None, false));
                // A new count, from now.
                let now = backup_age_at(&vault, &VAULT_ID, true, at);
                prop_assert_eq!((now.days, now.due), (None, false));
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Whatever a `putting-away` marker says, finishing it at launch moves
    /// the vault's files only into a real archive folder beside the vault,
    /// all of them or none, and the marker is gone afterwards.
    #[test]
    fn a_put_away_is_finished_only_into_an_archive_folder_beside_the_vault(text in putting_away_text()) {
        let folder = DataFolder::new();
        let data = folder.data();
        let archive = data.join("archive-1700000000");
        std::fs::create_dir(&archive).unwrap();
        std::fs::create_dir(data.join("notes")).unwrap();
        std::fs::write(data.join("archive-1700000002"), "a file").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(folder.root.path().join("outside"), data.join("archive-1700000001")).unwrap();
        std::fs::write(data.join(PUTTING_AWAY), text.replace(FOLDER, &data.to_string_lossy())).unwrap();

        finish_interrupted_recovery(&folder.vault());

        prop_assert!(!data.join(PUTTING_AWAY).exists());
        prop_assert!(folder.files_in(&folder.root.path().join("outside")).is_empty());
        prop_assert!(folder.files_in(&data.join("notes")).is_empty());
        let here = folder.files_in(&data);
        let archived = folder.files_in(&archive);
        prop_assert!(
            (here == VAULT_FILES && archived.is_empty()) || (here.is_empty() && archived == VAULT_FILES),
            "left {here:?}, archived {archived:?}"
        );
        if !archived.is_empty() {
            let (reason, _) = text.split_once('\n').unwrap();
            prop_assert!(reason == "removed" || reason == "left");
        }
    }
}
