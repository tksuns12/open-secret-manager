//! Input that was not made by this code: files the owner picks, revisions a
//! peer sends, and a vault file that something else wrote to. Each test
//! states a property and tries it on many generated inputs. A panic on any
//! of them is a failure.
//!
//! The cases are new on every run. One that fails is written to
//! `proptest-regressions/` beside this file and tried first from then on;
//! keep that file.

use std::collections::BTreeSet;

use proptest::prelude::*;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::{
    fixture_tests::{copy_of, fixture, Expected, CURRENT},
    preview_import, totp_code, EncryptedRevision, Error, ImportFormat, Item, RecoveryKey, Vault,
};

/// A secret that must never come back in an error.
const MARKER: &str = "hunter2-do-not-repeat";

fn formats() -> impl Strategy<Value = ImportFormat> {
    prop_oneof![
        Just(ImportFormat::BitwardenJson),
        Just(ImportFormat::ChromeCsv),
        Just(ImportFormat::FirefoxCsv),
    ]
}

/// What is shown to the owner or written down about an error.
fn said(error: &Error) -> String {
    format!("{error} {error:?}")
}

/// Any JSON value, with the marker among its strings and numbers.
fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        Just(Value::from(MARKER)),
        "[a-z ]{0,8}".prop_map(Value::from),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
            prop::collection::vec(("[a-z]{1,6}", inner), 0..4)
                .prop_map(|fields| Value::Object(fields.into_iter().collect())),
        ]
    })
}

/// Something shaped like a Bitwarden export, with any value in any place.
fn bitwarden_like() -> impl Strategy<Value = Value> {
    let field = prop_oneof![
        Just("type"),
        Just("name"),
        Just("notes"),
        Just("favorite"),
        Just("login"),
        Just("fields"),
        Just("card"),
        Just("identity"),
        Just("username"),
        Just("password"),
        Just("totp"),
        Just("uris"),
        Just("uri"),
        Just("value"),
    ];
    let login = prop::collection::vec((field.clone(), any_json()), 0..5).prop_map(|fields| {
        Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        )
    });
    let item = (
        prop_oneof![(0_u8..6).prop_map(Value::from), any_json()],
        prop_oneof![
            Just(Value::from(MARKER)),
            "[A-Za-z ]{0,6}".prop_map(Value::from),
            any_json()
        ],
        prop_oneof![login, any_json()],
        prop::collection::vec((field, any_json()), 0..4),
    )
        .prop_map(|(kind, name, login, more)| {
            let mut item = json!({ "type": kind, "name": name, "login": login });
            for (name, value) in more {
                item[name] = value;
            }
            item
        });
    prop_oneof![
        prop::collection::vec(item, 0..4).prop_map(|items| json!({ "items": items })),
        any_json(),
    ]
}

/// CSV text with the columns an import needs, in some order, and anything
/// in the rows.
fn csv_like() -> impl Strategy<Value = Vec<u8>> {
    let cell = prop_oneof![
        Just(MARKER.to_owned()),
        "[ -~]{0,12}",
        "\"[ -~\n]{0,12}\"",
        Just("https://example.test/login".to_owned()),
        Just(String::new()),
    ];
    let header = prop::sample::subsequence(
        vec![
            "name",
            "url",
            "username",
            "password",
            "note",
            "httpRealm",
            "formActionOrigin",
            "extra",
        ],
        0..=8,
    )
    .prop_shuffle();
    (
        header,
        prop::collection::vec(prop::collection::vec(cell, 0..9), 0..6),
    )
        .prop_map(|(header, rows)| {
            let mut text = header.join(",");
            for row in rows {
                text.push('\n');
                text.push_str(&row.join(","));
            }
            text.into_bytes()
        })
}

proptest! {
    /// Whatever bytes are handed in as an import are refused or become
    /// items that can be stored, and a refusal repeats none of the input.
    #[test]
    fn any_bytes_as_an_import_are_refused_or_become_storable_items(
        format in formats(),
        bytes in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        match preview_import(format, &bytes) {
            Ok(preview) => {
                prop_assert!(!preview.items().is_empty());
                for item in preview.items() {
                    prop_assert!(item.validate().is_ok());
                }
            }
            Err(error) => prop_assert!(matches!(error, Error::InvalidImport(_) | Error::Csv(_))),
        }
    }

    #[test]
    fn a_malformed_bitwarden_export_is_refused_without_repeating_what_it_held(export in bitwarden_like()) {
        let bytes = serde_json::to_vec(&export).unwrap();
        match preview_import(ImportFormat::BitwardenJson, &bytes) {
            Ok(preview) => {
                for item in preview.items() {
                    prop_assert!(item.validate().is_ok());
                }
                for warning in preview.warnings() {
                    prop_assert!(!warning.message.contains(MARKER), "{}", warning.message);
                }
            }
            Err(error) => prop_assert!(!said(&error).contains(MARKER), "{}", said(&error)),
        }
    }

    #[test]
    fn a_malformed_csv_export_is_refused_without_repeating_what_it_held(
        format in prop_oneof![Just(ImportFormat::ChromeCsv), Just(ImportFormat::FirefoxCsv)],
        bytes in csv_like(),
    ) {
        match preview_import(format, &bytes) {
            Ok(preview) => {
                for item in preview.items() {
                    prop_assert!(item.validate().is_ok());
                }
                for warning in preview.warnings() {
                    prop_assert!(!warning.message.contains(MARKER), "{}", warning.message);
                }
            }
            Err(error) => prop_assert!(!said(&error).contains(MARKER), "{}", said(&error)),
        }
    }

    /// A recovery key is read from exactly one text, and anything else is
    /// refused.
    #[test]
    fn a_recovery_key_is_read_only_from_its_own_text(text in "(OSM-RK1-)?[A-Za-z0-9_=+/ -]{0,60}") {
        if let Ok(key) = RecoveryKey::parse(&text) {
            prop_assert_eq!(key.to_string(), text);
        }
    }

    #[test]
    fn a_recovery_key_survives_being_written_down_and_typed_in(bytes in any::<[u8; 32]>()) {
        let key = RecoveryKey::from_bytes(bytes);
        let read = RecoveryKey::parse(&key.to_string()).unwrap();
        prop_assert!(read.expose() == &bytes);
        let debugged = format!("{:?}", key);
        prop_assert!(!debugged.contains(&key.to_string()));
    }

    /// A one-time code is six or eight digits, or the secret is refused,
    /// whatever was stored as the secret.
    #[test]
    fn a_one_time_code_is_digits_or_a_refusal(
        secret in prop_oneof![
            "[A-Z2-7a-z =-]{0,40}",
            "otpauth://(totp|hotp|x)/[a-z:@.]{0,12}\\?(secret=[A-Z2-7]{0,32}|digits=[0-9]{0,12}|period=[0-9]{0,22}|algorithm=[A-Za-z0-9]{0,8}|[a-z]{1,4}=[a-z0-9]{0,4}|&){0,6}",
            ".{0,40}",
        ],
        time in any::<u64>(),
    ) {
        match totp_code(&secret, time) {
            Ok(code) => {
                prop_assert!(code.len() == 6 || code.len() == 8);
                prop_assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
            }
            Err(error) => {
                prop_assert!(matches!(error, Error::InvalidItem(_)));
                prop_assert!(secret.len() < 4 || !said(&error).contains(&secret));
            }
        }
    }
}

/// The frozen vault, unlocked, with what its history and its shown items
/// are before anything hostile reaches it.
struct Sound {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    vault: Vault,
    stored: Vec<EncryptedRevision>,
    /// Every content the history holds, as JSON, deletions as `null`.
    history: BTreeSet<String>,
}

impl Sound {
    fn new() -> Self {
        let (dir, path) = copy_of(CURRENT);
        let mut vault = Vault::open(&path).unwrap();
        vault
            .unlock_with_recovery(&Expected::of(CURRENT).recovery())
            .unwrap();
        let stored = vault.encrypted_revisions().unwrap();
        let history = vault
            .history_for_tests()
            .unwrap()
            .iter()
            .map(|item| serde_json::to_string(item).unwrap())
            .collect();
        Self {
            _dir: dir,
            path,
            vault,
            stored,
            history,
        }
    }
}

/// What the owner sees of a vault: its items and whether each is in
/// conflict, and which revisions it has accepted.
fn shown(vault: &Vault) -> (Vec<String>, BTreeSet<String>) {
    let items = vault
        .list()
        .unwrap()
        .into_iter()
        .map(|summary| {
            let found = vault.get(&summary.id).unwrap();
            format!(
                "{} {} {}",
                found.revision,
                found.conflict,
                serde_json::to_string(&found.item).unwrap()
            )
        })
        .collect();
    (items, vault.revision_ids().unwrap().into_iter().collect())
}

/// One change to a revision that some device really wrote.
#[derive(Clone, Debug)]
enum Twist {
    FlipCiphertext(usize),
    FlipNonce(usize),
    FlipSignature(usize),
    FlipVault(usize),
    FlipAuthor(usize),
    Author(usize),
    Item(String),
    Parents(Vec<usize>),
    UnknownParent(u8),
    Epoch(u64),
    Tombstone,
    Truncate(usize),
    Extend(Vec<u8>),
    ContentOf(usize),
    SignatureOf(usize),
}

fn twists() -> impl Strategy<Value = Twist> {
    prop_oneof![
        any::<usize>().prop_map(Twist::FlipCiphertext),
        any::<usize>().prop_map(Twist::FlipNonce),
        any::<usize>().prop_map(Twist::FlipSignature),
        any::<usize>().prop_map(Twist::FlipVault),
        any::<usize>().prop_map(Twist::FlipAuthor),
        any::<usize>().prop_map(Twist::Author),
        prop_oneof![
            Just("fixture-bank".to_owned()),
            Just("fixture-mail".to_owned()),
            "[a-z-]{1,12}"
        ]
        .prop_map(Twist::Item),
        prop::collection::vec(any::<usize>(), 0..4).prop_map(Twist::Parents),
        any::<u8>().prop_map(Twist::UnknownParent),
        prop_oneof![Just(1_u64), Just(2), Just(3), 1..(1_u64 << 32)].prop_map(Twist::Epoch),
        Just(Twist::Tombstone),
        (0_usize..64).prop_map(Twist::Truncate),
        prop::collection::vec(any::<u8>(), 1..32).prop_map(Twist::Extend),
        any::<usize>().prop_map(Twist::ContentOf),
        any::<usize>().prop_map(Twist::SignatureOf),
    ]
}

fn twisted(stored: &[EncryptedRevision], base: usize, twists: &[Twist]) -> EncryptedRevision {
    let mut revision = stored[base % stored.len()].clone();
    let other = |index: usize| &stored[index % stored.len()];
    for twist in twists {
        match twist {
            Twist::FlipCiphertext(at) => {
                let at = at % revision.ciphertext.len().max(1);
                if let Some(byte) = revision.ciphertext.get_mut(at) {
                    *byte ^= 1;
                }
            }
            Twist::FlipNonce(at) => revision.nonce[at % 24] ^= 1,
            Twist::FlipSignature(at) => {
                let at = at % revision.signature.len().max(1);
                if let Some(byte) = revision.signature.get_mut(at) {
                    *byte ^= 1;
                }
            }
            Twist::FlipVault(at) => revision.vault_id[at % 32] ^= 1,
            Twist::FlipAuthor(at) => revision.author_device_id[at % 16] ^= 1,
            Twist::Author(index) => revision.author_device_id = other(*index).author_device_id,
            Twist::Item(id) => revision.item_id = id.clone(),
            Twist::Parents(indexes) => {
                let mut parents: Vec<String> = indexes
                    .iter()
                    .map(|index| other(*index).revision_id())
                    .collect();
                parents.sort();
                parents.dedup();
                revision.parents = parents;
            }
            Twist::UnknownParent(byte) => revision.parents = vec![format!("{byte:02x}").repeat(32)],
            Twist::Epoch(epoch) => revision.key_epoch = *epoch,
            Twist::Tombstone => revision.tombstone = !revision.tombstone,
            Twist::Truncate(by) => {
                let keep = revision.ciphertext.len().saturating_sub(*by);
                revision.ciphertext.truncate(keep);
            }
            Twist::Extend(more) => revision.ciphertext.extend_from_slice(more),
            Twist::ContentOf(index) => {
                revision.nonce = other(*index).nonce;
                revision.ciphertext = other(*index).ciphertext.clone();
            }
            Twist::SignatureOf(index) => revision.signature = other(*index).signature.clone(),
        }
    }
    revision
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A revision made from real ones by any changes is never taken into
    /// the history unless it is one of the real ones, and what the owner
    /// sees stays as it was. Each case tries several revisions on one vault,
    /// received while unlocked and while locked.
    #[test]
    fn a_changed_revision_never_joins_the_history(
        attempts in prop::collection::vec((any::<usize>(), prop::collection::vec(twists(), 1..4)), 1..12),
    ) {
        let mut sound = Sound::new();
        let before = shown(&sound.vault);
        let real: BTreeSet<String> = sound.stored.iter().map(EncryptedRevision::revision_id).collect();
        let recovery = Expected::of(CURRENT).recovery();

        for (base, twists) in &attempts {
            let revision = twisted(&sound.stored, *base, twists);
            let id = revision.revision_id();
            let outcome = sound.vault.apply_encrypted_revision(revision.clone());
            prop_assert!(outcome.is_err() || real.contains(&id), "{twists:?} was accepted");
            prop_assert_eq!(&shown(&sound.vault), &before);

            // The same revision, arriving while the vault is locked.
            sound.vault.lock();
            let staged = sound.vault.stage_revision(revision);
            prop_assert!(staged.is_ok() || matches!(staged, Err(Error::Crypto | Error::UnsupportedVersion(_))));
            sound.vault.unlock_with_recovery(&recovery).unwrap();
            sound.vault.process_staged().unwrap();
            prop_assert_eq!(&shown(&sound.vault), &before);
        }
        // Whatever is still waiting or held, the history is what it was.
        prop_assert_eq!(
            sound.vault.revision_ids().unwrap().into_iter().collect::<BTreeSet<_>>(),
            real
        );
    }

    /// A vault file that something wrote into opens to an error or to
    /// content that is part of its history: never to anything else, and
    /// never to a crash.
    #[test]
    fn a_damaged_vault_file_shows_an_error_or_what_was_written(
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..12),
        wipe in prop::option::of((any::<prop::sample::Index>(), 1_usize..4096)),
    ) {
        let sound = Sound::new();
        let history = sound.history.clone();
        let path = sound.path.clone();
        drop(sound.vault);

        let mut bytes = std::fs::read(&path).unwrap();
        for (at, with) in &flips {
            let at = at.index(bytes.len());
            bytes[at] ^= with | 1;
        }
        if let Some((at, length)) = wipe {
            let at = at.index(bytes.len());
            let end = (at + length).min(bytes.len());
            bytes[at..end].fill(0);
        }
        std::fs::write(&path, &bytes).unwrap();

        let read = || -> Result<Vec<Item>, Error> {
            let mut vault = Vault::open(&path)?;
            vault.unlock_with_recovery(&Expected::of(CURRENT).recovery())?;
            let mut items = Vec::new();
            for summary in vault.list()? {
                items.push(vault.get(&summary.id)?.item.clone());
                for version in vault.versions(&summary.id)? {
                    items.extend(version.item);
                }
            }
            for held in vault.quarantined()? {
                items.extend(held.item);
            }
            Ok(items)
        };
        if let Ok(items) = read() {
            for item in items {
                let content = serde_json::to_string(&Some(&item)).unwrap();
                // A held revision is not part of the history; the fixture's
                // two are known.
                let held = item.id.starts_with("fixture-from-");
                prop_assert!(history.contains(&content) || held, "{content} was never written");
            }
        }
    }

    /// A backup that something wrote into is refused, or restores exactly
    /// what the backup held.
    #[test]
    fn a_damaged_backup_is_refused_or_restores_what_it_held(
        changes in prop::collection::vec(
            (any::<prop::sample::Index>(), prop_oneof![
                any::<u8>().prop_map(|with| (0_u8, with)),
                any::<u8>().prop_map(|with| (1_u8, with)),
                Just((2_u8, 0_u8)),
            ]),
            1..6,
        ),
    ) {
        let expected = Expected::of(CURRENT);
        let mut bytes = std::fs::read(fixture(CURRENT, "backup.json")).unwrap();
        for (at, (kind, with)) in &changes {
            let at = at.index(bytes.len());
            match kind {
                0 => bytes[at] = *with,
                1 => bytes.insert(at, *with),
                _ => { bytes.remove(at); }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("backup.json");
        let destination = dir.path().join("restored.sqlite3");
        std::fs::write(&backup, &bytes).unwrap();
        match Vault::restore_backup(&backup, &destination, &expected.recovery(), "a new password") {
            Ok(restored) => {
                let stored: BTreeSet<String> = restored.revision_ids().unwrap().into_iter().collect();
                let written: BTreeSet<String> = expected.current()["revision_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id.as_str().unwrap().to_owned())
                    .collect();
                prop_assert_eq!(stored, written);
            }
            Err(_) => prop_assert!(!destination.exists()),
        }
    }
}

/// Puts `rows` rows of the shape a received revision has into a table of
/// the vault file, as fast as SQLite can count.
fn fill(path: &std::path::Path, table: &str, rows: usize) {
    Connection::open(path)
        .unwrap()
        .execute(
            &format!(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < {rows})
                 INSERT INTO {table}(revision, format_version, vault_id, item_id, parents, key_epoch,
                                     author_device_id, nonce, ciphertext, tombstone, signature)
                 SELECT printf('%064x', i), 2, (SELECT vault_id FROM vault_meta), 'filler', '', 9,
                        zeroblob(16), zeroblob(24), zeroblob(16), 1, zeroblob(64) FROM n"
            ),
            [],
        )
        .unwrap();
}

fn rows(path: &std::path::Path, table: &str) -> usize {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap() as usize
}

/// At most 100,000 received revisions wait to be processed. One more is
/// refused, locked or not, and nothing that waits is lost.
#[test]
fn the_queue_of_received_revisions_is_full_at_its_bound() {
    let mut sound = Sound::new();
    let recovery = Expected::of(CURRENT).recovery();
    let last = twisted(&sound.stored, 0, &[Twist::UnknownParent(0xee)]);
    let one_more = twisted(&sound.stored, 0, &[Twist::UnknownParent(0xef)]);
    fill(
        &sound.path,
        "ingress",
        100_000 - rows(&sound.path, "ingress") - 1,
    );

    sound.vault.lock();
    assert_eq!(
        sound.vault.stage_revision(last.clone()).unwrap(),
        crate::StageOutcome::Staged
    );
    assert!(matches!(
        sound.vault.stage_revision(one_more.clone()),
        Err(Error::IngressFull)
    ));
    // One that already waits is still recognized.
    assert_eq!(
        sound.vault.stage_revision(last).unwrap(),
        crate::StageOutcome::Duplicate
    );
    sound.vault.unlock_with_recovery(&recovery).unwrap();
    assert!(matches!(
        sound.vault.stage_revision(one_more),
        Err(Error::IngressFull)
    ));
    assert_eq!(rows(&sound.path, "ingress"), 100_000);
}

/// At most 10,000 revisions are held for the owner's review. The next one
/// stays in the queue it arrived in until the owner has made room.
#[test]
fn the_revisions_held_for_review_are_full_at_their_bound() {
    let mut sound = Sound::new();
    let unknown = sound
        .vault
        .quarantined()
        .unwrap()
        .into_iter()
        .find(|held| !held.known_author)
        .unwrap();
    fill(
        &sound.path,
        "quarantine",
        10_000 - rows(&sound.path, "quarantine"),
    );

    // The fixture has one received revision waiting, by a device the vault
    // does not know: it would be held, and there is no room.
    assert!(matches!(
        sound.vault.process_staged(),
        Err(Error::QuarantineFull)
    ));
    assert_eq!(rows(&sound.path, "ingress"), 1);
    assert_eq!(rows(&sound.path, "quarantine"), 10_000);

    sound.vault.discard_quarantined(&unknown.revision).unwrap();
    assert_eq!(sound.vault.process_staged().unwrap().quarantined, 1);
    assert_eq!(rows(&sound.path, "ingress"), 0);
    assert_eq!(rows(&sound.path, "quarantine"), 10_000);
}
