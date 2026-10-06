//! Reads the frozen files under `fixtures/`: a vault and a backup written
//! by each storage format's own code, at the last commit that wrote that
//! format (`examples/make_fixture.rs`). They are never made again; a test
//! here that fails means this build no longer reads what an earlier one
//! wrote.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use rusqlite::Connection;
use serde_json::Value;
use tempfile::{tempdir, TempDir};

use crate::{epoch_key_check, Error, Item, RecoveryKey, Vault};

/// Every storage format there has been, and the backup format its code
/// wrote.
const FORMATS: [(u32, u32); 8] = [
    (1, 1),
    (2, 2),
    (3, 3),
    (4, 3),
    (5, 3),
    (6, 4),
    (7, 4),
    (8, 4),
];
pub(crate) const CURRENT: u32 = 8;
const CURRENT_BACKUP: u32 = 4;

/// This crate's folder: where it was built, or `OSM_TEST_CRATE_DIR` when the
/// tests run on another machine with a copy of the crate's files, as on a
/// phone (`scripts/test-on-android.sh`).
pub(crate) fn crate_dir() -> PathBuf {
    std::env::var_os("OSM_TEST_CRATE_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
}

pub(crate) fn fixture(format: u32, name: &str) -> PathBuf {
    crate_dir()
        .join("fixtures")
        .join(format!("format-{format}"))
        .join(name)
}

/// What the fixture's writer recorded beside it.
pub(crate) struct Expected(Value);

impl Expected {
    pub(crate) fn of(format: u32) -> Self {
        Self(
            serde_json::from_slice(&std::fs::read(fixture(format, "expected.json")).unwrap())
                .unwrap(),
        )
    }

    fn text(&self, name: &str) -> &str {
        self.0[name].as_str().unwrap()
    }

    fn password(&self) -> &str {
        self.text("password")
    }

    pub(crate) fn recovery(&self) -> RecoveryKey {
        RecoveryKey::parse(self.text("recovery_key")).unwrap()
    }

    /// The items that are there, each with the revision it was at.
    fn live(&self) -> Vec<(String, Item)> {
        self.0["live"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["revision"].as_str().unwrap().to_owned(),
                    serde_json::from_value(entry["item"].clone()).unwrap(),
                )
            })
            .collect()
    }

    /// What only the current format's fixture has.
    pub(crate) fn current(&self) -> &Value {
        &self.0["current_format"]
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn texts(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|text| text.as_str().unwrap().to_owned())
        .collect()
}

/// A copy of a format's vault file that a test may change.
pub(crate) fn copy_of(format: u32) -> (TempDir, PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.sqlite3");
    std::fs::copy(fixture(format, "vault.sqlite3"), &path).unwrap();
    (dir, path)
}

fn format_in(path: &Path) -> u32 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT format_version FROM vault_meta", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// Checks that an unlocked vault holds what every fixture was written with.
fn assert_basic_content(vault: &Vault, expected: &Expected, same_revisions: bool) {
    let live = expected.live();
    for (revision, item) in &live {
        let found = vault.get(&item.id).unwrap();
        assert!(found.item == *item, "{} differs", item.id);
        assert!(!found.conflict);
        // Every format but the first keeps its signed revisions as they
        // are, so their IDs stay what they were.
        assert_eq!(found.revision == *revision, same_revisions, "{}", item.id);
    }
    assert!(matches!(vault.get("fixture-note"), Err(Error::NotFound)));
    let listed: BTreeSet<String> = vault
        .list()
        .unwrap()
        .into_iter()
        .map(|item| item.id)
        .collect();
    for (_, item) in &live {
        assert!(listed.contains(&item.id));
    }
    assert!(!listed.contains("fixture-note"));
}

#[test]
fn a_vault_written_by_every_earlier_format_opens_with_its_content_and_keeps_working() {
    for (format, _) in FORMATS {
        let expected = Expected::of(format);
        let (dir, path) = copy_of(format);
        assert_eq!(format_in(&path), format);

        let mut vault = Vault::open(&path).unwrap();
        // Formats that had one key for everything are re-rooted with the
        // password, so the recovery key alone cannot open them yet.
        if format <= 5 {
            assert!(
                matches!(
                    vault.unlock_with_recovery(&expected.recovery()),
                    Err(Error::UpgradeRequiresPassword)
                ),
                "format {format}"
            );
        }
        assert!(matches!(
            vault.unlock("not the password"),
            Err(Error::InvalidCredentials)
        ));
        vault.unlock(expected.password()).unwrap();
        assert_basic_content(&vault, &expected, format != 1);
        assert_eq!(format_in(&path), CURRENT, "format {format}");
        assert!(!vault.rows_changed(), "format {format}");

        // It stays readable: locked and unlocked again, and opened again.
        vault.lock();
        vault.unlock(expected.password()).unwrap();
        drop(vault);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(expected.password()).unwrap();
        assert_basic_content(&vault, &expected, format != 1);

        // The recovery key still belongs to it. A re-rooted vault asks for
        // it once more before it opens the vault again.
        if format <= 5 {
            assert!(!vault.recovery_enabled(), "format {format}");
            assert!(vault
                .enable_recovery(
                    &RecoveryKey::parse("OSM-RK1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                        .unwrap()
                )
                .is_err());
            vault.enable_recovery(&expected.recovery()).unwrap();
        }
        assert!(vault.recovery_enabled());
        vault.lock();
        vault.unlock_with_recovery(&expected.recovery()).unwrap();
        assert_basic_content(&vault, &expected, format != 1);

        // And it can be written to, backed up, and restored.
        let mail = vault.get("fixture-mail").unwrap();
        let mut edited = mail.item.clone();
        edited.notes = "edited by the current build".into();
        vault.update(edited.clone(), &mail.revision).unwrap();
        vault.put(Item::new("Added by the current build")).unwrap();
        let backup = dir.path().join("backup.json");
        vault.export_backup(&backup).unwrap();
        let restored = Vault::restore_backup(
            &backup,
            dir.path().join("restored.sqlite3"),
            &expected.recovery(),
            "another password",
        )
        .unwrap();
        assert!(restored.get("fixture-mail").unwrap().item == edited);
        assert!(
            restored.get("fixture-bank").unwrap().item == vault.get("fixture-bank").unwrap().item
        );
        assert!(matches!(restored.get("fixture-note"), Err(Error::NotFound)));
        assert_eq!(
            restored
                .revision_ids()
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            vault
                .revision_ids()
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            "format {format}"
        );
    }
}

#[test]
fn a_vault_of_format_6_opens_with_its_recovery_key_before_any_password() {
    let expected = Expected::of(6);
    let (_dir, path) = copy_of(6);
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock_with_recovery(&expected.recovery()).unwrap();
    assert_basic_content(&vault, &expected, true);
    assert_eq!(format_in(&path), CURRENT);
}

#[test]
fn the_current_formats_vault_holds_what_it_was_written_with_and_is_not_rewritten() {
    let expected = Expected::of(CURRENT);
    let current = expected.current();
    let (_dir, path) = copy_of(CURRENT);
    let before = std::fs::read(&path).unwrap();

    // What a locked vault can say.
    let mut vault = Vault::open(&path).unwrap();
    assert_eq!(hex(&vault.vault_id()), current["vault_id"]);
    assert_eq!(hex(&vault.device_id().unwrap()), current["device_id"]);
    assert_eq!(
        hex(&vault.device_public_key().unwrap()),
        current["device_public_key"]
    );
    assert_eq!(
        hex(&vault.recovery_check().unwrap()),
        current["recovery_check"]
    );
    assert_eq!(vault.current_epoch(), current["current_epoch"]);
    assert_eq!(vault.write_fence(), current["write_fence"]);
    let stored: BTreeSet<String> = vault.revision_ids().unwrap().into_iter().collect();
    assert_eq!(
        stored,
        texts(&current["revision_ids"]).into_iter().collect()
    );
    assert_eq!(
        vault.staged_revision_ids().unwrap(),
        [current["staged_while_locked"].as_str().unwrap()]
    );
    assert_eq!(
        vault.staged_missing_parents().unwrap(),
        texts(&current["staged_missing_parents"])
    );

    // What it holds once unlocked, by password and by recovery key.
    vault.unlock_with_recovery(&expected.recovery()).unwrap();
    vault.lock();
    vault.unlock(expected.password()).unwrap();
    assert_basic_content(&vault, &expected, true);
    let vault_id = vault.vault_id();
    let checks: Vec<Value> = vault
        .epoch_keys()
        .unwrap()
        .iter()
        .map(|(epoch, key)| serde_json::json!({ "epoch": epoch, "check": hex(&epoch_key_check(&vault_id, *epoch, key)) }))
        .collect();
    assert_eq!(Value::from(checks), current["epoch_key_checks"]);
    let authors: Vec<Value> = vault
        .authorized_devices()
        .unwrap()
        .iter()
        .map(
            |(device, key)| serde_json::json!({ "device_id": hex(device), "public_key": hex(key) }),
        )
        .collect();
    assert_eq!(Value::from(authors), current["authors"]);
    let removed: Vec<String> = vault
        .revoked_devices()
        .unwrap()
        .iter()
        .map(|device| hex(device))
        .collect();
    assert_eq!(removed, texts(&current["removed"]));
    assert!(
        vault
            .unconfirmed_recovery_key()
            .unwrap()
            .unwrap()
            .to_string()
            == expected.text("recovery_key")
    );

    // The conflict between two authors, one of them since removed.
    assert!(vault.get("fixture-shared").unwrap().conflict);
    let versions: Vec<Value> = vault
        .versions("fixture-shared")
        .unwrap()
        .into_iter()
        .map(|version| {
            serde_json::json!({
                "revision": version.revision,
                "author_device_id": hex(&version.author_device_id),
                "item": version.item,
            })
        })
        .collect();
    assert_eq!(Value::from(versions), current["conflict"]["versions"]);

    // What is held for the owner's review.
    let held = |vault: &Vault| -> Vec<Value> {
        vault
            .quarantined()
            .unwrap()
            .into_iter()
            .map(|held| {
                serde_json::json!({
                    "revision": held.revision,
                    "item_id": held.item_id,
                    "author_device_id": hex(&held.author_device_id),
                    "known_author": held.known_author,
                    "parents": held.parents,
                    "item": held.item,
                })
            })
            .collect()
    };
    assert_eq!(Value::from(held(&vault)), current["held"]);
    assert!(vault.get("fixture-epoch-two").is_ok());
    assert!(matches!(
        vault.get("fixture-from-stranger"),
        Err(Error::NotFound)
    ));
    assert!(vault.get("fixture-from-second").unwrap().item.title == "Written by the second device");

    // None of this wrote to the file: the current format needs no change.
    vault.lock();
    drop(vault);
    assert!(std::fs::read(&path).unwrap() == before);

    // The revision that arrived while locked is by a device this vault does
    // not know, so processing it holds it with the others.
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock(expected.password()).unwrap();
    let report = vault.process_staged().unwrap();
    assert_eq!(
        (
            report.applied,
            report.quarantined,
            report.rejected,
            report.pending
        ),
        (0, 1, 0, 0)
    );
    assert_eq!(held(&vault).len(), 3);
    assert!(vault.staged_revision_ids().unwrap().is_empty());
}

#[test]
fn a_backup_of_the_current_format_restores_and_an_older_one_is_refused_untouched() {
    for (format, backup_format) in FORMATS {
        let expected = Expected::of(format);
        let dir = tempdir().unwrap();
        let destination = dir.path().join("restored.sqlite3");
        let restored = Vault::restore_backup(
            fixture(format, "backup.json"),
            &destination,
            &expected.recovery(),
            "a new password",
        );
        if backup_format != CURRENT_BACKUP {
            assert!(
                matches!(restored, Err(Error::UnsupportedVersion(found)) if found == backup_format),
                "format {format}"
            );
            assert!(!destination.exists());
            continue;
        }
        let restored = restored.unwrap();
        assert_basic_content(&restored, &expected, true);
        assert_eq!(format_in(&destination), CURRENT);
        // A restored copy is a device of its own.
        let (_source_dir, source) = copy_of(format);
        assert_ne!(
            restored.device_id(),
            Vault::open(source).unwrap().device_id()
        );
        if format == CURRENT {
            let current = expected.current();
            assert_eq!(hex(&restored.vault_id()), current["vault_id"]);
            assert_eq!(restored.current_epoch(), current["current_epoch"]);
            assert_eq!(restored.epoch_keys().unwrap().len(), 2);
            assert!(restored.get("fixture-shared").unwrap().conflict);
            // What was held stays held: the removed device's edit made
            // after its removal is not taken in by restoring.
            assert_eq!(restored.quarantined().unwrap().len(), 2);
            assert!(
                restored.get("fixture-from-second").unwrap().item.title
                    == "Written by the second device"
            );
            let removed: Vec<String> = restored
                .revoked_devices()
                .unwrap()
                .iter()
                .map(|device| hex(device))
                .collect();
            assert_eq!(removed, texts(&current["removed"]));
            let stored: BTreeSet<String> = restored.revision_ids().unwrap().into_iter().collect();
            assert_eq!(
                stored,
                texts(&current["revision_ids"]).into_iter().collect()
            );
        }
    }

    // A wrong recovery key opens no backup and writes nothing.
    let dir = tempdir().unwrap();
    let destination = dir.path().join("restored.sqlite3");
    assert!(matches!(
        Vault::restore_backup(
            fixture(CURRENT, "backup.json"),
            &destination,
            &Expected::of(6).recovery(),
            "a new password",
        ),
        Err(Error::InvalidCredentials)
    ));
    assert!(!destination.exists());
}

#[test]
fn the_frozen_files_are_the_ones_that_were_committed() {
    use sha2::{Digest, Sha256};

    let folder = crate_dir().join("fixtures");
    let sums = std::fs::read_to_string(folder.join("SHA256SUMS")).unwrap();
    let mut listed = BTreeSet::new();
    for line in sums.lines() {
        let (sum, name) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(folder.join(name)).unwrap();
        // A test that opens a frozen vault where it lies can upgrade it;
        // tests work on copies.
        assert_eq!(hex(&Sha256::digest(&bytes)), sum, "{name} was changed");
        listed.insert(name.to_owned());
    }
    let frozen: BTreeSet<String> = FORMATS
        .iter()
        .flat_map(|(format, _)| {
            ["vault.sqlite3", "backup.json"].map(|name| format!("format-{format}/{name}"))
        })
        .collect();
    assert_eq!(listed, frozen);
}

/// The triggers that keep rows as they were written. Whoever can write the
/// file can drop them, so they are no part of what authenticates it.
const TRIGGERS: [&str; 9] = [
    "revisions_no_update",
    "revisions_no_delete",
    "devices_no_update",
    "epoch_keys_no_update",
    "epoch_keys_no_delete",
    "revoked_devices_no_update",
    "revoked_devices_no_delete",
    "quarantine_no_update",
    "ingress_no_update",
];

/// How a changed copy of the current format's vault is opened.
#[derive(Clone, Copy)]
enum With {
    Password,
    Recovery,
}

/// Changes a copy of the current format's vault as someone with the file
/// in hand could, then opens it and reads everything in it.
fn read_after(with: With, change: impl FnOnce(&Connection)) -> Result<(), Error> {
    let expected = Expected::of(CURRENT);
    let (_dir, path) = copy_of(CURRENT);
    let connection = Connection::open(&path).unwrap();
    for trigger in TRIGGERS {
        connection
            .execute(&format!("DROP TRIGGER {trigger}"), [])
            .unwrap();
    }
    change(&connection);
    drop(connection);

    let mut vault = Vault::open(&path)?;
    match with {
        With::Password => vault.unlock(expected.password())?,
        With::Recovery => vault.unlock_with_recovery(&expected.recovery())?,
    }
    for item in vault.list()? {
        vault.get(&item.id)?;
        vault.versions(&item.id)?;
    }
    for held in vault.quarantined()? {
        // A held revision by a device this vault knows verifies under that
        // device's key; the fixture has one.
        if held.item_id == "fixture-from-second" && !held.known_author {
            return Err(Error::InvalidSignature);
        }
    }
    vault.unconfirmed_recovery_key()?;
    vault.process_staged()?;
    Ok(())
}

/// Flips one bit of one stored value: the first row `filter` selects.
fn flip(
    table: &'static str,
    column: &'static str,
    filter: &'static str,
) -> impl FnOnce(&Connection) {
    move |connection| {
        let (row, mut value): (i64, Vec<u8>) = connection
            .query_row(
                &format!(
                    "SELECT rowid, {column} FROM {table} WHERE {filter} ORDER BY rowid LIMIT 1"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let last = value.len() - 1;
        value[last] ^= 1;
        connection
            .execute(
                &format!("UPDATE {table} SET {column}=? WHERE rowid=?"),
                rusqlite::params![value, row],
            )
            .unwrap();
    }
}

fn run(statement: &'static str) -> impl FnOnce(&Connection) {
    move |connection| {
        assert!(
            connection.execute(statement, []).unwrap() > 0,
            "{statement}"
        );
    }
}

#[test]
fn a_changed_bit_in_any_authenticated_value_of_the_vault_file_is_refused() {
    // Unchanged, everything reads, with either key.
    read_after(With::Password, |_| {}).unwrap();
    read_after(With::Recovery, |_| {}).unwrap();

    // What the password opens.
    for column in ["password_salt", "password_nonce", "password_wrapped_key"] {
        assert!(
            matches!(
                read_after(With::Password, flip("vault_meta", column, "1")),
                Err(Error::InvalidCredentials)
            ),
            "{column}"
        );
    }
    assert!(matches!(
        read_after(
            With::Password,
            run("UPDATE vault_meta SET kdf_iterations = 2")
        ),
        Err(Error::InvalidCredentials)
    ));

    // Everything else, opened with the recovery key, which needs no
    // password hashing.
    // Refused as not authentic, not for some other reason.
    let refused = |change: Box<dyn FnOnce(&Connection)>| {
        matches!(
            read_after(With::Recovery, change),
            Err(Error::Crypto | Error::InvalidSignature | Error::InvalidCredentials)
        )
    };
    let flips: [(&str, &str, &str); 22] = [
        // The vault's and this device's identity, and the keys under the
        // root key.
        ("vault_meta", "vault_id", "1"),
        ("vault_meta", "recovery_nonce", "1"),
        ("vault_meta", "recovery_wrapped_key", "1"),
        ("vault_meta", "device_id", "1"),
        ("vault_meta", "device_public_key", "1"),
        ("vault_meta", "device_key_nonce", "1"),
        ("vault_meta", "device_wrapped_signing_key", "1"),
        ("vault_meta", "recipient_nonce", "1"),
        ("vault_meta", "recipient_wrapped_secret", "1"),
        ("epoch_keys", "nonce", "epoch = 1"),
        ("epoch_keys", "wrapped_key", "epoch = 1"),
        ("epoch_keys", "wrapped_key", "epoch = 2"),
        ("unconfirmed_recovery", "nonce", "1"),
        ("unconfirmed_recovery", "wrapped_key", "1"),
        // Who may write, and who was removed.
        ("devices", "authorization", "1"),
        ("devices", "public_key", "1"),
        ("revoked_devices", "revocation", "1"),
        // A stored revision.
        ("revisions", "vault_id", "item_id = 'fixture-bank'"),
        ("revisions", "nonce", "item_id = 'fixture-bank'"),
        ("revisions", "ciphertext", "item_id = 'fixture-bank'"),
        ("revisions", "signature", "item_id = 'fixture-bank'"),
        (
            "revisions",
            "ciphertext",
            "item_id = 'fixture-shared' AND revision IN (SELECT revision FROM heads)",
        ),
    ];
    for (table, column, filter) in flips {
        assert!(
            refused(Box::new(flip(table, column, filter))),
            "{table}.{column} where {filter}"
        );
    }
    // A held revision by a known device no longer verifies as that device's.
    assert!(refused(Box::new(flip(
        "quarantine",
        "signature",
        "item_id = 'fixture-from-second'"
    ))));
    assert!(refused(Box::new(flip(
        "quarantine",
        "ciphertext",
        "item_id = 'fixture-from-stranger'"
    ))));

    // The fields of a revision's header that are not bytes.
    for statement in [
        "UPDATE revisions SET key_epoch = 2 WHERE item_id = 'fixture-bank'",
        "UPDATE revisions SET item_id = 'fixture-renamed' WHERE item_id = 'fixture-bank'",
        "UPDATE revisions SET parents = '' WHERE revision IN (SELECT revision FROM heads WHERE item_id = 'fixture-mail')",
        "UPDATE revisions SET author_device_id = (SELECT device_id FROM revoked_devices) \
         WHERE revision IN (SELECT revision FROM heads WHERE item_id = 'fixture-bank')",
        // A key filed under another epoch.
        "UPDATE epoch_keys SET epoch = 3 WHERE epoch = 2",
        // A signer added, or a removal recorded, without the root key.
        "INSERT INTO devices(device_id, public_key, authorization) \
         VALUES (zeroblob(16), zeroblob(32), zeroblob(32))",
        "INSERT INTO revoked_devices(device_id, revocation) \
         SELECT device_id, zeroblob(32) FROM vault_meta",
    ] {
        assert!(refused(Box::new(run(statement))), "{statement}");
    }
    // A deletion passed off as an edit.
    assert!(refused(Box::new(|connection: &Connection| {
        connection
            .execute_batch(
                "UPDATE revisions SET tombstone = 0 WHERE item_id = 'fixture-note';
                 UPDATE heads SET tombstone = 0 WHERE item_id = 'fixture-note';",
            )
            .unwrap();
    })));
}

/// The file proves that what it shows was written by an authorized device,
/// and since format 8 that nothing was taken out of it or changed: heads
/// taken out, or set back to an earlier version, are set again from the
/// revisions at the next unlock, and the owner is told.
#[test]
fn an_item_or_an_edit_hidden_in_the_vault_file_comes_back_and_is_said() {
    let expected = Expected::of(CURRENT);
    let opened = |change: &str| {
        let (dir, path) = copy_of(CURRENT);
        let connection = Connection::open(&path).unwrap();
        for trigger in TRIGGERS {
            connection
                .execute(&format!("DROP TRIGGER {trigger}"), [])
                .unwrap();
        }
        connection.execute_batch(change).unwrap();
        drop(connection);
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock_with_recovery(&expected.recovery()).unwrap();
        (dir, vault)
    };
    let (_dir, untouched) = opened("");
    assert!(!untouched.rows_changed());

    // An item's head taken out: the item is back.
    let (_dir, vault) = opened("DELETE FROM heads WHERE item_id = 'fixture-bank'");
    assert!(vault.rows_changed());
    assert_eq!(
        vault.get("fixture-bank").unwrap().revision,
        untouched.get("fixture-bank").unwrap().revision
    );
    // An edit hidden by setting the head back to an earlier version: the
    // edit is back.
    let (_dir, vault) = opened(
        "UPDATE heads SET revision = (SELECT r.revision FROM revisions r \
         WHERE r.item_id = heads.item_id AND r.revision <> heads.revision LIMIT 1) \
         WHERE item_id = 'fixture-mail'",
    );
    assert!(vault.rows_changed());
    assert_eq!(
        vault.get("fixture-mail").unwrap().revision,
        untouched.get("fixture-mail").unwrap().revision
    );
    // An edit marked as a deletion: the revision's row itself was changed,
    // against its ID, so the item stays missing, but the owner is told.
    let (_dir, vault) = opened(
        "UPDATE revisions SET tombstone = 1 WHERE item_id = 'fixture-bank';
         UPDATE heads SET tombstone = 1 WHERE item_id = 'fixture-bank';",
    );
    assert!(vault.rows_changed());
    assert!(matches!(vault.get("fixture-bank"), Err(Error::NotFound)));
}

#[test]
fn a_format_from_the_future_is_refused_and_the_file_left_alone() {
    // A vault file.
    let (dir, path) = copy_of(CURRENT);
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE vault_meta SET format_version = 9", [])
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        Vault::open(&path),
        Err(Error::UnsupportedVersion(9))
    ));
    assert!(std::fs::read(&path).unwrap() == before);

    // A backup.
    let expected = Expected::of(CURRENT);
    let mut envelope: Value =
        serde_json::from_slice(&std::fs::read(fixture(CURRENT, "backup.json")).unwrap()).unwrap();
    assert_eq!(envelope["format_version"], CURRENT_BACKUP);
    envelope["format_version"] = 5.into();
    let backup = dir.path().join("backup.json");
    std::fs::write(&backup, envelope.to_string()).unwrap();
    let destination = dir.path().join("restored.sqlite3");
    assert!(matches!(
        Vault::restore_backup(
            &backup,
            &destination,
            &expected.recovery(),
            "a new password"
        ),
        Err(Error::UnsupportedVersion(5))
    ));
    assert!(!destination.exists());

    // A revision, received while locked and while unlocked.
    let (_dir, path) = copy_of(CURRENT);
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock_with_recovery(&expected.recovery()).unwrap();
    let mut revision = vault.encrypted_revisions().unwrap().remove(0);
    assert_eq!(revision.format_version, 2);
    revision.format_version = 3;
    assert!(matches!(
        vault.apply_encrypted_revision(revision.clone()),
        Err(Error::UnsupportedVersion(3))
    ));
    vault.lock();
    assert!(matches!(
        vault.stage_revision(revision),
        Err(Error::UnsupportedVersion(3))
    ));
}

#[test]
fn a_changed_byte_anywhere_in_a_backup_is_refused_and_nothing_is_written() {
    let expected = Expected::of(CURRENT);
    let frozen = std::fs::read(fixture(CURRENT, "backup.json")).unwrap();
    let dir = tempdir().unwrap();
    let backup = dir.path().join("backup.json");
    let destination = dir.path().join("restored.sqlite3");
    // Every byte of the envelope's own fields, which come first, and bytes
    // spread through the encrypted payload after them.
    let payload = frozen
        .windows(13)
        .position(|window| window == b"\"ciphertext\":")
        .unwrap();
    let positions = (0..payload + 64).chain((payload + 64..frozen.len()).step_by(61));
    let mut tried = 0;
    for position in positions {
        let mut changed = frozen.clone();
        changed[position] ^= 1;
        std::fs::write(&backup, &changed).unwrap();
        let restored = Vault::restore_backup(
            &backup,
            &destination,
            &expected.recovery(),
            "a new password",
        );
        assert!(restored.is_err(), "byte {position} of the backup");
        assert!(!destination.exists(), "byte {position} of the backup");
        tried += 1;
    }
    assert!(tried > 700, "{tried}");
}

/// Makes a sound revision into one that is a step outside what is allowed.
type Change = Box<dyn Fn(&mut crate::EncryptedRevision)>;

/// The bounds a stored or received value has to keep, tried on both sides
/// of each edge.
#[test]
fn the_bounds_of_the_format_hold_at_their_edges() {
    let expected = Expected::of(CURRENT);
    let (_dir, path) = copy_of(CURRENT);
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock_with_recovery(&expected.recovery()).unwrap();

    // An item of exactly the largest size is stored and read back; one
    // byte more is refused.
    const LARGEST: usize = 16 * 1024 * 1024;
    let mut item = Item::new("As large as an item may be");
    item.id = "fixture-large".into();
    let empty = serde_json::to_vec(&item).unwrap().len();
    item.notes = "n".repeat(LARGEST - empty);
    assert_eq!(serde_json::to_vec(&item).unwrap().len(), LARGEST);
    vault.put(item.clone()).unwrap();
    assert!(vault.get("fixture-large").unwrap().item.notes.len() == LARGEST - empty);
    let mut larger = item.clone();
    larger.id = "fixture-larger".into();
    larger.notes.push('n');
    assert!(matches!(vault.put(larger), Err(Error::InvalidItem(_))));

    // A received revision is checked for its shape before it is stored,
    // locked or not. Each of these is one step outside what is allowed.
    let base = vault.encrypted_revisions().unwrap().remove(0);
    let parent = |index: u8| format!("{index:02x}").repeat(32);
    let mut most_parents = base.clone();
    most_parents.parents = (0..16).map(parent).collect();
    let mut longest_id = base.clone();
    longest_id.item_id = "i".repeat(128);
    let mut last_epoch = base.clone();
    last_epoch.key_epoch = 1 << 32;
    vault.lock();
    for allowed in [most_parents.clone(), longest_id.clone(), last_epoch.clone()] {
        assert_eq!(
            vault.stage_revision(allowed).unwrap(),
            crate::StageOutcome::Staged
        );
    }
    let refused: Vec<(&str, Change)> = vec![
        (
            "a parent too many",
            Box::new(|revision| {
                revision.parents = (0..17)
                    .map(|index| format!("{index:02x}").repeat(32))
                    .collect()
            }),
        ),
        (
            "parents out of order",
            Box::new(|revision| revision.parents = vec!["b".repeat(64), "a".repeat(64)]),
        ),
        (
            "a parent twice",
            Box::new(|revision| revision.parents = vec!["a".repeat(64), "a".repeat(64)]),
        ),
        (
            "a parent that is no revision ID",
            Box::new(|revision| revision.parents = vec!["A".repeat(64)]),
        ),
        (
            "a parent of the wrong length",
            Box::new(|revision| revision.parents = vec!["a".repeat(63)]),
        ),
        (
            "an item ID too long",
            Box::new(|revision| revision.item_id = "i".repeat(129)),
        ),
        ("no item ID", Box::new(|revision| revision.item_id.clear())),
        ("epoch zero", Box::new(|revision| revision.key_epoch = 0)),
        (
            "an epoch past the last",
            Box::new(|revision| revision.key_epoch = (1 << 32) + 1),
        ),
        (
            "a ciphertext shorter than its tag",
            Box::new(|revision| revision.ciphertext.truncate(15)),
        ),
        (
            "a ciphertext too large",
            Box::new(|revision| revision.ciphertext = vec![0; LARGEST + 17]),
        ),
        (
            "a signature too short",
            Box::new(|revision| revision.signature.truncate(63)),
        ),
        (
            "a signature too long",
            Box::new(|revision| revision.signature.push(0)),
        ),
        (
            "another vault's revision",
            Box::new(|revision| revision.vault_id[0] ^= 1),
        ),
    ];
    for (what, change) in &refused {
        let mut revision = base.clone();
        change(&mut revision);
        assert!(
            matches!(vault.stage_revision(revision), Err(Error::Crypto)),
            "{what}"
        );
    }
    vault.unlock_with_recovery(&expected.recovery()).unwrap();
    for (what, change) in &refused {
        let mut revision = base.clone();
        change(&mut revision);
        assert!(
            matches!(vault.apply_encrypted_revision(revision), Err(Error::Crypto)),
            "{what}"
        );
    }

    // A vault holds at most 1,024 epoch keys.
    while vault.epoch_keys().unwrap().len() < 1024 {
        vault.generate_epoch_key().unwrap();
    }
    assert!(matches!(vault.generate_epoch_key(), Err(Error::Crypto)));
}

/// The stored cost of the password hashing is checked before any memory is
/// taken for it.
#[test]
fn a_password_hashing_cost_outside_its_bounds_is_refused_before_it_is_paid() {
    let expected = Expected::of(CURRENT);
    let unlock_with = |column: &str, value: u64| {
        let (_dir, path) = copy_of(CURRENT);
        Connection::open(&path)
            .unwrap()
            .execute(&format!("UPDATE vault_meta SET {column} = {value}"), [])
            .unwrap();
        Vault::open(&path).unwrap().unlock(expected.password())
    };
    for (column, value) in [
        ("kdf_memory_kib", 8 * 1024 - 1),
        ("kdf_memory_kib", 256 * 1024 + 1),
        // Four gigabytes: refused, not attempted.
        ("kdf_memory_kib", 4 * 1024 * 1024),
        ("kdf_iterations", 0),
        ("kdf_iterations", 11),
        ("kdf_parallelism", 0),
        ("kdf_parallelism", 17),
    ] {
        assert!(
            matches!(unlock_with(column, value), Err(Error::Crypto)),
            "{column} = {value}"
        );
    }
    // Inside the bounds the hashing runs, and the changed cost gives
    // another key, which opens nothing.
    for (column, value) in [
        ("kdf_memory_kib", 8 * 1024),
        ("kdf_memory_kib", 256 * 1024),
        ("kdf_iterations", 1),
        ("kdf_iterations", 10),
        ("kdf_parallelism", 16),
    ] {
        assert!(
            matches!(unlock_with(column, value), Err(Error::InvalidCredentials)),
            "{column} = {value}"
        );
    }
}

/// Takes rows out of a closed vault's file, as anyone who can write the
/// file can, past the triggers that stop the app itself. Returns how many
/// rows the statement changed.
pub(crate) fn take_out(path: &Path, statement: &str) -> usize {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TRIGGER IF EXISTS revisions_no_delete;
             DROP TRIGGER IF EXISTS epoch_keys_no_delete;
             DROP TRIGGER IF EXISTS revoked_devices_no_delete;",
        )
        .unwrap();
    connection.execute(statement, []).unwrap()
}

#[test]
fn a_format_7_vault_is_sealed_at_its_first_unlock_and_cannot_be_set_back() {
    let expected = Expected::of(7);
    let (_dir, path) = copy_of(7);
    let mut vault = Vault::open(&path).unwrap();
    assert_eq!(format_in(&path), 7, "sealing needs the key");
    vault.unlock(expected.password()).unwrap();
    assert_eq!(format_in(&path), 8);
    assert!(!vault.rows_changed());
    drop(vault);
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock(expected.password()).unwrap();
    assert!(!vault.rows_changed());
    drop(vault);
    // Set back to format 7 by hand, so that an unlock would seal it again
    // over whatever had been taken out: the signing key is under format
    // 8's label now, so the vault does not unlock, and stays as it is.
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE vault_meta SET format_version = 7", [])
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut vault = Vault::open(&path).unwrap();
    assert!(matches!(
        vault.unlock(expected.password()),
        Err(Error::Crypto)
    ));
    drop(vault);
    assert!(std::fs::read(&path).unwrap() == before);
}

#[test]
fn a_row_taken_out_of_a_sealed_vault_never_goes_unnoticed() {
    let expected = Expected::of(CURRENT);
    for (what, statement) in [
        (
            "an earlier version",
            "DELETE FROM revisions WHERE revision IN \
             (SELECT revision FROM revisions WHERE revision NOT IN (SELECT revision FROM heads) LIMIT 1)",
        ),
        ("a removed device's mark", "DELETE FROM revoked_devices"),
        (
            "an earlier epoch's key",
            "DELETE FROM epoch_keys WHERE epoch < (SELECT current_epoch FROM vault_meta)",
        ),
        (
            "another author",
            "DELETE FROM devices WHERE device_id <> (SELECT device_id FROM vault_meta)",
        ),
        ("the seal itself", "UPDATE vault_meta SET row_seal = NULL"),
        (
            "the seal, changed",
            "UPDATE vault_meta SET row_seal = zeroblob(72)",
        ),
    ] {
        let (_dir, path) = copy_of(CURRENT);
        assert!(take_out(&path, statement) > 0, "nothing to take: {what}");
        // It still opens, and says so.
        let mut vault = Vault::open(&path).unwrap();
        vault.unlock(expected.password()).unwrap();
        assert!(vault.rows_changed(), "{what} taken out went unnoticed");
    }
    // Untouched, it says nothing.
    let (_dir, path) = copy_of(CURRENT);
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock(expected.password()).unwrap();
    assert!(!vault.rows_changed());
}
