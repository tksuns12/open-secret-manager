//! Writes a vault, a backup of it, and what a reader should find in them,
//! with the vault code of the commit this file is built in. It was run once
//! per storage format to make the fixtures under `fixtures/`, and is run
//! again only when the format changes, for the new format's folder. It
//! refuses to write over a fixture: a frozen file is never made again.
//!
//!   cargo run -p osm-vault-core --example make_fixture -- <folder> <commit>
//!
//! The fixtures of formats 1 to 6 were made by `basic` alone, built in each
//! of those commits; what `extras` uses did not exist then.
use std::path::{Path, PathBuf};

use osm_vault_core::{epoch_key_check, Error, Item, ItemKind, RecoveryKey, Vault};

/// Not a secret: these open only the fixture files.
const PASSWORD: &str = "fixture password, not a secret";

fn item(id: &str, title: &str) -> Item {
    let mut item = Item::new(title);
    item.id = id.to_owned();
    item
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What every format's fixture holds.
fn basic(vault: &mut Vault) {
    // A login edited twice: three revisions in a chain.
    let mut mail = item("fixture-mail", "Mail");
    mail.username = "owner@example.test".into();
    mail.password = "first password".into();
    mail.url = "https://mail.example.test/login".into();
    let first = vault.put(mail.clone()).unwrap();
    mail.password = "second password".into();
    let second = vault.update(mail.clone(), &first.revision).unwrap();
    mail.password = "third password, with ünïcödé".into();
    mail.notes = "edited twice".into();
    vault.update(mail.clone(), &second.revision).unwrap();

    // A note that was deleted: a revision and its tombstone.
    let mut note = item("fixture-note", "A note that was deleted");
    note.kind = ItemKind::SecureNote;
    note.notes = "gone".into();
    let noted = vault.put(note).unwrap();
    vault.delete("fixture-note", &noted.revision).unwrap();

    // A login with every field in use.
    let mut bank = item("fixture-bank", "Bank");
    bank.username = "account 42".into();
    bank.password = "p@ss \"quoted\" \\ and 🔑".into();
    bank.url = "https://bank.example.test:8443/".into();
    bank.notes = "line one\nline two".into();
    bank.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    bank.custom_fields.insert("PIN".into(), "0000".into());
    bank.custom_fields
        .insert("Branch".into(), "Main Street".into());
    bank.tags = vec!["money".into(), "important".into()];
    bank.favorite = true;
    vault.put(bank).unwrap();
}

/// Takes the revision `id` from one copy of the vault to another.
fn carry(from: &Vault, to: &mut Vault, id: &str) -> Result<(), Error> {
    let revision = from.revisions_by_id(&[id.to_owned()]).unwrap().remove(0);
    to.apply_encrypted_revision(revision).map(|_| ())
}

/// What only the current format can hold: a second author and a conflict
/// with it, a removed device, revisions held for review, a second key
/// epoch, a raised write fence, and a recovery key not yet confirmed.
fn extras(vault: &mut Vault, recovery: &RecoveryKey, folder: &Path) -> serde_json::Value {
    let shared = vault.put(item("fixture-shared", "Shared")).unwrap();

    // Two more copies of the vault, each a device of its own.
    let scratch = folder.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    vault.export_backup(scratch.join("backup.json")).unwrap();
    let restore = |name: &str| {
        Vault::restore_backup(
            scratch.join("backup.json"),
            scratch.join(name),
            recovery,
            PASSWORD,
        )
        .unwrap()
    };
    let mut second = restore("second.sqlite3");
    let mut stranger = restore("stranger.sqlite3");
    let second_id = second.device_id().unwrap();

    // The second device is an author here. It and this device edit the same
    // item at the same time: a conflict of two authors.
    vault
        .authorize_device(second_id, second.device_public_key().unwrap())
        .unwrap();
    let mut theirs = item("fixture-shared", "Shared, as the second device has it");
    theirs.notes = "edited on the second device".into();
    let theirs = second.update(theirs, &shared.revision).unwrap();
    let mut ours = item("fixture-shared", "Shared, as this device has it");
    ours.notes = "edited on this device".into();
    vault.update(ours, &shared.revision).unwrap();
    carry(&second, vault, &theirs.revision).unwrap();

    // An item the second device wrote, accepted before that device was
    // removed, and an edit of it made afterwards, which is held.
    let written = second
        .put(item("fixture-from-second", "Written by the second device"))
        .unwrap();
    carry(&second, vault, &written.revision).unwrap();
    vault.revoke_device(second_id).unwrap();
    let late = second
        .update(
            item("fixture-from-second", "Edited after the removal"),
            &written.revision,
        )
        .unwrap();
    assert!(matches!(
        carry(&second, vault, &late.revision),
        Err(Error::Quarantined)
    ));

    // An item from a device that was never an author here, which is held.
    let unknown = stranger
        .put(item(
            "fixture-from-stranger",
            "Written by an unknown device",
        ))
        .unwrap();
    assert!(matches!(
        carry(&stranger, vault, &unknown.revision),
        Err(Error::Quarantined)
    ));

    // A second key epoch, with an item written under it.
    let (epoch, _) = vault.generate_epoch_key().unwrap();
    vault.activate_epoch(epoch).unwrap();
    vault.raise_write_fence(epoch).unwrap();
    vault
        .put(item("fixture-epoch-two", "Written under the second epoch"))
        .unwrap();

    vault.keep_recovery_key_until_confirmed(recovery).unwrap();

    // A revision that arrives while the vault is locked, after the backup
    // is written: the unknown device's edit of its own item.
    let follow_up = stranger
        .update(
            item("fixture-from-stranger", "Edited by the unknown device"),
            &unknown.revision,
        )
        .unwrap();
    let staged = stranger
        .revisions_by_id(std::slice::from_ref(&follow_up.revision))
        .unwrap()
        .remove(0);

    let vault_id = vault.vault_id();
    let versions: Vec<serde_json::Value> = vault
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
    let held: Vec<serde_json::Value> = vault
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
        .collect();
    let found = serde_json::json!({
        "vault_id": hex(&vault_id),
        "device_id": hex(&vault.device_id().unwrap()),
        "device_public_key": hex(&vault.device_public_key().unwrap()),
        "recovery_check": hex(&vault.recovery_check().unwrap()),
        "current_epoch": vault.current_epoch(),
        "write_fence": vault.write_fence(),
        "epoch_key_checks": vault.epoch_keys().unwrap().iter()
            .map(|(epoch, key)| serde_json::json!({ "epoch": epoch, "check": hex(&epoch_key_check(&vault_id, *epoch, key)) }))
            .collect::<Vec<_>>(),
        "authors": vault.authorized_devices().unwrap().iter()
            .map(|(device, key)| serde_json::json!({ "device_id": hex(device), "public_key": hex(key) }))
            .collect::<Vec<_>>(),
        "removed": vault.revoked_devices().unwrap().iter().map(|device| hex(device)).collect::<Vec<_>>(),
        "conflict": { "item_id": "fixture-shared", "versions": versions },
        "held": held,
        "revision_ids": vault.revision_ids().unwrap(),
        "staged_while_locked": staged.revision_id(),
        "staged_missing_parents": [unknown.revision],
        "recovery_key_kept": true,
    });

    vault.export_backup(folder.join("backup.json")).unwrap();
    vault.lock();
    vault.stage_revision(staged).unwrap();
    drop((second, stranger));
    std::fs::remove_dir_all(&scratch).unwrap();
    found
}

fn main() {
    let mut args = std::env::args().skip(1);
    let folder = PathBuf::from(args.next().expect("folder"));
    let commit = args.next().expect("commit");
    std::fs::create_dir_all(&folder).unwrap();
    // `create` refuses a file that is already there.
    let (mut vault, recovery) = Vault::create(folder.join("vault.sqlite3"), PASSWORD).unwrap();

    basic(&mut vault);
    let live: Vec<serde_json::Value> = ["fixture-bank", "fixture-mail"]
        .iter()
        .map(|id| {
            let found = vault.get(id).unwrap();
            serde_json::json!({ "revision": found.revision, "item": found.item })
        })
        .collect();
    let extras = extras(&mut vault, &recovery, &folder);
    let expected = serde_json::json!({
        "about": "What a reader should find in vault.sqlite3 and backup.json beside this file. The password and the recovery key open only these fixtures.",
        "made_by_commit": commit,
        "password": PASSWORD,
        "recovery_key": recovery.to_string(),
        "live": live,
        "deleted": ["fixture-note"],
        "current_format": extras,
    });
    std::fs::write(
        folder.join("expected.json"),
        serde_json::to_string_pretty(&expected).unwrap() + "\n",
    )
    .unwrap();
}
