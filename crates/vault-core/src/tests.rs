use std::fs;

use rusqlite::Connection;
use tempfile::tempdir;

use crate::{
    crypto::{
        derive_password_key, encrypt, key_wrap_aad, legacy_record_aad, legacy_revision_id,
        random_array, KdfConfig,
    },
    generate_password, preview_import, totp_code, Error, ImportFormat, Item, PasswordPolicy,
    RecoveryKey, Vault,
};

fn login(title: &str) -> Item {
    let mut item = Item::new(title);
    item.username = "alice@example.test".into();
    item.password = "correct horse battery staple".into();
    item.url = "https://example.test/private".into();
    item.notes = "private note value".into();
    item
}

#[test]
fn locked_lifecycle_and_revision_conflicts() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, recovery) = Vault::create(&path, "initial password").unwrap();
    assert!(vault.is_unlocked());
    assert_eq!(format!("{recovery:?}"), "RecoveryKey([REDACTED])");

    let item = login("Primary login");
    let item_id = item.id.clone();
    let first = vault.put(item.clone()).unwrap();
    let first_wire = vault.encrypted_revisions().unwrap().remove(0);
    let replay = vault.apply_encrypted_revision(first_wire, None).unwrap();
    assert_eq!(replay.revision, first.revision);
    assert!(matches!(vault.put(item.clone()), Err(Error::AlreadyExists)));
    assert_eq!(vault.get(&item_id).unwrap().item.password, item.password);
    assert_eq!(vault.search("ALICE").unwrap().len(), 1);

    let mut changed = item;
    changed.password = "updated password".into();
    let second = vault.update(changed.clone(), &first.revision).unwrap();
    assert_eq!(
        second.parent_revision.as_deref(),
        Some(first.revision.as_str())
    );
    assert!(matches!(
        vault.update(changed, &first.revision),
        Err(Error::Conflict { .. })
    ));

    vault.lock();
    assert!(!vault.is_unlocked());
    assert!(matches!(vault.list(), Err(Error::Locked)));
    assert!(matches!(
        vault.unlock("wrong password"),
        Err(Error::InvalidCredentials)
    ));
    vault.unlock("initial password").unwrap();
    assert_eq!(vault.get(&item_id).unwrap().revision, second.revision);
    vault.delete(&item_id, &second.revision).unwrap();
    assert!(matches!(vault.get(&item_id), Err(Error::NotFound)));
}

#[test]
fn concurrent_connections_cannot_overwrite_one_head() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut first, _) = Vault::create(&path, "password").unwrap();
    let mut item = login("shared");
    let item_id = item.id.clone();
    let revision = first.put(item.clone()).unwrap();
    let mut second = Vault::open(&path).unwrap();
    second.unlock("password").unwrap();

    item.password = "first writer".into();
    first.update(item.clone(), &revision.revision).unwrap();
    item.password = "stale writer".into();
    assert!(matches!(
        second.update(item, &revision.revision),
        Err(Error::Conflict { .. })
    ));
    assert_eq!(first.get(&item_id).unwrap().item.password, "first writer");
}

#[test]
fn sqlite_contains_no_item_plaintext_and_tampering_is_detected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let item = login("Secret service title");
    let item_id = item.id.clone();
    vault.put(item).unwrap();
    drop(vault);

    let bytes = fs::read(&path).unwrap();
    for plaintext in [
        b"Secret service title".as_slice(),
        b"alice@example.test".as_slice(),
        b"correct horse battery staple".as_slice(),
        b"https://example.test/private".as_slice(),
        b"private note value".as_slice(),
    ] {
        assert!(!bytes
            .windows(plaintext.len())
            .any(|window| window == plaintext));
    }

    let connection = Connection::open(&path).unwrap();
    assert!(connection
        .execute(
            "UPDATE revisions SET ciphertext=zeroblob(length(ciphertext))",
            []
        )
        .is_err());
    connection
        .execute("DROP TRIGGER revisions_no_update", [])
        .unwrap();
    connection
        .execute(
            "UPDATE revisions SET ciphertext=zeroblob(length(ciphertext))",
            [],
        )
        .unwrap();
    drop(connection);
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock("password").unwrap();
    // The author signature covers the ciphertext, so tampering is caught
    // before decryption is attempted.
    assert!(matches!(vault.get(&item_id), Err(Error::InvalidSignature)));
}

#[test]
fn password_change_rewraps_master_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create(&path, "old password").unwrap();
    let item = login("Kept login");
    let item_id = item.id.clone();
    vault.put(item).unwrap();
    assert!(matches!(
        vault.change_password("incorrect", "new password"),
        Err(Error::InvalidCredentials)
    ));
    vault
        .change_password("old password", "new password")
        .unwrap();
    drop(vault);

    let mut reopened = Vault::open(&path).unwrap();
    assert!(matches!(
        reopened.unlock("old password"),
        Err(Error::InvalidCredentials)
    ));
    reopened.unlock("new password").unwrap();
    assert_eq!(reopened.get(&item_id).unwrap().item.title, "Kept login");
}

#[test]
fn recovery_unlock_and_backup_restore_preserve_identity() {
    let dir = tempdir().unwrap();
    let original_path = dir.path().join("original.db");
    let backup_path = dir.path().join("vault.osmbak");
    let restored_path = dir.path().join("restored.db");
    let (mut vault, recovery) = Vault::create(&original_path, "old device password").unwrap();
    let item = login("Backed up login");
    let item_id = item.id.clone();
    vault.put(item).unwrap();
    let identity = vault.vault_id();
    vault.export_backup(&backup_path).unwrap();
    let rendered_recovery = recovery.to_string();
    drop(vault);

    let parsed = RecoveryKey::parse(&rendered_recovery).unwrap();
    let mut recovered_original = Vault::open(&original_path).unwrap();
    recovered_original.unlock_with_recovery(&parsed).unwrap();
    assert_eq!(
        recovered_original.get(&item_id).unwrap().item.title,
        "Backed up login"
    );
    drop(recovered_original);

    let restored =
        Vault::restore_backup(&backup_path, &restored_path, &parsed, "new device password")
            .unwrap();
    assert_eq!(restored.vault_id(), identity);
    assert_eq!(
        restored.get(&item_id).unwrap().item.password,
        "correct horse battery staple"
    );
    drop(restored);
    let mut reopened = Vault::open(&restored_path).unwrap();
    reopened.unlock("new device password").unwrap();
    assert_eq!(reopened.vault_id(), identity);
}

#[test]
fn backup_tampering_is_detected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.db");
    let backup_path = dir.path().join("vault.osmbak");
    let restored_path = dir.path().join("restored.db");
    let (vault, recovery) = Vault::create(&vault_path, "password").unwrap();
    vault.export_backup(&backup_path).unwrap();
    drop(vault);
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&backup_path).unwrap()).unwrap();
    let ciphertext = envelope["ciphertext"].as_str().unwrap();
    let mut replacement = ciphertext.as_bytes().to_vec();
    replacement[0] = if replacement[0] == b'A' { b'B' } else { b'A' };
    envelope["ciphertext"] = String::from_utf8(replacement).unwrap().into();
    fs::write(&backup_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(matches!(
        Vault::restore_backup(&backup_path, &restored_path, &recovery, "new password"),
        Err(Error::InvalidBackup(_))
    ));
    assert!(!restored_path.exists());
}

#[test]
fn totp_matches_rfc_6238_sha1_vectors() {
    let uri = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1";
    assert_eq!(totp_code(uri, 59).unwrap(), "94287082");
    assert_eq!(
        totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap(),
        "287082"
    );

    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let mut item = login("TOTP login");
    item.totp_secret = Some(uri.into());
    let item_id = item.id.clone();
    vault.put(item).unwrap();
    assert_eq!(vault.item_totp_code(&item_id, 59).unwrap(), "94287082");
    vault.lock();
    assert!(matches!(
        vault.item_totp_code(&item_id, 59),
        Err(Error::Locked)
    ));
}

#[test]
fn generator_honors_required_character_sets() {
    let policy = PasswordPolicy {
        length: 64,
        ..PasswordPolicy::default()
    };
    let generated = generate_password(&policy).unwrap();
    assert_eq!(generated.len(), 64);
    assert!(generated.bytes().any(|byte| byte.is_ascii_lowercase()));
    assert!(generated.bytes().any(|byte| byte.is_ascii_uppercase()));
    assert!(generated.bytes().any(|byte| byte.is_ascii_digit()));
    assert!(generated
        .bytes()
        .any(|byte| b"!@#$%^&*()-_=+[]{}:,.?".contains(&byte)));
}

#[test]
fn import_requires_preview_then_consuming_confirmation() {
    let bitwarden = br#"{
      "items": [
        {"type":1,"name":"Bitwarden login","notes":"n","favorite":true,
         "login":{"username":"bw-user","password":"bw-pass","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://bw.example"}]},
         "fields":[{"name":"account","value":"personal"}]},
        {"type":99,"name":"unsupported"}
      ]
    }"#;
    let preview = preview_import(ImportFormat::BitwardenJson, bitwarden).unwrap();
    assert_eq!(preview.valid_count(), 1);
    assert_eq!(preview.warnings().len(), 1);
    assert_eq!(preview.items()[0].password, "bw-pass");

    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let imported = vault.confirm_import(preview).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(
        vault.get(&imported[0].item_id).unwrap().item.username,
        "bw-user"
    );

    let chrome =
        b"name,url,username,password,note\nChrome,https://chrome.example,ch-user, ch-pass ,memo\n";
    let chrome_preview = preview_import(ImportFormat::ChromeCsv, chrome).unwrap();
    assert_eq!(chrome_preview.items()[0].password, " ch-pass ");
    vault.confirm_import(chrome_preview).unwrap();

    let firefox = b"url,username,password,httpRealm,formActionOrigin,guid\nhttps://firefox.example,ff-user,ff-pass,realm,https://action.example,id\n";
    let firefox_preview = preview_import(ImportFormat::FirefoxCsv, firefox).unwrap();
    assert!(firefox_preview.items()[0].notes.contains("HTTP realm"));
    vault.confirm_import(firefox_preview).unwrap();
    assert_eq!(vault.list().unwrap().len(), 3);
}

#[test]
fn oversized_import_rolls_back_every_item() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let first = login("first");
    let mut oversized = login("oversized");
    oversized.notes = "x".repeat(16 * 1024 * 1024);
    assert!(matches!(
        vault.put_items_atomic(vec![first, oversized]),
        Err(Error::InvalidItem(_))
    ));
    assert!(vault.list().unwrap().is_empty());
}

#[test]
fn revisions_are_signed_by_the_local_device_and_forgeries_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let device_id = vault.device_id().unwrap();
    vault.put(login("Signed")).unwrap();
    let wire = vault.encrypted_revisions().unwrap().remove(0);
    assert_eq!(wire.author_device_id, device_id);
    assert_eq!(wire.signature.len(), 64);

    let mut forged = wire.clone();
    forged.signature[0] ^= 1;
    assert!(matches!(
        vault.apply_encrypted_revision(forged, None),
        Err(Error::InvalidSignature)
    ));
    let mut unknown = wire.clone();
    unknown.author_device_id = [0xAA; 16];
    assert!(matches!(
        vault.apply_encrypted_revision(unknown, None),
        Err(Error::UnknownAuthor)
    ));
    let mut truncated = wire.clone();
    truncated.signature.pop();
    assert!(matches!(
        vault.apply_encrypted_revision(truncated, None),
        Err(Error::Crypto)
    ));
    // The untouched revision still replays idempotently.
    vault.apply_encrypted_revision(wire, None).unwrap();

    // The signing identity survives lock and reopen.
    vault.lock();
    drop(vault);
    let mut reopened = Vault::open(&path).unwrap();
    assert_eq!(reopened.device_id(), Some(device_id));
    reopened.unlock("password").unwrap();
    assert_eq!(reopened.list().unwrap().len(), 1);
}

#[test]
fn restored_vault_signs_as_a_new_device_and_unknown_authors_are_rejected() {
    let dir = tempdir().unwrap();
    let original_path = dir.path().join("original.db");
    let backup_path = dir.path().join("vault.osmbak");
    let restored_path = dir.path().join("restored.db");
    let (mut original, recovery) = Vault::create(&original_path, "password").unwrap();
    let item = login("Shared");
    let item_id = item.id.clone();
    let first = original.put(item).unwrap();
    original.export_backup(&backup_path).unwrap();

    let mut restored =
        Vault::restore_backup(&backup_path, &restored_path, &recovery, "new password").unwrap();
    assert_ne!(restored.device_id(), original.device_id());
    // Revisions written by the source device still verify after restore.
    let mut changed = restored.get(&item_id).unwrap().item;
    changed.password = "edited on restored device".into();
    let second = restored.update(changed, &first.revision).unwrap();
    let edit = restored
        .encrypted_revisions()
        .unwrap()
        .into_iter()
        .find(|revision| revision.revision_id() == second.revision)
        .unwrap();
    assert_eq!(Some(edit.author_device_id), restored.device_id());

    // The original vault has never authorized the restored device.
    assert!(matches!(
        original.apply_encrypted_revision(edit.clone(), Some(&first.revision)),
        Err(Error::UnknownAuthor)
    ));
    original
        .authorize_device(
            restored.device_id().unwrap(),
            restored.device_public_key().unwrap(),
        )
        .unwrap();
    original
        .apply_encrypted_revision(edit, Some(&first.revision))
        .unwrap();
    assert_eq!(
        original.get(&item_id).unwrap().item.password,
        "edited on restored device"
    );
}

#[test]
fn tampered_device_authorization_fails_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (vault, _) = Vault::create(&path, "password").unwrap();
    drop(vault);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO devices(device_id,public_key,authorization) VALUES(?,?,?)",
            rusqlite::params![
                [7_u8; 16].as_slice(),
                [9_u8; 32].as_slice(),
                [0_u8; 32].as_slice()
            ],
        )
        .unwrap();
    drop(connection);
    let mut vault = Vault::open(&path).unwrap();
    assert!(matches!(vault.unlock("password"), Err(Error::Crypto)));
    assert!(!vault.is_unlocked());
}

const LEGACY_SCHEMA: &str = r#"
CREATE TABLE vault_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    format_version INTEGER NOT NULL,
    vault_id BLOB NOT NULL, kdf_memory_kib INTEGER NOT NULL, kdf_iterations INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL, password_salt BLOB NOT NULL, password_nonce BLOB NOT NULL,
    password_wrapped_key BLOB NOT NULL, recovery_nonce BLOB NOT NULL, recovery_wrapped_key BLOB NOT NULL
) STRICT;
CREATE TABLE revisions (
    revision TEXT PRIMARY KEY, format_version INTEGER NOT NULL, vault_id BLOB NOT NULL,
    item_id TEXT NOT NULL, parent_revision TEXT, key_epoch INTEGER NOT NULL, nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL, tombstone INTEGER NOT NULL
) STRICT;
CREATE INDEX revisions_item_id ON revisions(item_id);
CREATE TRIGGER revisions_no_update BEFORE UPDATE ON revisions
BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
CREATE TRIGGER revisions_no_delete BEFORE DELETE ON revisions
BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
CREATE TABLE heads (
    item_id TEXT PRIMARY KEY, revision TEXT NOT NULL REFERENCES revisions(revision),
    tombstone INTEGER NOT NULL
) STRICT;
"#;

/// Writes a format 1 vault exactly as the pre-signing core did.
fn write_legacy_vault(path: &std::path::Path, password: &str, revisions: &[(&Item, bool)]) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch(LEGACY_SCHEMA).unwrap();
    let vault_id = random_array::<32>();
    let master = random_array::<32>();
    let salt = random_array::<16>();
    let nonce = random_array::<24>();
    let kdf = KdfConfig::default();
    let wrapped = encrypt(
        &derive_password_key(password, &salt, kdf).unwrap(),
        &nonce,
        &key_wrap_aad(&vault_id, b"password"),
        &master,
    )
    .unwrap();
    let recovery_nonce = random_array::<24>();
    let recovery_wrapped = encrypt(
        &random_array::<32>(),
        &recovery_nonce,
        &key_wrap_aad(&vault_id, b"recovery"),
        &master,
    )
    .unwrap();
    connection
        .execute(
            "INSERT INTO vault_meta VALUES (1,1,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![
                vault_id.as_slice(),
                kdf.memory_kib,
                kdf.iterations,
                kdf.parallelism,
                salt.as_slice(),
                nonce.as_slice(),
                wrapped,
                recovery_nonce.as_slice(),
                recovery_wrapped
            ],
        )
        .unwrap();
    let mut heads = std::collections::BTreeMap::<String, String>::new();
    for (item, tombstone) in revisions {
        let parent = heads.get(&item.id).cloned();
        let aad = legacy_record_aad(&vault_id, &item.id, parent.as_deref(), 1, *tombstone);
        let plaintext = if *tombstone {
            Vec::new()
        } else {
            serde_json::to_vec(item).unwrap()
        };
        let nonce = random_array::<24>();
        let ciphertext = encrypt(&master, &nonce, &aad, &plaintext).unwrap();
        let id = legacy_revision_id(&aad, &nonce, &ciphertext);
        connection
            .execute(
                "INSERT INTO revisions VALUES (?,1,?,?,?,1,?,?,?)",
                rusqlite::params![
                    id,
                    vault_id.as_slice(),
                    item.id,
                    parent,
                    nonce.as_slice(),
                    ciphertext,
                    tombstone
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO heads VALUES (?,?,?) ON CONFLICT(item_id) DO UPDATE SET revision=excluded.revision,tombstone=excluded.tombstone",
                rusqlite::params![item.id, id, tombstone],
            )
            .unwrap();
        heads.insert(item.id.clone(), id);
    }
}

#[test]
fn legacy_vault_migrates_to_signed_revisions_on_first_unlock() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let kept = login("Kept");
    let mut edited = kept.clone();
    edited.password = "second password".into();
    let removed = login("Removed");
    write_legacy_vault(
        &path,
        "password",
        &[
            (&kept, false),
            (&edited, false),
            (&removed, false),
            (&removed, true),
        ],
    );

    let mut vault = Vault::open(&path).unwrap();
    assert_eq!(vault.device_id(), None);
    assert!(matches!(vault.list(), Err(Error::Locked)));
    assert!(matches!(
        vault.unlock("wrong"),
        Err(Error::InvalidCredentials)
    ));
    vault.unlock("password").unwrap();
    let device_id = vault.device_id().unwrap();

    let current = vault.get(&kept.id).unwrap();
    assert_eq!(current.item.password, "second password");
    assert!(matches!(vault.get(&removed.id), Err(Error::NotFound)));
    let revisions = vault.encrypted_revisions().unwrap();
    assert_eq!(revisions.len(), 4);
    assert!(revisions
        .iter()
        .all(|revision| revision.format_version == 2 && revision.author_device_id == device_id));
    // History and ancestry survive: the edit still points at the original.
    let head = revisions
        .iter()
        .find(|revision| revision.revision_id() == current.revision)
        .unwrap();
    let parent = head.parent_revision.as_deref().unwrap();
    assert!(revisions
        .iter()
        .any(|revision| revision.revision_id() == parent && revision.parent_revision.is_none()));

    // Writing continues from the migrated head, and the result persists.
    let mut next = current.item;
    next.title = "Kept after migration".into();
    vault.update(next, &current.revision).unwrap();
    drop(vault);
    let mut reopened = Vault::open(&path).unwrap();
    assert_eq!(reopened.device_id(), Some(device_id));
    reopened.unlock("password").unwrap();
    assert_eq!(
        reopened.get(&kept.id).unwrap().item.title,
        "Kept after migration"
    );
}
