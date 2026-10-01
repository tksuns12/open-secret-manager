use std::fs;

use rusqlite::Connection;
use tempfile::tempdir;

use base64ct::Encoding;

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
    let replay = vault.apply_encrypted_revision(first_wire).unwrap();
    assert_eq!(replay.revision, first.revision);
    assert!(matches!(vault.put(item.clone()), Err(Error::AlreadyExists)));
    assert_eq!(vault.get(&item_id).unwrap().item.password, item.password);
    assert_eq!(vault.search("ALICE").unwrap().len(), 1);

    let mut changed = item;
    changed.password = "updated password".into();
    let second = vault.update(changed.clone(), &first.revision).unwrap();
    assert_eq!(second.parents, vec![first.revision.clone()]);
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
        vault.apply_encrypted_revision(forged),
        Err(Error::InvalidSignature)
    ));
    // The author is bound into the AEAD, so relabeling it cannot even
    // produce a revision that qualifies for quarantine.
    let mut unknown = wire.clone();
    unknown.author_device_id = [0xAA; 16];
    assert!(matches!(
        vault.apply_encrypted_revision(unknown),
        Err(Error::Crypto)
    ));
    assert!(vault.quarantined().unwrap().is_empty());
    let mut truncated = wire.clone();
    truncated.signature.pop();
    assert!(matches!(
        vault.apply_encrypted_revision(truncated),
        Err(Error::Crypto)
    ));
    // The untouched revision still replays idempotently.
    vault.apply_encrypted_revision(wire).unwrap();

    // The signing identity survives lock and reopen.
    vault.lock();
    drop(vault);
    let mut reopened = Vault::open(&path).unwrap();
    assert_eq!(reopened.device_id(), Some(device_id));
    reopened.unlock("password").unwrap();
    assert_eq!(reopened.list().unwrap().len(), 1);
}

#[test]
fn restored_vault_signs_as_a_new_device_and_unknown_authors_are_quarantined() {
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

    // The original vault has never authorized the restored device, so the
    // edit is held, not merged.
    assert!(matches!(
        original.apply_encrypted_revision(edit.clone()),
        Err(Error::Quarantined)
    ));
    assert_eq!(original.quarantined().unwrap().len(), 1);
    original
        .authorize_device(
            restored.device_id().unwrap(),
            restored.device_public_key().unwrap(),
        )
        .unwrap();
    original.apply_encrypted_revision(edit).unwrap();
    // Once its author is authorized the exact signed revision applies and
    // the held copy is released.
    assert!(original.quarantined().unwrap().is_empty());
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
    let parent = head.parents[0].as_str();
    assert!(revisions
        .iter()
        .any(|revision| revision.revision_id() == parent && revision.parents.is_empty()));

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

/// Two copies of one vault that each trust the other's device, sharing one
/// item at `base` revision. Returns (original, copy, item, base revision).
fn two_copies(dir: &std::path::Path) -> (Vault, Vault, Item, String) {
    let (mut first, second, item, base, _) = untrusted_copy(dir);
    first
        .authorize_device(
            second.device_id().unwrap(),
            second.device_public_key().unwrap(),
        )
        .unwrap();
    (first, second, item, base)
}

/// Like `two_copies`, but the original has not authorized the copy's device,
/// so the copy's revisions are unknown-author revisions to it. Also returns
/// the vault's recovery key.
fn untrusted_copy(dir: &std::path::Path) -> (Vault, Vault, Item, String, RecoveryKey) {
    let (mut first, recovery) = Vault::create(dir.join("a.db"), "password").unwrap();
    let item = login("Shared");
    let base = first.put(item.clone()).unwrap().revision;
    first.export_backup(dir.join("a.osmbak")).unwrap();
    let second = Vault::restore_backup(
        dir.join("a.osmbak"),
        dir.join("b.db"),
        &recovery,
        "password",
    )
    .unwrap();
    (first, second, item, base, recovery)
}

fn edit(vault: &mut Vault, item: &Item, base: &str, password: &str) -> crate::EncryptedRevision {
    let mut changed = item.clone();
    changed.password = password.into();
    let info = vault.update(changed, base).unwrap();
    wire(vault, &info.revision)
}

fn wire(vault: &Vault, revision: &str) -> crate::EncryptedRevision {
    vault
        .encrypted_revisions()
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.revision_id() == revision)
        .unwrap()
}

fn head_set(vault: &Vault, item_id: &str) -> Vec<String> {
    vault
        .versions(item_id)
        .unwrap()
        .into_iter()
        .map(|version| version.revision)
        .collect()
}

#[test]
fn concurrent_edits_keep_both_heads_in_either_order_until_resolved() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let from_a = edit(&mut a, &item, &base, "from A");
    let from_b = edit(&mut b, &item, &base, "from B");
    // Each copy receives the other's edit after its own: both orders.
    a.apply_encrypted_revision(from_b.clone()).unwrap();
    b.apply_encrypted_revision(from_a.clone()).unwrap();

    for vault in [&a, &b] {
        let shown = vault.get(&item.id).unwrap();
        assert!(shown.conflict);
        assert!(vault.list().unwrap()[0].conflict);
        let versions = vault.versions(&item.id).unwrap();
        assert_eq!(versions.len(), 2);
        let mut passwords: Vec<_> = versions
            .iter()
            .map(|version| version.item.as_ref().unwrap().password.clone())
            .collect();
        passwords.sort();
        assert_eq!(passwords, ["from A", "from B"]);
    }
    assert_eq!(head_set(&a, &item.id), head_set(&b, &item.id));
    // Both copies show the same version while conflicted.
    assert_eq!(
        a.get(&item.id).unwrap().revision,
        b.get(&item.id).unwrap().revision
    );

    let shown = a.get(&item.id).unwrap();
    assert!(matches!(
        a.update(shown.item.clone(), &shown.revision),
        Err(Error::Unresolved)
    ));
    assert!(matches!(
        a.delete(&item.id, &shown.revision),
        Err(Error::Unresolved)
    ));

    // The conflict survives a restart.
    drop(a);
    let mut a = Vault::open(dir.path().join("a.db")).unwrap();
    a.unlock("password").unwrap();
    assert!(a.get(&item.id).unwrap().conflict);

    let heads = head_set(&a, &item.id);
    let mut kept = item.clone();
    kept.password = "merged".into();
    let resolution = a.resolve(&item.id, Some(kept), &heads).unwrap();
    assert_eq!(resolution.parents, heads);
    let resolved = a.get(&item.id).unwrap();
    assert!(!resolved.conflict);
    assert_eq!(resolved.item.password, "merged");

    b.apply_encrypted_revision(wire(&a, &resolution.revision))
        .unwrap();
    assert_eq!(
        head_set(&b, &item.id),
        std::slice::from_ref(&resolution.revision)
    );
    // Replaying an already superseded revision is a no-op, not a new head.
    b.apply_encrypted_revision(from_a).unwrap();
    assert_eq!(head_set(&b, &item.id), [resolution.revision]);
    // Ordinary editing resumes after resolution.
    let current = b.get(&item.id).unwrap();
    b.update(current.item, &current.revision).unwrap();
}

#[test]
fn resolution_supersedes_only_the_named_heads() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let from_a = edit(&mut a, &item, &base, "from A");
    let from_b = edit(&mut b, &item, &base, "from B");
    a.apply_encrypted_revision(from_b).unwrap();
    let reviewed = head_set(&a, &item.id);
    assert_eq!(reviewed.len(), 2);

    // A third concurrent edit arrives after the owner reviewed the conflict.
    let mut late_item = item.clone();
    late_item.password = "late".into();
    let late = b
        .seal_for_test(&late_item, vec![base.clone()], false)
        .unwrap();
    let late_id = late.revision_id();
    a.apply_encrypted_revision(late).unwrap();
    assert_eq!(head_set(&a, &item.id).len(), 3);

    let resolution = a.resolve(&item.id, Some(item.clone()), &reviewed).unwrap();
    let mut remaining = vec![resolution.revision.clone(), late_id];
    remaining.sort();
    assert_eq!(head_set(&a, &item.id), remaining);
    assert!(a.get(&item.id).unwrap().conflict);

    // A resolution naming a head that is no longer current is stale.
    assert!(matches!(
        a.resolve(&item.id, None, &[from_a.revision_id()]),
        Err(Error::Conflict { .. })
    ));
    assert!(matches!(
        a.resolve(&item.id, None, &[]),
        Err(Error::InvalidItem(_))
    ));
}

#[test]
fn delete_edit_race_keeps_the_edit_visible_until_resolved() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let deleted = a.delete(&item.id, &base).unwrap();
    let deletion = wire(&a, &deleted.revision);
    let edited = edit(&mut b, &item, &base, "edited while deleted");
    a.apply_encrypted_revision(edited).unwrap();
    b.apply_encrypted_revision(deletion).unwrap();

    for vault in [&a, &b] {
        let shown = vault.get(&item.id).unwrap();
        assert!(shown.conflict);
        assert_eq!(shown.item.password, "edited while deleted");
        assert_eq!(vault.list().unwrap().len(), 1);
        assert_eq!(
            vault
                .versions(&item.id)
                .unwrap()
                .iter()
                .filter(|version| version.item.is_none())
                .count(),
            1
        );
    }

    let heads = head_set(&a, &item.id);
    let resolution = a.resolve(&item.id, None, &heads).unwrap();
    assert!(matches!(a.get(&item.id), Err(Error::NotFound)));
    assert!(a.list().unwrap().is_empty());
    b.apply_encrypted_revision(wire(&a, &resolution.revision))
        .unwrap();
    assert!(matches!(b.get(&item.id), Err(Error::NotFound)));
}

#[test]
fn invalid_ancestry_is_rejected_and_missing_parents_can_be_retried() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let other = login("Other");
    let other_head = a.put(other.clone()).unwrap().revision;

    let cross = a.seal_for_test(&item, vec![other_head], false).unwrap();
    assert!(matches!(
        a.apply_encrypted_revision(cross),
        Err(Error::InvalidParent)
    ));
    let unknown = a.seal_for_test(&item, vec!["a".repeat(64)], false).unwrap();
    assert!(matches!(
        a.apply_encrypted_revision(unknown),
        Err(Error::MissingParent)
    ));
    for parents in [
        vec!["b".repeat(64), "a".repeat(64)],
        vec!["a".repeat(64), "a".repeat(64)],
        vec!["A".repeat(64)],
    ] {
        let malformed = a.seal_for_test(&item, parents, false).unwrap();
        assert!(matches!(
            a.apply_encrypted_revision(malformed),
            Err(Error::Crypto)
        ));
    }
    assert_eq!(head_set(&a, &item.id), std::slice::from_ref(&base));

    // A child that arrives before its parent is refused without side
    // effects and accepted once the parent has been applied.
    let first = edit(&mut a, &item, &base, "first");
    let second = edit(&mut a, &item, &first.revision_id(), "second");
    assert!(matches!(
        b.apply_encrypted_revision(second.clone()),
        Err(Error::MissingParent)
    ));
    assert_eq!(head_set(&b, &item.id), [base]);
    b.apply_encrypted_revision(first).unwrap();
    b.apply_encrypted_revision(second.clone()).unwrap();
    assert_eq!(head_set(&b, &item.id), [second.revision_id()]);
    assert_eq!(b.get(&item.id).unwrap().item.password, "second");
}

#[test]
fn single_head_vault_migrates_without_changing_signed_revisions() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v2.db");
    let item = login("Before migration");
    let mut changed = item.clone();
    changed.password = "changed".into();
    Vault::create_format5(&path, "password", &[item.clone(), changed]).unwrap();
    // Revision IDs and ciphertext are readable without unlocking.
    let before = {
        let vault = Vault::open(&path).unwrap();
        vault
            .revisions_by_id(&vault.revision_ids().unwrap())
            .unwrap()
    };
    let second = before[1].revision_id();

    // Rebuild the format 2 layout: single parent column, one head per item.
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER epoch_keys_no_update; DROP TRIGGER epoch_keys_no_delete;
             DROP TABLE epoch_keys;
             DROP TRIGGER quarantine_no_update; DROP TABLE quarantine;
             DROP TRIGGER ingress_no_update; DROP TABLE ingress;
             DROP TRIGGER revisions_no_update; DROP TRIGGER revisions_no_delete;
             DROP INDEX revisions_item_id; DROP INDEX heads_item_id;
             ALTER TABLE heads RENAME TO multi_heads;
             ALTER TABLE revisions RENAME TO multi_revisions;
             CREATE TABLE revisions (
                 revision TEXT PRIMARY KEY, format_version INTEGER NOT NULL, vault_id BLOB NOT NULL,
                 item_id TEXT NOT NULL, parent_revision TEXT, key_epoch INTEGER NOT NULL,
                 author_device_id BLOB NOT NULL REFERENCES devices(device_id), nonce BLOB NOT NULL,
                 ciphertext BLOB NOT NULL, tombstone INTEGER NOT NULL, signature BLOB NOT NULL
             ) STRICT;
             CREATE INDEX revisions_item_id ON revisions(item_id);
             CREATE TRIGGER revisions_no_update BEFORE UPDATE ON revisions
             BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
             CREATE TRIGGER revisions_no_delete BEFORE DELETE ON revisions
             BEGIN SELECT RAISE(ABORT, 'revisions are immutable'); END;
             INSERT INTO revisions SELECT revision,format_version,vault_id,item_id,NULLIF(parents,''),
                 key_epoch,author_device_id,nonce,ciphertext,tombstone,signature
                 FROM multi_revisions ORDER BY rowid;
             CREATE TABLE heads (
                 item_id TEXT PRIMARY KEY, revision TEXT NOT NULL REFERENCES revisions(revision),
                 tombstone INTEGER NOT NULL
             ) STRICT;
             INSERT INTO heads SELECT item_id,revision,tombstone FROM multi_heads;
             DROP TABLE multi_heads; DROP TABLE multi_revisions;
             UPDATE vault_meta SET format_version=2;",
        )
        .unwrap();
    drop(connection);

    let mut migrated = Vault::open(&path).unwrap();
    assert!(migrated.device_id().is_some());
    migrated.unlock("password").unwrap();
    // Signed bytes, and therefore revision IDs, are unchanged.
    assert_eq!(migrated.encrypted_revisions().unwrap(), before);
    let current = migrated.get(&item.id).unwrap();
    assert_eq!(current.revision, second);
    assert!(!current.conflict);
    migrated.update(current.item, &current.revision).unwrap();
    // The chained 2 -> 3 -> 4 -> 5 -> 7 migration created the quarantine.
    assert!(migrated.quarantined().unwrap().is_empty());
    drop(migrated);
    let version: u32 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT format_version FROM vault_meta", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 7);
}

#[test]
fn unknown_author_revisions_are_held_not_merged() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base, _) = untrusted_copy(dir.path());
    let foreign = edit(&mut b, &item, &base, "from unknown device");
    let foreign_id = foreign.revision_id();

    assert!(matches!(
        a.apply_encrypted_revision(foreign.clone()),
        Err(Error::Quarantined)
    ));
    // Nothing is materialized: heads, content, and history are untouched.
    assert_eq!(head_set(&a, &item.id), std::slice::from_ref(&base));
    assert_eq!(a.get(&item.id).unwrap().item.password, item.password);
    assert!(a
        .encrypted_revisions()
        .unwrap()
        .iter()
        .all(|revision| revision.revision_id() != foreign_id));

    let held = a.quarantined().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].revision, foreign_id);
    assert_eq!(Some(held[0].author_device_id), b.device_id());
    assert_eq!(held[0].parents, std::slice::from_ref(&base));
    assert_eq!(
        held[0].item.as_ref().unwrap().password,
        "from unknown device"
    );

    // Replays are deduplicated and the hold survives a restart.
    assert!(matches!(
        a.apply_encrypted_revision(foreign),
        Err(Error::Quarantined)
    ));
    drop(a);
    let mut a = Vault::open(dir.path().join("a.db")).unwrap();
    a.unlock("password").unwrap();
    assert_eq!(a.quarantined().unwrap().len(), 1);

    // Ciphertext the vault key did not produce is rejected, not held.
    let head = b.get(&item.id).unwrap().revision;
    let mut forged = edit(&mut b, &item, &head, "x");
    forged.ciphertext[0] ^= 1;
    assert!(matches!(
        a.apply_encrypted_revision(forged),
        Err(Error::Crypto)
    ));
    assert_eq!(a.quarantined().unwrap().len(), 1);
}

#[test]
fn accepting_reauthors_content_and_never_overrides_local_edits() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base, _) = untrusted_copy(dir.path());
    let foreign = edit(&mut b, &item, &base, "from unknown device");
    let foreign_id = foreign.revision_id();
    assert!(matches!(
        a.apply_encrypted_revision(foreign),
        Err(Error::Quarantined)
    ));
    // A local edit made while the foreign one is held.
    edit(&mut a, &item, &base, "local edit");

    let accepted = a.accept_quarantined(&foreign_id).unwrap();
    assert_eq!(accepted.parents, [base]);
    assert_ne!(accepted.revision, foreign_id);
    let reauthored = wire(&a, &accepted.revision);
    assert_eq!(Some(reauthored.author_device_id), a.device_id());
    assert!(a.quarantined().unwrap().is_empty());
    assert!(a
        .encrypted_revisions()
        .unwrap()
        .iter()
        .all(|revision| Some(revision.author_device_id) != b.device_id()));

    // Accepted content joins as a concurrent head; the owner still decides.
    assert!(a.get(&item.id).unwrap().conflict);
    let mut passwords: Vec<_> = a
        .versions(&item.id)
        .unwrap()
        .into_iter()
        .map(|version| version.item.unwrap().password.clone())
        .collect();
    passwords.sort();
    assert_eq!(passwords, ["from unknown device", "local edit"]);
    assert!(matches!(
        a.accept_quarantined(&foreign_id),
        Err(Error::NotFound)
    ));
}

#[test]
fn discard_and_missing_parents_leave_the_vault_unchanged() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base, _) = untrusted_copy(dir.path());
    let first = edit(&mut b, &item, &base, "first");
    let second = edit(&mut b, &item, &first.revision_id(), "second");

    // A held child whose parent never arrived cannot be accepted yet.
    assert!(matches!(
        a.apply_encrypted_revision(second.clone()),
        Err(Error::Quarantined)
    ));
    assert!(matches!(
        a.accept_quarantined(&second.revision_id()),
        Err(Error::MissingParent)
    ));
    assert_eq!(a.quarantined().unwrap().len(), 1);
    assert_eq!(head_set(&a, &item.id), [base]);

    a.discard_quarantined(&second.revision_id()).unwrap();
    assert!(a.quarantined().unwrap().is_empty());
    assert!(matches!(
        a.discard_quarantined(&second.revision_id()),
        Err(Error::NotFound)
    ));
    // A discarded revision received again is held again, not dropped.
    assert!(matches!(
        a.apply_encrypted_revision(second),
        Err(Error::Quarantined)
    ));
    assert_eq!(a.quarantined().unwrap().len(), 1);
}

#[test]
fn held_revisions_survive_backup_and_restore() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base, recovery) = untrusted_copy(dir.path());
    let foreign = edit(&mut b, &item, &base, "held through backup");
    let foreign_id = foreign.revision_id();
    assert!(matches!(
        a.apply_encrypted_revision(foreign),
        Err(Error::Quarantined)
    ));
    let backup_path = dir.path().join("with-quarantine.osmbak");
    a.export_backup(&backup_path).unwrap();

    let restored = Vault::restore_backup(
        &backup_path,
        dir.path().join("restored.db"),
        &recovery,
        "password",
    )
    .unwrap();
    // The hold is carried over, still unmerged, and still reviewable.
    let held = restored.quarantined().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].revision, foreign_id);
    assert_eq!(head_set(&restored, &item.id), [base]);
}

#[test]
fn locked_vault_stages_revisions_and_applies_them_on_unlock() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let incoming = edit(&mut b, &item, &base, "sent while A was locked");
    let incoming_id = incoming.revision_id();
    drop(a);

    // Opened without a password: no key is available.
    let mut locked = Vault::open(dir.path().join("a.db")).unwrap();
    assert!(!locked.is_unlocked());
    assert_eq!(
        locked.stage_revision(incoming.clone()).unwrap(),
        crate::StageOutcome::Staged
    );
    assert_eq!(
        locked.stage_revision(incoming.clone()).unwrap(),
        crate::StageOutcome::Duplicate
    );
    assert_eq!(
        locked.staged_revision_ids().unwrap(),
        std::slice::from_ref(&incoming_id)
    );
    assert!(matches!(locked.get(&item.id), Err(Error::Locked)));
    assert!(matches!(locked.process_staged(), Err(Error::Locked)));
    // Staged, not accepted: the head set is unchanged.
    assert!(!locked.revision_ids().unwrap().contains(&incoming_id));
    drop(locked);

    // The staged revision survives a restart and is applied on unlock.
    a = Vault::open(dir.path().join("a.db")).unwrap();
    assert_eq!(a.staged_revision_ids().unwrap().len(), 1);
    a.unlock("password").unwrap();
    let report = a.process_staged().unwrap();
    assert_eq!((report.applied, report.pending, report.rejected), (1, 0, 0));
    assert_eq!(
        a.get(&item.id).unwrap().item.password,
        "sent while A was locked"
    );
    assert!(a.staged_revision_ids().unwrap().is_empty());
    // Once accepted it is a duplicate, not staged again.
    assert_eq!(
        a.stage_revision(incoming).unwrap(),
        crate::StageOutcome::Duplicate
    );
}

#[test]
fn a_staged_child_waits_for_its_parent_across_restarts() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let first = edit(&mut b, &item, &base, "first");
    let second = edit(&mut b, &item, &first.revision_id(), "second");

    a.stage_revision(second.clone()).unwrap();
    assert_eq!(a.staged_missing_parents().unwrap(), [first.revision_id()]);
    let report = a.process_staged().unwrap();
    assert_eq!((report.applied, report.pending), (0, 1));
    drop(a);

    let mut a = Vault::open(dir.path().join("a.db")).unwrap();
    a.stage_revision(first).unwrap();
    assert!(a.staged_missing_parents().unwrap().is_empty());
    a.unlock("password").unwrap();
    // Arrival order was child first; processing repeats until both apply.
    let report = a.process_staged().unwrap();
    assert_eq!((report.applied, report.pending), (2, 0));
    assert_eq!(a.get(&item.id).unwrap().item.password, "second");
}

#[test]
fn staged_forgeries_are_discarded_and_valid_revisions_kept() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let valid = edit(&mut b, &item, &base, "valid");
    let other = login("Other");
    let mut forged = b.seal_for_test(&other, Vec::new(), false).unwrap();
    forged.signature[0] ^= 1;

    // Staging checks shape only, so a bad signature is not noticed yet...
    a.lock();
    a.stage_revision(forged.clone()).unwrap();
    a.stage_revision(valid).unwrap();
    // ...but a malformed envelope is refused outright.
    let mut malformed = forged.clone();
    malformed.signature.pop();
    assert!(matches!(a.stage_revision(malformed), Err(Error::Crypto)));
    assert_eq!(a.staged_revision_ids().unwrap().len(), 2);

    a.unlock("password").unwrap();
    let report = a.process_staged().unwrap();
    assert_eq!((report.applied, report.rejected, report.pending), (1, 1, 0));
    assert!(matches!(
        report.first_rejection,
        Some(Error::InvalidSignature)
    ));
    assert!(a.staged_revision_ids().unwrap().is_empty());
    assert!(matches!(a.get(&other.id), Err(Error::NotFound)));
    assert_eq!(a.get(&item.id).unwrap().item.password, "valid");
}

#[test]
fn staged_revisions_from_unknown_devices_go_to_quarantine() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base, _) = untrusted_copy(dir.path());
    let foreign = edit(&mut b, &item, &base, "from unknown device");
    a.lock();
    a.stage_revision(foreign).unwrap();
    a.unlock("password").unwrap();
    let report = a.process_staged().unwrap();
    assert_eq!(
        (report.quarantined, report.applied, report.pending),
        (1, 0, 0)
    );
    assert_eq!(a.quarantined().unwrap().len(), 1);
    assert!(a.staged_revision_ids().unwrap().is_empty());
}

#[test]
fn a_format_4_vault_gains_the_ingress_queue_when_opened_locked() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v4.db");
    let item = login("Before upgrade");
    Vault::create_format5(&path, "password", std::slice::from_ref(&item)).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER ingress_no_update; DROP TABLE ingress;
             UPDATE vault_meta SET format_version=4;",
        )
        .unwrap();
    drop(connection);
    let version = |path: &std::path::Path| -> u32 {
        Connection::open(path)
            .unwrap()
            .query_row("SELECT format_version FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap()
    };

    // Opening without a key adds the queue, so staging works while locked.
    let mut vault = Vault::open(&path).unwrap();
    assert_eq!(version(&path), 5);
    let stored = vault
        .revisions_by_id(&vault.revision_ids().unwrap())
        .unwrap()
        .remove(0);
    assert_eq!(
        vault.stage_revision(stored).unwrap(),
        crate::StageOutcome::Duplicate
    );
    // Re-rooting waits for a password unlock.
    vault.unlock("password").unwrap();
    assert_eq!(version(&path), 7);
    assert_eq!(vault.get(&item.id).unwrap().item.title, "Before upgrade");
}

#[test]
fn epochs_rotate_without_losing_history() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let item = login("Rotated");
    let first = vault.put(item.clone()).unwrap();
    assert_eq!(vault.current_epoch(), 1);

    // A generated key is held but not used until activated.
    let (epoch, _) = vault.generate_epoch_key().unwrap();
    assert_eq!(epoch, 2);
    let mut changed = item.clone();
    changed.password = "still epoch 1".into();
    let second = vault.update(changed.clone(), &first.revision).unwrap();
    assert_eq!(wire(&vault, &second.revision).key_epoch, 1);

    vault.activate_epoch(2).unwrap();
    changed.password = "epoch 2".into();
    let third = vault.update(changed, &second.revision).unwrap();
    assert_eq!(wire(&vault, &third.revision).key_epoch, 2);
    assert!(matches!(
        vault.activate_epoch(1),
        Err(Error::Conflict { .. })
    ));
    assert!(matches!(
        vault.activate_epoch(3),
        Err(Error::MissingEpochKey)
    ));

    // Both epochs persist and stay readable.
    vault.lock();
    drop(vault);
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock("password").unwrap();
    assert_eq!(vault.current_epoch(), 2);
    assert_eq!(vault.get(&item.id).unwrap().item.password, "epoch 2");
    assert_eq!(vault.encrypted_revisions().unwrap().len(), 3);
}

#[test]
fn revisions_under_an_epoch_this_device_lacks_wait_for_its_key() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base) = two_copies(dir.path());
    let (epoch, key) = a.generate_epoch_key().unwrap();
    a.activate_epoch(epoch).unwrap();
    let newer = edit(&mut a, &item, &base, "written under epoch 2");

    b.stage_revision(newer).unwrap();
    let report = b.process_staged().unwrap();
    assert_eq!((report.applied, report.pending, report.rejected), (0, 1, 0));

    // A different key for a known epoch is refused; the real one unblocks it.
    b.install_epoch_key(epoch, &key).unwrap();
    assert!(matches!(
        b.install_epoch_key(epoch, &[7; 32]),
        Err(Error::Crypto)
    ));
    let report = b.process_staged().unwrap();
    assert_eq!((report.applied, report.pending), (1, 0));
    assert_eq!(
        b.get(&item.id).unwrap().item.password,
        "written under epoch 2"
    );
}

/// Every key a joined device holds: its own root and its epoch keys.
fn keys_held(vault: &Vault) -> Vec<[u8; 32]> {
    let mut keys = vec![*vault.root_key_for_tests()];
    keys.extend(vault.epoch_keys().unwrap().into_iter().map(|(_, key)| *key));
    keys
}

#[test]
fn a_removed_device_cannot_read_later_epochs_from_a_leaked_file_or_backup() {
    let dir = tempdir().unwrap();
    let (mut a, recovery) = Vault::create(dir.path().join("a.db"), "password").unwrap();
    a.put(login("Before removal")).unwrap();
    let joined = Vault::join(
        dir.path().join("b.db"),
        "joined password",
        crate::PendingDevice::generate(),
        a.enrollment_material().unwrap(),
    )
    .unwrap();
    // The joined device got the epoch keys, not A's root key.
    assert!(!keys_held(&joined).contains(&*a.root_key_for_tests()));

    // A rotates without the joined device, then writes and backs up.
    let (epoch, _) = a.generate_epoch_key().unwrap();
    a.activate_epoch(epoch).unwrap();
    a.put(login("After removal")).unwrap();
    let backup = dir.path().join("after.osmbak");
    a.export_backup(&backup).unwrap();
    drop(a);

    // A's file wraps the new epoch key under A's root: nothing the joined
    // device holds opens it.
    let connection = Connection::open(dir.path().join("a.db")).unwrap();
    let (vault_id, nonce, wrapped): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT (SELECT vault_id FROM vault_meta), nonce, wrapped_key FROM epoch_keys WHERE epoch=2",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let aad = crate::crypto::epoch_key_aad(&vault_id.try_into().unwrap(), 2);
    for key in keys_held(&joined) {
        assert!(
            crate::crypto::decrypt(&key, &nonce.clone().try_into().unwrap(), &aad, &wrapped)
                .is_err()
        );
    }
    // Neither do they open the newer backup; only the recovery key does.
    let envelope: serde_json::Value = serde_json::from_slice(&fs::read(&backup).unwrap()).unwrap();
    let wrapped_root =
        base64ct::Base64UrlUnpadded::decode_vec(envelope["recovery_wrapped_key"].as_str().unwrap())
            .unwrap();
    let root_nonce: [u8; 24] =
        base64ct::Base64UrlUnpadded::decode_vec(envelope["recovery_nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let wrap_aad = key_wrap_aad(&joined.vault_id(), b"recovery");
    for key in keys_held(&joined) {
        assert!(crate::crypto::decrypt(&key, &root_nonce, &wrap_aad, &wrapped_root).is_err());
    }
    let restored = Vault::restore_backup(
        &backup,
        dir.path().join("restored.db"),
        &recovery,
        "restored password",
    )
    .unwrap();
    assert_eq!(restored.list().unwrap().len(), 2);
    assert_eq!(restored.current_epoch(), 2);
}

#[test]
fn a_joined_device_enables_recovery_only_with_the_right_key() {
    let dir = tempdir().unwrap();
    let (a, recovery) = Vault::create(dir.path().join("a.db"), "password").unwrap();
    let path = dir.path().join("b.db");
    let mut joined = Vault::join(
        &path,
        "joined password",
        crate::PendingDevice::generate(),
        a.enrollment_material().unwrap(),
    )
    .unwrap();
    assert!(!joined.recovery_enabled());
    assert!(matches!(
        joined.export_backup(dir.path().join("b.osmbak")),
        Err(Error::RecoveryNotEnabled)
    ));
    joined.lock();
    assert!(matches!(
        joined.unlock_with_recovery(&recovery),
        Err(Error::RecoveryNotEnabled)
    ));

    joined.unlock("joined password").unwrap();
    let (_, other_vaults_key) = Vault::create(dir.path().join("other.db"), "x").unwrap();
    assert!(matches!(
        joined.enable_recovery(&other_vaults_key),
        Err(Error::InvalidRecoveryKey)
    ));
    joined.enable_recovery(&recovery).unwrap();
    drop(joined);
    let mut reopened = Vault::open(&path).unwrap();
    reopened.unlock_with_recovery(&recovery).unwrap();
    reopened.export_backup(dir.path().join("b.osmbak")).unwrap();
}

#[test]
fn a_shared_key_vault_is_re_rooted_at_its_next_password_unlock() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v5.db");
    let item = login("Kept through re-rooting");
    let recovery = Vault::create_format5(&path, "password", std::slice::from_ref(&item)).unwrap();
    let before = {
        let vault = Vault::open(&path).unwrap();
        vault
            .revisions_by_id(&vault.revision_ids().unwrap())
            .unwrap()
    };

    // Re-rooting needs the password, so recovery cannot do it.
    let mut vault = Vault::open(&path).unwrap();
    assert!(matches!(
        vault.unlock_with_recovery(&recovery),
        Err(Error::UpgradeRequiresPassword)
    ));
    assert!(!vault.is_unlocked());

    vault.unlock("password").unwrap();
    assert_eq!(
        vault.get(&item.id).unwrap().item.title,
        "Kept through re-rooting"
    );
    assert_eq!(vault.encrypted_revisions().unwrap(), before);
    // The old shared key is now epoch 1, distinct from the new root.
    let epochs = vault.epoch_keys().unwrap();
    assert_eq!(epochs.len(), 1);
    assert_ne!(*epochs[0].1, *vault.root_key_for_tests());
    // Recovery is re-enabled by entering the key, checked against the old
    // wrapper.
    assert!(!vault.recovery_enabled());
    let (_, wrong) = Vault::create(dir.path().join("other.db"), "x").unwrap();
    assert!(matches!(
        vault.enable_recovery(&wrong),
        Err(Error::InvalidRecoveryKey)
    ));
    vault.enable_recovery(&recovery).unwrap();
    vault.put(login("After re-rooting")).unwrap();
    drop(vault);

    let mut reopened = Vault::open(&path).unwrap();
    reopened.unlock_with_recovery(&recovery).unwrap();
    assert_eq!(reopened.list().unwrap().len(), 2);
    reopened.lock();
    reopened.unlock("password").unwrap();
}

/// A device joined from `from`'s current enrollment material.
fn join(dir: &std::path::Path, name: &str, from: &Vault) -> Vault {
    Vault::join(
        dir.join(name),
        "password",
        crate::PendingDevice::generate(),
        from.enrollment_material().unwrap(),
    )
    .unwrap()
}

/// Applies every revision `from` has accepted, parents first. Returns how
/// many were quarantined.
fn deliver(to: &mut Vault, from: &Vault) -> usize {
    let mut held = 0;
    for revision in from.encrypted_revisions().unwrap() {
        match to.apply_encrypted_revision(revision) {
            Ok(_) => {}
            Err(Error::Quarantined) => held += 1,
            Err(error) => panic!("{error}"),
        }
    }
    held
}

fn authorize(vault: &mut Vault, other: &Vault) {
    vault
        .authorize_device(
            other.device_id().unwrap(),
            other.device_public_key().unwrap(),
        )
        .unwrap();
}

#[test]
fn a_removed_devices_later_revisions_are_held_unless_a_member_builds_on_them() {
    let dir = tempdir().unwrap();
    let (mut a, _) = Vault::create(dir.path().join("a.db"), "password").unwrap();
    let item = login("Shared");
    let base = a.put(item.clone()).unwrap().revision;
    let mut r = join(dir.path(), "r.db", &a);
    authorize(&mut a, &r);
    let mut b = join(dir.path(), "b.db", &a);
    authorize(&mut a, &b);
    authorize(&mut r, &b);
    deliver(&mut r, &a);
    deliver(&mut b, &a);

    // Before removal R's edit is accepted everywhere.
    let r1 = edit(&mut r, &item, &base, "r1");
    a.apply_encrypted_revision(r1.clone()).unwrap();
    b.apply_encrypted_revision(r1.clone()).unwrap();

    // A learns of the removal first. B accepts R's next edit before it does.
    let r_id = r.device_id().unwrap();
    assert!(a.revoke_device(r_id).unwrap());
    assert!(!a.revoke_device(r_id).unwrap());
    let r2 = edit(&mut r, &item, &r1.revision_id(), "r2");
    assert!(matches!(
        a.apply_encrypted_revision(r2.clone()),
        Err(Error::Quarantined)
    ));
    b.apply_encrypted_revision(r2.clone()).unwrap();
    b.revoke_device(r_id).unwrap();
    // A still reads what R wrote before removal.
    assert_eq!(a.get(&item.id).unwrap().item.password, "r1");

    // B builds on r2, which vouches for it: A accepts both, as-is.
    let b1 = edit(&mut b, &item, &r2.revision_id(), "b1");
    a.apply_encrypted_revision(b1.clone()).unwrap();
    assert_eq!(head_set(&a, &item.id), vec![b1.revision_id()]);
    assert!(a.quarantined().unwrap().is_empty());
    assert!(a.encrypted_revisions().unwrap().contains(&r2));

    // Nobody builds on R's later edit, so it stays held, also after a
    // restart.
    let r3 = edit(&mut r, &item, &r2.revision_id(), "r3");
    drop(a);
    let mut a = Vault::open(dir.path().join("a.db")).unwrap();
    a.unlock("password").unwrap();
    assert_eq!(a.revoked_devices().unwrap(), vec![r_id]);
    assert!(matches!(
        a.apply_encrypted_revision(r3),
        Err(Error::Quarantined)
    ));
    assert_eq!(a.quarantined().unwrap().len(), 1);
    assert_eq!(a.get(&item.id).unwrap().item.password, "b1");

    assert!(matches!(
        a.revoke_device(a.device_id().unwrap()),
        Err(Error::InvalidDevice(_))
    ));
    assert!(matches!(
        a.revoke_device([9; 16]),
        Err(Error::InvalidDevice(_))
    ));
}

#[test]
fn endorsing_a_removed_devices_heads_keeps_them_for_devices_that_join_later() {
    let dir = tempdir().unwrap();
    let (mut a, _) = Vault::create(dir.path().join("a.db"), "password").unwrap();
    let item = login("Shared");
    let base = a.put(item.clone()).unwrap().revision;
    let mut r = join(dir.path(), "r.db", &a);
    authorize(&mut a, &r);
    deliver(&mut r, &a);
    let r1 = edit(&mut r, &item, &base, "r1");
    a.apply_encrypted_revision(r1.clone()).unwrap();
    let deleted = a.put(login("Deleted by R")).unwrap();
    deliver(&mut r, &a);
    let tombstone = r.delete(&deleted.item_id, &deleted.revision).unwrap();
    a.apply_encrypted_revision(wire(&r, &tombstone.revision))
        .unwrap();

    a.revoke_device(r.device_id().unwrap()).unwrap();
    let endorsed = a.endorse_heads_of(r.device_id().unwrap()).unwrap();
    assert_eq!(endorsed.len(), 2);
    assert_eq!(endorsed[0].parents, vec![r1.revision_id()]);
    // Endorsed heads are no longer R's, so a second call does nothing.
    assert!(a
        .endorse_heads_of(r.device_id().unwrap())
        .unwrap()
        .is_empty());
    assert_eq!(a.get(&item.id).unwrap().item.password, "r1");
    assert!(matches!(a.get(&deleted.item_id), Err(Error::NotFound)));

    // A device joining now treats R as removed, yet ends up with A's view:
    // each held revision of R's is released by A's endorsement.
    let mut joined = join(dir.path(), "j.db", &a);
    assert_eq!(
        joined.revoked_devices().unwrap(),
        vec![r.device_id().unwrap()]
    );
    assert_eq!(deliver(&mut joined, &a), 2);
    assert!(joined.quarantined().unwrap().is_empty());
    for id in [&item.id, &deleted.item_id] {
        assert_eq!(head_set(&joined, id), head_set(&a, id));
    }
    assert_eq!(joined.get(&item.id).unwrap().item.password, "r1");
}

#[test]
fn held_revisions_apply_once_their_author_is_authorized() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base, _) = untrusted_copy(dir.path());
    let foreign = edit(&mut b, &item, &base, "from B");
    assert!(matches!(
        a.apply_encrypted_revision(foreign.clone()),
        Err(Error::Quarantined)
    ));
    assert_eq!(a.retry_quarantined().unwrap(), 0);
    authorize(&mut a, &b);
    assert_eq!(a.retry_quarantined().unwrap(), 1);
    assert!(a.quarantined().unwrap().is_empty());
    assert_eq!(head_set(&a, &item.id), vec![foreign.revision_id()]);
}

#[test]
fn a_write_fence_stops_writes_until_the_committed_epoch_is_active() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("a.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let item = login("Fenced");
    let first = vault.put(item.clone()).unwrap();
    vault.lock();
    drop(vault);

    // Committed membership moved on while this device was locked.
    let mut vault = Vault::open(&path).unwrap();
    vault.raise_write_fence(2).unwrap();
    vault.unlock("password").unwrap();
    assert_eq!(vault.write_fence(), 2);
    assert!(matches!(
        vault.put(login("Blocked")),
        Err(Error::EpochPending)
    ));
    assert!(matches!(
        vault.update(item.clone(), &first.revision),
        Err(Error::EpochPending)
    ));
    // Reading is unaffected.
    assert_eq!(vault.list().unwrap().len(), 1);

    let (epoch, _) = vault.generate_epoch_key().unwrap();
    vault.activate_epoch(epoch).unwrap();
    vault.put(login("Allowed")).unwrap();
    // The fence never moves back.
    vault.raise_write_fence(1).unwrap();
    assert_eq!(vault.write_fence(), 2);
    assert!(matches!(vault.raise_write_fence(0), Err(Error::Crypto)));
}

#[test]
fn a_format_6_vault_gains_membership_fields_when_opened_locked() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v6.db");
    let (mut vault, _) = Vault::create(&path, "password").unwrap();
    let item = login("Before upgrade");
    vault.put(item.clone()).unwrap();
    drop(vault);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE revoked_devices;
             ALTER TABLE vault_meta DROP COLUMN recipient_nonce;
             ALTER TABLE vault_meta DROP COLUMN recipient_wrapped_secret;
             ALTER TABLE vault_meta DROP COLUMN write_fence;
             UPDATE vault_meta SET format_version=6;",
        )
        .unwrap();
    drop(connection);
    let version = |path: &std::path::Path| -> u32 {
        Connection::open(path)
            .unwrap()
            .query_row("SELECT format_version FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap()
    };

    // Without the key: the fence works at once.
    let mut vault = Vault::open(&path).unwrap();
    assert_eq!(version(&path), 7);
    vault.raise_write_fence(1).unwrap();
    // The recipient secret needs the root key, so it appears at unlock and
    // stays the same afterwards.
    vault.unlock("password").unwrap();
    let secret = vault.recipient_secret().unwrap();
    assert_eq!(vault.get(&item.id).unwrap().item.title, "Before upgrade");
    vault.lock();
    assert!(matches!(vault.recipient_secret(), Err(Error::Locked)));
    vault.unlock("password").unwrap();
    assert_eq!(*vault.recipient_secret().unwrap(), *secret);
    drop(vault);
    let mut reopened = Vault::open(&path).unwrap();
    reopened.unlock("password").unwrap();
    assert_eq!(*reopened.recipient_secret().unwrap(), *secret);
}

#[test]
fn joining_keeps_the_pending_recipient_secret_and_backups_keep_revocations() {
    let dir = tempdir().unwrap();
    let (mut a, recovery) = Vault::create(dir.path().join("a.db"), "password").unwrap();
    let item = login("Shared");
    let base = a.put(item.clone()).unwrap().revision;
    let pending = crate::PendingDevice::generate();
    let secret = pending.recipient_secret();
    let mut r = Vault::join(
        dir.path().join("r.db"),
        "password",
        pending,
        a.enrollment_material().unwrap(),
    )
    .unwrap();
    assert_eq!(*r.recipient_secret().unwrap(), *secret);
    assert_ne!(*a.recipient_secret().unwrap(), *secret);
    authorize(&mut a, &r);
    deliver(&mut r, &a);
    let r1 = edit(&mut r, &item, &base, "r1");
    a.apply_encrypted_revision(r1.clone()).unwrap();
    a.revoke_device(r.device_id().unwrap()).unwrap();

    let backup = dir.path().join("a.osmbak");
    a.export_backup(&backup).unwrap();
    let mut restored = Vault::restore_backup(
        &backup,
        dir.path().join("restored.db"),
        &recovery,
        "password",
    )
    .unwrap();
    // R's accepted edit is restored as accepted; its later ones are held.
    assert_eq!(
        restored.revoked_devices().unwrap(),
        vec![r.device_id().unwrap()]
    );
    assert_eq!(restored.get(&item.id).unwrap().item.password, "r1");
    let r2 = edit(&mut r, &item, &r1.revision_id(), "r2");
    assert!(matches!(
        restored.apply_encrypted_revision(r2),
        Err(Error::Quarantined)
    ));
    // A restored vault is a new device with its own recipient secret.
    assert_ne!(
        *restored.recipient_secret().unwrap(),
        *a.recipient_secret().unwrap()
    );
}

#[test]
fn a_fork_starts_a_new_trust_domain_from_the_current_versions() {
    let dir = tempdir().unwrap();
    let (mut a, mut b, item, base, old_recovery) = untrusted_copy(dir.path());

    // The source has history, a deletion, a held revision, and a conflict.
    let kept = login("Kept");
    let first = a.put(kept.clone()).unwrap().revision;
    edit(&mut a, &kept, &first, "second version");
    let gone = login("Gone");
    let created = a.put(gone.clone()).unwrap().revision;
    a.delete(&gone.id, &created).unwrap();
    let unknown = b.put(login("From an unknown device")).unwrap().revision;
    assert!(matches!(
        a.apply_encrypted_revision(wire(&b, &unknown)),
        Err(Error::Quarantined)
    ));
    assert_eq!(a.quarantined().unwrap().len(), 1);
    a.authorize_device(b.device_id().unwrap(), b.device_public_key().unwrap())
        .unwrap();
    edit(&mut a, &item, &base, "from A");
    let from_b = edit(&mut b, &item, &base, "from B");
    a.apply_encrypted_revision(from_b).unwrap();
    assert!(a.get(&item.id).unwrap().conflict);
    let before = a.encrypted_revisions().unwrap();

    let path = dir.path().join("fork.db");
    let (mut fork, recovery, report) = a.fork(&path, "new password").unwrap();
    assert_eq!(
        report,
        crate::ForkReport {
            items: 2,
            conflicts: 1,
            held_left_behind: 1,
            staged_left_behind: 0,
        }
    );

    // Nothing of the old domain's identity or keys is reused.
    assert_ne!(fork.vault_id(), a.vault_id());
    assert_ne!(fork.device_id(), a.device_id());
    assert_ne!(fork.device_public_key(), a.device_public_key());
    assert_eq!(fork.current_epoch(), 1);
    assert_eq!(fork.epoch_keys().unwrap().len(), 1);
    assert!(keys_held(&a)
        .iter()
        .all(|key| !keys_held(&fork).contains(key)));
    assert_eq!(
        fork.authorized_devices().unwrap(),
        vec![(fork.device_id().unwrap(), fork.device_public_key().unwrap())]
    );

    // The current versions are there; history, the deletion, and the held
    // revision are not. The conflict is still a conflict.
    assert_eq!(fork.list().unwrap().len(), 2);
    assert_eq!(fork.get(&kept.id).unwrap().item.password, "second version");
    assert!(matches!(fork.get(&gone.id), Err(Error::NotFound)));
    assert!(fork.quarantined().unwrap().is_empty());
    assert!(fork.get(&item.id).unwrap().conflict);
    let mut versions: Vec<String> = fork
        .versions(&item.id)
        .unwrap()
        .into_iter()
        .map(|version| version.item.unwrap().password.clone())
        .collect();
    versions.sort();
    assert_eq!(versions, ["from A", "from B"]);
    let revisions = fork.encrypted_revisions().unwrap();
    assert_eq!(revisions.len(), 3);
    for revision in &revisions {
        assert!(revision.parents.is_empty());
        assert_eq!(revision.vault_id, fork.vault_id());
        assert_eq!(Some(revision.author_device_id), fork.device_id());
    }
    // The owner resolves it in the new vault as in any other.
    let heads = head_set(&fork, &item.id);
    let keep = fork.versions(&item.id).unwrap().remove(0).item;
    fork.resolve(&item.id, keep, &heads).unwrap();
    assert!(!fork.get(&item.id).unwrap().conflict);

    // The two domains accept nothing from each other, verified or staged.
    assert!(a.apply_encrypted_revision(revisions[0].clone()).is_err());
    assert!(a.stage_revision(revisions[0].clone()).is_err());
    assert!(fork.apply_encrypted_revision(before[0].clone()).is_err());
    assert!(fork.stage_revision(before[0].clone()).is_err());

    // The source is untouched, and an existing file is never overwritten.
    assert_eq!(a.encrypted_revisions().unwrap(), before);
    assert_eq!(a.quarantined().unwrap().len(), 1);
    assert!(a.fork(&path, "new password").is_err());

    // The new vault has its own password and its own recovery key.
    drop(fork);
    let mut reopened = Vault::open(&path).unwrap();
    assert!(reopened.unlock("password").is_err());
    assert!(reopened.unlock_with_recovery(&old_recovery).is_err());
    reopened.unlock_with_recovery(&recovery).unwrap();
    reopened.lock();
    reopened.unlock("new password").unwrap();
    assert_eq!(reopened.list().unwrap().len(), 2);

    // A locked vault cannot be forked.
    a.lock();
    assert!(matches!(
        a.fork(dir.path().join("other.db"), "p"),
        Err(Error::Locked)
    ));
}
