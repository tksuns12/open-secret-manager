//! Secrets stay out of what is printed: the debug form of every value that
//! holds one, and the errors the core returns.

use tempfile::tempdir;

use crate::{preview_import, Error, ImportFormat, Item, PendingDevice, RecoveryKey, Vault};

const PASSWORD: &str = "hygiene test password";
/// A value that must never be printed.
const MARKER: &str = "hunter2-do-not-print";

/// Every form a key's bytes could be printed in.
fn forms(bytes: &[u8]) -> Vec<String> {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let listed = format!("{bytes:?}");
    let decimals = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    vec![hex, listed, decimals]
}

fn assert_hidden(printed: &str, secrets: &[String]) {
    for secret in secrets {
        assert!(
            !printed.contains(secret.as_str()),
            "printed a secret: {printed}"
        );
    }
}

#[test]
fn values_that_hold_secrets_print_none_of_them() {
    let dir = tempdir().unwrap();
    let (mut vault, recovery) = Vault::create(dir.path().join("vault.sqlite3"), PASSWORD).unwrap();
    let mut item = Item::new(format!("Title {MARKER}"));
    item.username = MARKER.into();
    item.password = MARKER.into();
    item.notes = MARKER.into();
    item.url = format!("https://example.test/{MARKER}");
    item.totp_secret = Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into());
    item.custom_fields.insert("PIN".into(), MARKER.into());
    let written = vault.put(item.clone()).unwrap();

    let mut secrets = vec![
        MARKER.to_owned(),
        "JBSWY3DPEHPK3PXP".to_owned(),
        PASSWORD.to_owned(),
        recovery.to_string(),
    ];
    secrets.extend(forms(&vault.root_key_for_tests()[..]));
    for (_, key) in vault.epoch_keys().unwrap() {
        secrets.extend(forms(&key[..]));
    }
    secrets.extend(forms(&vault.recipient_secret().unwrap()[..]));

    let read = vault.get(&written.item_id).unwrap();
    let summary = vault.list().unwrap().remove(0);
    let versions = vault.versions(&written.item_id).unwrap();
    let material = vault.enrollment_material().unwrap();
    let pending = PendingDevice::generate();
    secrets.extend(forms(&pending.recipient_secret()[..]));
    let revisions = vault.encrypted_revisions().unwrap();
    for printed in [
        format!("{vault:?}"),
        format!("{item:?}"),
        format!("{read:?}"),
        format!("{summary:?}"),
        format!("{versions:?}"),
        format!("{material:?}"),
        format!("{pending:?}"),
        format!("{recovery:?}"),
        format!("{revisions:?}"),
        format!("{:?}", RecoveryKey::parse(&recovery.to_string()).unwrap()),
        format!("{:?}", vault.unlock_session()),
    ] {
        assert_hidden(&printed, &secrets);
    }

    // Held revisions print as the others do.
    vault.lock();
    assert_hidden(&format!("{vault:?}"), &secrets);
}

#[test]
fn errors_repeat_no_secret() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.sqlite3");
    let (mut vault, _) = Vault::create(&path, PASSWORD).unwrap();
    let secrets = vec![MARKER.to_owned(), PASSWORD.to_owned()];
    let mut errors: Vec<Error> = Vec::new();

    // A wrong password, a password given when one was set, and a recovery
    // key that is not this vault's.
    vault.lock();
    errors.push(vault.unlock(&format!("{PASSWORD}{MARKER}")).unwrap_err());
    errors.push(
        vault
            .unlock_with_recovery(
                &RecoveryKey::parse("OSM-RK1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            )
            .unwrap_err(),
    );
    vault.unlock(PASSWORD).unwrap();
    errors.push(
        vault
            .change_password(MARKER, "another password")
            .unwrap_err(),
    );
    errors.push(RecoveryKey::parse(&format!("OSM-RK1-{MARKER}")).unwrap_err());
    // An item refused, one too large, and a one-time code from a secret
    // that is not one.
    let mut item = Item::new(" ");
    item.password = MARKER.into();
    errors.push(vault.put(item).unwrap_err());
    let mut item = Item::new("Large");
    item.password = MARKER.repeat(1 + 16 * 1024 * 1024 / MARKER.len());
    errors.push(vault.put(item).unwrap_err());
    let mut item = Item::new("With a code");
    item.totp_secret = Some(format!("{MARKER}!"));
    let written = vault.put(item).unwrap();
    errors.push(vault.item_totp_code(&written.item_id, 0).unwrap_err());
    // Imports that are not imports, with a password where something else
    // was expected.
    let not_text = [
        format!("url,username,password\n{MARKER},").into_bytes(),
        vec![0xff, 0xfe],
    ]
    .concat();
    for (format, bytes) in [
        (
            ImportFormat::BitwardenJson,
            format!(r#"{{"items":[{{"type":"{MARKER}"}}]}}"#).into_bytes(),
        ),
        (
            ImportFormat::BitwardenJson,
            format!(
                r#"{{"items":[{{"type":1,"name":"n","login":{{"password":{{"{MARKER}":1}}}}}}]}}"#
            )
            .into_bytes(),
        ),
        (
            ImportFormat::ChromeCsv,
            format!("name,url,username\n{MARKER},x,y").into_bytes(),
        ),
        (ImportFormat::FirefoxCsv, not_text),
    ] {
        errors.push(preview_import(format, &bytes).unwrap_err());
    }
    // A backup that is not this vault's, at a path that says nothing.
    errors.push(
        Vault::restore_backup(
            dir.path().join("missing.json"),
            dir.path().join("restored.sqlite3"),
            &RecoveryKey::parse("OSM-RK1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            MARKER,
        )
        .unwrap_err(),
    );

    for error in &errors {
        assert_hidden(&format!("{error} {error:?}"), &secrets);
    }
    assert_eq!(errors.len(), 12);
}
