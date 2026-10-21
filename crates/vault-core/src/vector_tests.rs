//! The encodings the storage and wire formats are built from, checked
//! against frozen values: `fixtures/vectors.json` holds the inputs and what
//! this code made of them when the formats were frozen, for this and for
//! any other implementation to compare with, and `fixtures/vectors-8.json`
//! adds what format 8 brought. A further test reads the frozen vault's rows
//! with these encodings alone, so the vectors are the ones the file was
//! written with.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::{
    crypto::{
        decrypt, device_authorization, device_key_aad, device_revocation, encrypt, epoch_key_aad,
        key_wrap_aad, legacy_record_aad, legacy_revision_id, recipient_key_aad, record_aad,
        recovery_check, revision_id, revision_signature_message, row_mark, row_marks, row_seal_aad,
        row_seal_key, sealed_device_key_aad, verify_device_authorization, verify_device_revocation,
        xor_into, RowSets,
    },
    epoch_key_check,
    fixture_tests::{fixture, hex, Expected, CURRENT},
    storage::backup_aad,
    verify_pairing_signature, EncryptedRevision, Item, ItemKind, RecoveryKey,
    CONTROL_SIGNATURE_DOMAIN, PAIRING_SIGNATURE_DOMAIN,
};

/// `N` bytes counting up from `first`: inputs anyone can write down.
pub(crate) fn counting<const N: usize>(first: u8) -> [u8; N] {
    std::array::from_fn(|index| first.wrapping_add(index as u8))
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// Who seals the vectors' revisions, and with what.
struct Sealer<'a> {
    vault_id: &'a [u8; 32],
    author: &'a [u8; 16],
    signing_key: &'a SigningKey,
    epoch_key: &'a [u8; 32],
    nonce: &'a [u8; 24],
}

/// One sealed revision, built from the encodings step by step.
fn sealed(
    sealer: &Sealer<'_>,
    item_id: &str,
    parents: &[String],
    key_epoch: u64,
    plaintext: Option<&[u8]>,
) -> Value {
    let Sealer {
        vault_id,
        author,
        signing_key,
        epoch_key,
        nonce,
    } = *sealer;
    let tombstone = plaintext.is_none();
    let aad = record_aad(vault_id, item_id, parents, key_epoch, author, tombstone);
    let ciphertext = encrypt(epoch_key, nonce, &aad, plaintext.unwrap_or_default()).unwrap();
    let message = revision_signature_message(&aad, nonce, &ciphertext);
    let signature = signing_key.sign(&message).to_bytes();
    let revision = EncryptedRevision {
        format_version: 2,
        vault_id: *vault_id,
        item_id: item_id.to_owned(),
        parents: parents.to_vec(),
        key_epoch,
        author_device_id: *author,
        nonce: *nonce,
        ciphertext: ciphertext.clone(),
        tombstone,
        signature: signature.to_vec(),
    };
    assert_eq!(
        revision.revision_id(),
        revision_id(&aad, nonce, &ciphertext, &signature)
    );
    json!({
        "item_id": item_id,
        "parents": parents,
        "key_epoch": key_epoch,
        "tombstone": tombstone,
        "aad": hex(&aad),
        "ciphertext": hex(&ciphertext),
        "signed_message": hex(&message),
        "signature": hex(&signature),
        "revision_id": revision.revision_id(),
        // As a backup's payload holds it.
        "as_json": serde_json::to_string(&revision).unwrap(),
    })
}

fn vectors() -> Value {
    let vault_id: [u8; 32] = counting(0x10);
    let device_id: [u8; 16] = counting(0x40);
    let signing_seed: [u8; 32] = counting(0x60);
    let root_key: [u8; 32] = counting(0x80);
    let epoch_key: [u8; 32] = counting(0xa0);
    let recovery_key: [u8; 32] = counting(0xc0);
    let recipient_secret: [u8; 32] = counting(0x30);
    let nonce: [u8; 24] = counting(0xe0);
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let key_epoch = 3_u64;
    let parents = vec!["1".repeat(64), "a".repeat(64)];

    let mut item = Item::new("Bank, with ünïcödé and 🔑");
    item.id = "vector-item".into();
    item.kind = ItemKind::Login;
    item.username = "account 42".into();
    item.password = "p@ss \"quoted\" \\".into();
    item.url = "https://bank.example.test:8443/".into();
    item.notes = "line one\nline two".into();
    item.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    item.custom_fields.insert("PIN".into(), "0000".into());
    item.custom_fields
        .insert("Branch".into(), "Main Street".into());
    item.tags = vec!["money".into(), "important".into()];
    item.favorite = true;
    let plaintext = serde_json::to_vec(&item).unwrap();
    let mut note = Item::new("A note");
    note.id = "vector-note".into();
    note.kind = ItemKind::SecureNote;

    let sealer = Sealer {
        vault_id: &vault_id,
        author: &device_id,
        signing_key: &signing_key,
        epoch_key: &epoch_key,
        nonce: &nonce,
    };

    let recovery = RecoveryKey::from_bytes(recovery_key);
    let recovery_text = recovery.to_string();
    assert!(RecoveryKey::parse(&recovery_text).unwrap().expose() == &recovery_key);
    let wrap = |key: &[u8; 32], aad: &[u8], secret: &[u8]| {
        hex(&encrypt(key, &nonce, aad, secret).unwrap())
    };

    let pairing_message = b"a pairing message";
    let mut pairing_signed = PAIRING_SIGNATURE_DOMAIN.to_vec();
    pairing_signed.extend_from_slice(pairing_message);
    let pairing_signature = signing_key.sign(&pairing_signed).to_bytes();
    verify_pairing_signature(&public_key, pairing_message, &pairing_signature).unwrap();
    let mut control_signed = CONTROL_SIGNATURE_DOMAIN.to_vec();
    control_signed.extend_from_slice(b"a control request");

    // The backup envelope carries these two as text, and binds that text.
    let recovery_nonce_text = "4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3";
    let recovery_wrapper_text = "wrapped-root-key-as-base64url-text";

    json!({
        "about": "Inputs and what the vault code made of them when the formats were frozen. Bytes are lowercase hexadecimal. Every key here is a counting pattern and protects nothing. Each encryption is XChaCha20-Poly1305 with the given key, the one nonce in the inputs, and the named authenticated data; each signature is Ed25519 with the key made from signing_seed.",
        "inputs": {
            "vault_id": hex(&vault_id),
            "device_id": hex(&device_id),
            "signing_seed": hex(&signing_seed),
            "root_key": hex(&root_key),
            "epoch_key": hex(&epoch_key),
            "recovery_key": hex(&recovery_key),
            "recipient_secret": hex(&recipient_secret),
            "nonce": hex(&nonce),
            "key_epoch": key_epoch,
            "parents": parents,
            "item": item,
            "pairing_message": String::from_utf8_lossy(pairing_message),
            "control_message": "a control request",
            "backup_recovery_nonce_text": recovery_nonce_text,
            "backup_recovery_wrapped_key_text": recovery_wrapper_text,
        },
        "keys": {
            "device_public_key": hex(&public_key),
            "recovery_key_text": recovery_text,
            "recovery_check": hex(&recovery_check(&recovery_key, &vault_id).unwrap()),
            "epoch_key_check": hex(&epoch_key_check(&vault_id, key_epoch, &epoch_key)),
            "password_wrap_aad": hex(&key_wrap_aad(&vault_id, b"password")),
            "recovery_wrap_aad": hex(&key_wrap_aad(&vault_id, b"recovery")),
            "root_key_wrapped_by_recovery_key": wrap(&recovery_key, &key_wrap_aad(&vault_id, b"recovery"), &root_key),
            "unconfirmed_recovery_aad": hex(&key_wrap_aad(&vault_id, b"unconfirmed-recovery")),
            "recovery_key_wrapped_by_root_key": wrap(&root_key, &key_wrap_aad(&vault_id, b"unconfirmed-recovery"), &recovery_key),
            "signing_seed_aad": hex(&device_key_aad(&vault_id, &device_id, &public_key)),
            "signing_seed_wrapped_by_root_key": wrap(&root_key, &device_key_aad(&vault_id, &device_id, &public_key), &signing_seed),
            "epoch_key_aad": hex(&epoch_key_aad(&vault_id, key_epoch)),
            "epoch_key_wrapped_by_root_key": wrap(&root_key, &epoch_key_aad(&vault_id, key_epoch), &epoch_key),
            "recipient_secret_aad": hex(&recipient_key_aad(&vault_id, &device_id)),
            "recipient_secret_wrapped_by_root_key": wrap(&root_key, &recipient_key_aad(&vault_id, &device_id), &recipient_secret),
            "device_authorization": hex(&device_authorization(&root_key, &vault_id, &device_id, &public_key).unwrap()),
            "device_revocation": hex(&device_revocation(&root_key, &vault_id, &device_id).unwrap()),
        },
        "revisions": {
            "item_plaintext": String::from_utf8(plaintext.clone()).unwrap(),
            "edit_with_two_parents": sealed(&sealer, "vector-item", &parents, key_epoch, Some(&plaintext)),
            "new_item": sealed(&sealer, "vector-note", &[], 1, Some(&serde_json::to_vec(&note).unwrap())),
            "deletion": sealed(&sealer, "vector-item", &parents[..1], key_epoch, None),
        },
        "signatures": {
            "pairing_signed_message": hex(&pairing_signed),
            "pairing_signature": hex(&pairing_signature),
            "control_signed_message": hex(&control_signed),
            "control_signature": hex(&signing_key.sign(&control_signed).to_bytes()),
        },
        "backup": {
            "payload_aad": hex(&backup_aad(&vault_id, recovery_nonce_text, recovery_wrapper_text)),
        },
        "format_1_read_only": {
            "record_aad_with_parent": hex(&legacy_record_aad(&vault_id, "vector-item", Some(&parents[0]), 1, false)),
            "record_aad_without_parent": hex(&legacy_record_aad(&vault_id, "vector-item", None, 1, true)),
            "revision_id": legacy_revision_id(b"aad", &nonce, b"ciphertext"),
        },
    })
}

/// What format 8 added, from the same inputs as `vectors()`: the signing
/// seed's new label, and the seal over the rows never changed or removed.
fn format_8_vectors() -> Value {
    let vault_id: [u8; 32] = counting(0x10);
    let device_id: [u8; 16] = counting(0x40);
    let signing_seed: [u8; 32] = counting(0x60);
    let root_key: [u8; 32] = counting(0x80);
    let nonce: [u8; 24] = counting(0xe0);
    let public_key = SigningKey::from_bytes(&signing_seed)
        .verifying_key()
        .to_bytes();
    let aad = sealed_device_key_aad(&vault_id, &device_id, &public_key);

    let sets = example_rows();
    let seal_key = row_seal_key(&root_key).unwrap();
    let marks = row_marks(&seal_key, &sets).unwrap();
    let mark = |table: &str, key: &[u8]| hex(&row_mark(&seal_key, table, key).unwrap());
    let hex_list = |keys: &[Vec<u8>]| keys.iter().map(|key| hex(key)).collect::<Vec<_>>();
    let mut seal = nonce.to_vec();
    seal.extend_from_slice(&encrypt(&root_key, &nonce, &row_seal_aad(&vault_id), &marks).unwrap());

    json!({
        "about": "What format 8 added, made from the inputs of vectors.json, whose counting patterns are repeated here. Bytes are lowercase hexadecimal. A row's mark is HMAC-SHA256 under seal_key, itself HMAC-SHA256 of the text osm-row-seal-key-v1 under root_key; the marks of a vault's rows are XORed together, in any order, and the seal is the nonce followed by those marks encrypted by root_key under row_seal_aad.",
        "inputs": {
            "vault_id": hex(&vault_id),
            "device_id": hex(&device_id),
            "signing_seed": hex(&signing_seed),
            "root_key": hex(&root_key),
            "nonce": hex(&nonce),
            "row_sets": {
                "revisions": sets.revisions,
                "devices": hex_list(&sets.devices),
                "revoked_devices": hex_list(&sets.revoked),
                "epoch_keys": sets.epochs,
            },
        },
        "keys": {
            "device_public_key": hex(&public_key),
            "signing_seed_aad": hex(&aad),
            "signing_seed_wrapped_by_root_key": hex(&encrypt(&root_key, &nonce, &aad, &signing_seed).unwrap()),
        },
        "row_seal": {
            "seal_key": hex(&*seal_key),
            "mark_of_revision": mark("revisions", sets.revisions[0].as_bytes()),
            "mark_of_device": mark("devices", &sets.devices[0]),
            "mark_of_revoked_device": mark("revoked_devices", &sets.revoked[0]),
            "mark_of_epoch_key": mark("epoch_keys", &sets.epochs[0].to_be_bytes()),
            "marks_of_the_sets": hex(&marks),
            "row_seal_aad": hex(&row_seal_aad(&vault_id)),
            "row_seal": hex(&seal),
        },
    })
}

/// Rows of each of the four sealed sets, to mark.
fn example_rows() -> RowSets {
    RowSets {
        revisions: vec!["0".repeat(64), "f".repeat(64)],
        devices: vec![counting::<16>(0x40).to_vec(), counting::<16>(0x50).to_vec()],
        revoked: vec![counting::<16>(0x50).to_vec()],
        epochs: vec![1, 2, 3],
    }
}

/// Says where two values differ, so that a failure names the encoding.
fn differences(path: &str, frozen: &Value, made: &Value, found: &mut Vec<String>) {
    match (frozen, made) {
        (Value::Object(frozen), Value::Object(made)) => {
            for name in frozen.keys().chain(made.keys()) {
                let (left, right) = (frozen.get(name), made.get(name));
                match (left, right) {
                    (Some(left), Some(right)) => {
                        differences(&format!("{path}.{name}"), left, right, found)
                    }
                    _ => found.push(format!("{path}.{name} is in one and not the other")),
                }
            }
        }
        _ if frozen != made => found.push(path.to_owned()),
        _ => {}
    }
}

/// The frozen file `name` in the fixtures, after checking that `made`
/// matches it.
pub(crate) fn frozen(name: &str, made: &Value) -> Value {
    let path = crate::fixture_tests::crate_dir()
        .join("fixtures")
        .join(name);
    // A frozen file is not written over. To add one for a new format, run
    // once with `OSM_WRITE_NEW_FIXTURES=1` while it does not exist.
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(made).unwrap() + "\n").unwrap();
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found = Vec::new();
    differences("vectors", &frozen, made, &mut found);
    found.sort();
    found.dedup();
    assert!(
        found.is_empty(),
        "these no longer match the frozen values in {name}: {found:#?}"
    );
    frozen
}

#[test]
fn the_encodings_are_the_frozen_ones() {
    let frozen = frozen("vectors.json", &vectors());

    // And back: what was frozen opens with the same keys.
    let text = |section: &str, name: &str| unhex(frozen[section][name].as_str().unwrap());
    let array = |section: &str, name: &str| -> [u8; 32] { text(section, name).try_into().unwrap() };
    let nonce: [u8; 24] = text("inputs", "nonce").try_into().unwrap();
    let vault_id = array("inputs", "vault_id");
    let root = decrypt(
        &array("inputs", "recovery_key"),
        &nonce,
        &key_wrap_aad(&vault_id, b"recovery"),
        &text("keys", "root_key_wrapped_by_recovery_key"),
    )
    .unwrap();
    assert_eq!(hex(&root), frozen["inputs"]["root_key"]);
    let edit = &frozen["revisions"]["edit_with_two_parents"];
    let plaintext = decrypt(
        &array("inputs", "epoch_key"),
        &nonce,
        &unhex(edit["aad"].as_str().unwrap()),
        &unhex(edit["ciphertext"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&plaintext),
        frozen["revisions"]["item_plaintext"].as_str().unwrap()
    );
    let item: Item = serde_json::from_slice(&plaintext).unwrap();
    assert!(serde_json::to_value(&item).unwrap() == frozen["inputs"]["item"]);
    VerifyingKey::from_bytes(&array("keys", "device_public_key"))
        .unwrap()
        .verify_strict(
            &unhex(edit["signed_message"].as_str().unwrap()),
            &Signature::from_slice(&unhex(edit["signature"].as_str().unwrap())).unwrap(),
        )
        .unwrap();
    let as_json: EncryptedRevision =
        serde_json::from_str(edit["as_json"].as_str().unwrap()).unwrap();
    assert_eq!(as_json.revision_id(), edit["revision_id"]);
}

#[test]
fn the_format_8_encodings_are_the_frozen_ones() {
    let frozen = frozen("vectors-8.json", &format_8_vectors());

    // And back: the frozen wrapping opens under its label, and not under the
    // label of earlier formats.
    let text = |section: &str, name: &str| unhex(frozen[section][name].as_str().unwrap());
    let inputs = |name: &str| unhex(frozen["inputs"][name].as_str().unwrap());
    let root: [u8; 32] = inputs("root_key").try_into().unwrap();
    let nonce: [u8; 24] = inputs("nonce").try_into().unwrap();
    let vault_id: [u8; 32] = inputs("vault_id").try_into().unwrap();
    let device_id: [u8; 16] = inputs("device_id").try_into().unwrap();
    let public_key: [u8; 32] = text("keys", "device_public_key").try_into().unwrap();
    let wrapped = text("keys", "signing_seed_wrapped_by_root_key");
    let seed = decrypt(&root, &nonce, &text("keys", "signing_seed_aad"), &wrapped).unwrap();
    assert_eq!(hex(&seed), frozen["inputs"]["signing_seed"]);
    assert!(decrypt(
        &root,
        &nonce,
        &device_key_aad(&vault_id, &device_id, &public_key),
        &wrapped
    )
    .is_err());

    // The seal opens to the marks of the sets, which are the XOR of each
    // row's mark, and differ with any one row taken out of any set.
    let seal = text("row_seal", "row_seal");
    let marks = decrypt(
        &root,
        seal[..24].try_into().unwrap(),
        &text("row_seal", "row_seal_aad"),
        &seal[24..],
    )
    .unwrap();
    assert_eq!(hex(&marks), frozen["row_seal"]["marks_of_the_sets"]);
    let seal_key: [u8; 32] = text("row_seal", "seal_key").try_into().unwrap();
    let sets = format_8_rows(&frozen["inputs"]["row_sets"]);
    let mut each = [0; 32];
    let rows = sets
        .revisions
        .iter()
        .map(|id| ("revisions", id.as_bytes().to_vec()));
    let rows = rows
        .chain(sets.devices.iter().map(|id| ("devices", id.clone())))
        .chain(
            sets.revoked
                .iter()
                .map(|id| ("revoked_devices", id.clone())),
        )
        .chain(
            sets.epochs
                .iter()
                .map(|epoch| ("epoch_keys", epoch.to_be_bytes().to_vec())),
        );
    for (table, key) in rows {
        xor_into(&mut each, &row_mark(&seal_key, table, &key).unwrap());
    }
    assert_eq!(hex(&each), frozen["row_seal"]["marks_of_the_sets"]);
    let mut fewer = vec![hex(&each)];
    for set in 0..4 {
        let mut smaller = format_8_rows(&frozen["inputs"]["row_sets"]);
        match set {
            0 => drop(smaller.revisions.pop()),
            1 => drop(smaller.devices.pop()),
            2 => drop(smaller.revoked.pop()),
            _ => drop(smaller.epochs.pop()),
        }
        fewer.push(hex(&row_marks(&seal_key, &smaller).unwrap()));
    }
    fewer.sort();
    fewer.dedup();
    assert_eq!(fewer.len(), 5);
}

/// The row sets as the format 8 vectors write them.
fn format_8_rows(sets: &Value) -> RowSets {
    let keys = |name: &str| -> Vec<Vec<u8>> {
        sets[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| unhex(key.as_str().unwrap()))
            .collect()
    };
    RowSets {
        revisions: sets["revisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_owned())
            .collect(),
        devices: keys("devices"),
        revoked: keys("revoked_devices"),
        epochs: sets["epoch_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch| epoch.as_u64().unwrap())
            .collect(),
    }
}

/// Reads the frozen vault's rows with the encodings above and nothing else:
/// no `Vault`. What the vectors describe is what the file holds.
#[test]
fn the_frozen_vault_is_laid_out_as_the_encodings_say() {
    let expected = Expected::of(CURRENT);
    let recovery = expected.recovery();
    // Read-only, so the frozen file is not touched.
    let connection = Connection::open_with_flags(
        fixture(CURRENT, "vault.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let blob = |sql: &str| -> Vec<u8> { connection.query_row(sql, [], |row| row.get(0)).unwrap() };
    let vault_id: [u8; 32] = blob("SELECT vault_id FROM vault_meta").try_into().unwrap();
    let device_id: [u8; 16] = blob("SELECT device_id FROM vault_meta").try_into().unwrap();
    let public_key: [u8; 32] = blob("SELECT device_public_key FROM vault_meta")
        .try_into()
        .unwrap();
    let nonce = |sql: &str| -> [u8; 24] { blob(sql).try_into().unwrap() };

    // The recovery key opens the root key, and the check value is its.
    let root: [u8; 32] = decrypt(
        recovery.expose(),
        &nonce("SELECT recovery_nonce FROM vault_meta"),
        &key_wrap_aad(&vault_id, b"recovery"),
        &blob("SELECT recovery_wrapped_key FROM vault_meta"),
    )
    .unwrap()
    .as_slice()
    .try_into()
    .unwrap();
    assert_eq!(
        recovery_check(recovery.expose(), &vault_id)
            .unwrap()
            .to_vec(),
        blob("SELECT recovery_check FROM vault_meta")
    );
    // The root key opens the signing seed, the recipient secret, and the
    // recovery key kept until confirmed.
    let seed = decrypt(
        &root,
        &nonce("SELECT device_key_nonce FROM vault_meta"),
        &sealed_device_key_aad(&vault_id, &device_id, &public_key),
        &blob("SELECT device_wrapped_signing_key FROM vault_meta"),
    )
    .unwrap();
    assert_eq!(
        SigningKey::from_bytes(seed.as_slice().try_into().unwrap())
            .verifying_key()
            .to_bytes(),
        public_key
    );
    decrypt(
        &root,
        &nonce("SELECT recipient_nonce FROM vault_meta"),
        &recipient_key_aad(&vault_id, &device_id),
        &blob("SELECT recipient_wrapped_secret FROM vault_meta"),
    )
    .unwrap();
    let kept = decrypt(
        &root,
        &nonce("SELECT nonce FROM unconfirmed_recovery"),
        &key_wrap_aad(&vault_id, b"unconfirmed-recovery"),
        &blob("SELECT wrapped_key FROM unconfirmed_recovery"),
    )
    .unwrap();
    assert!(kept.as_slice() == recovery.expose());

    // Authors and removed devices carry the root key's marks.
    let mut authors = std::collections::BTreeMap::new();
    let mut statement = connection
        .prepare("SELECT device_id, public_key, authorization FROM devices")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (device, key, mark) = row.unwrap();
        let (device, key): ([u8; 16], [u8; 32]) =
            (device.try_into().unwrap(), key.try_into().unwrap());
        verify_device_authorization(&root, &vault_id, &device, &key, &mark).unwrap();
        authors.insert(device, VerifyingKey::from_bytes(&key).unwrap());
    }
    assert_eq!(authors.len(), 2);
    let removed: [u8; 16] = blob("SELECT device_id FROM revoked_devices")
        .try_into()
        .unwrap();
    verify_device_revocation(
        &root,
        &vault_id,
        &removed,
        &blob("SELECT revocation FROM revoked_devices"),
    )
    .unwrap();

    // Each epoch key opens under the root key and matches the recorded check.
    let mut epoch_keys = std::collections::BTreeMap::new();
    for entry in expected.current()["epoch_key_checks"].as_array().unwrap() {
        let epoch = entry["epoch"].as_u64().unwrap();
        let key: [u8; 32] = decrypt(
            &root,
            &nonce(&format!(
                "SELECT nonce FROM epoch_keys WHERE epoch = {epoch}"
            )),
            &epoch_key_aad(&vault_id, epoch),
            &blob(&format!(
                "SELECT wrapped_key FROM epoch_keys WHERE epoch = {epoch}"
            )),
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
        assert_eq!(
            hex(&epoch_key_check(&vault_id, epoch, &key)),
            entry["check"]
        );
        epoch_keys.insert(epoch, key);
    }

    // The seal is the one over the rows the file holds, each set sorted.
    fn column<T: rusqlite::types::FromSql>(connection: &Connection, sql: &str) -> Vec<T> {
        let mut statement = connection.prepare(sql).unwrap();
        let rows = statement.query_map([], |row| row.get(0)).unwrap();
        rows.map(Result::unwrap).collect()
    }
    let sets = RowSets {
        revisions: column(
            &connection,
            "SELECT revision FROM revisions ORDER BY revision",
        ),
        devices: column(
            &connection,
            "SELECT device_id FROM devices ORDER BY device_id",
        ),
        revoked: column(
            &connection,
            "SELECT device_id FROM revoked_devices ORDER BY device_id",
        ),
        epochs: column::<i64>(&connection, "SELECT epoch FROM epoch_keys ORDER BY epoch")
            .into_iter()
            .map(|epoch| u64::try_from(epoch).unwrap())
            .collect(),
    };
    assert_eq!(sets.epochs, epoch_keys.keys().copied().collect::<Vec<_>>());
    assert!(!sets.revisions.is_empty());
    let seal = blob("SELECT row_seal FROM vault_meta");
    let marks = decrypt(
        &root,
        seal[..24].try_into().unwrap(),
        &row_seal_aad(&vault_id),
        &seal[24..],
    )
    .unwrap();
    assert_eq!(
        marks.as_slice(),
        row_marks(&row_seal_key(&root).unwrap(), &sets).unwrap()
    );
    assert_eq!(
        connection
            .query_row("SELECT rows_changed FROM vault_meta", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );

    // Every stored, held, and staged revision: its ID, its signature when
    // its author is known here, and its content.
    let mut read = 0;
    for table in ["revisions", "quarantine", "ingress"] {
        let mut statement = connection
            .prepare(&format!(
                "SELECT revision, format_version, vault_id, item_id, parents, key_epoch, \
                 author_device_id, nonce, ciphertext, tombstone, signature FROM {table}"
            ))
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            let id: String = row.get(0).unwrap();
            assert_eq!(row.get::<_, u32>(1).unwrap(), 2);
            assert_eq!(row.get::<_, Vec<u8>>(2).unwrap(), vault_id);
            let item_id: String = row.get(3).unwrap();
            let joined: String = row.get(4).unwrap();
            let parents: Vec<String> = (0..joined.len())
                .step_by(64)
                .map(|at| joined[at..at + 64].to_owned())
                .collect();
            let key_epoch = u64::try_from(row.get::<_, i64>(5).unwrap()).unwrap();
            let author: [u8; 16] = row.get::<_, Vec<u8>>(6).unwrap().try_into().unwrap();
            let revision_nonce: [u8; 24] = row.get::<_, Vec<u8>>(7).unwrap().try_into().unwrap();
            let ciphertext: Vec<u8> = row.get(8).unwrap();
            let tombstone: bool = row.get(9).unwrap();
            let signature: Vec<u8> = row.get(10).unwrap();

            let aad = record_aad(&vault_id, &item_id, &parents, key_epoch, &author, tombstone);
            assert_eq!(
                revision_id(&aad, &revision_nonce, &ciphertext, &signature),
                id,
                "{table}"
            );
            if let Some(key) = authors.get(&author) {
                key.verify_strict(
                    &revision_signature_message(&aad, &revision_nonce, &ciphertext),
                    &Signature::from_slice(&signature).unwrap(),
                )
                .unwrap();
            }
            let plaintext =
                decrypt(&epoch_keys[&key_epoch], &revision_nonce, &aad, &ciphertext).unwrap();
            if tombstone {
                assert!(plaintext.is_empty());
            } else {
                let item: Item = serde_json::from_slice(&plaintext).unwrap();
                assert_eq!(item.id, item_id);
            }
            read += 1;
        }
    }
    assert_eq!(read, 11 + 2 + 1);

    // The heads are the revisions that no other names as a parent.
    let mut follows = std::collections::BTreeMap::new();
    let mut named = Vec::new();
    let mut statement = connection
        .prepare("SELECT revision, item_id, parents, tombstone FROM revisions")
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let parents: String = row.get(2).unwrap();
        named.extend(
            (0..parents.len())
                .step_by(64)
                .map(|at| parents[at..at + 64].to_owned()),
        );
        follows.insert(
            row.get::<_, String>(0).unwrap(),
            (
                row.get::<_, String>(1).unwrap(),
                row.get::<_, bool>(3).unwrap(),
            ),
        );
    }
    for parent in named {
        follows.remove(&parent);
    }
    let mut statement = connection
        .prepare("SELECT revision, item_id, tombstone FROM heads")
        .unwrap();
    let heads: std::collections::BTreeMap<String, (String, bool)> = statement
        .query_map([], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?))))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(heads, follows);
}

/// The fields of an item are part of record format 2. Since Phase 8 a
/// build keeps a field it does not know and writes it back after its own,
/// so that an edit here does not drop a later build's field; builds from
/// before drop it.
#[test]
fn a_versions_time_comes_after_the_items_fields_and_a_deletion_holds_it_alone() {
    use crate::storage::{saved_at, version_plaintext};
    let item: Item = serde_json::from_str(
        r#"{"id":"i","title":"t","kind":"login","username":"","password":"","url":"","notes":"",
            "totp_secret":null,"custom_fields":{},"tags":[],"favorite":false,"added_later":"x"}"#,
    )
    .unwrap();
    let saved = version_plaintext(Some(&item), Some(1_767_225_600)).unwrap();
    assert_eq!(
        std::str::from_utf8(&saved).unwrap(),
        r#"{"id":"i","title":"t","kind":"login","username":"","password":"","url":"","notes":"","totp_secret":null,"custom_fields":{},"tags":[],"favorite":false,"added_later":"x","saved_at":1767225600}"#
    );
    let deletion = version_plaintext(None, Some(1_767_225_600)).unwrap();
    assert_eq!(deletion.as_slice(), br#"{"saved_at":1767225600}"#);
    assert_eq!(saved_at(&saved), Some(1_767_225_600));
    assert_eq!(saved_at(&deletion), Some(1_767_225_600));
    // Read back, the time is not one of the item's fields.
    let read: Item = serde_json::from_slice(&saved).unwrap();
    assert_eq!(read, item);
    assert_eq!(
        read.unknown_fields.keys().collect::<Vec<_>>(),
        ["added_later"]
    );

    // Without a time, as before Phase 15; and a time in any other form is
    // none, while the item still reads.
    assert_eq!(saved_at(b""), None);
    assert_eq!(
        saved_at(&version_plaintext(Some(&item), None).unwrap()),
        None
    );
    for odd in [
        r#""1767225600""#,
        "-1",
        "1.5",
        "null",
        "18446744073709551616",
    ] {
        let text = format!(
            r#"{{"id":"i","title":"t","kind":"login","username":"","password":"","url":"","notes":"","totp_secret":null,"custom_fields":{{}},"tags":[],"favorite":false,"saved_at":{odd}}}"#
        );
        assert_eq!(saved_at(text.as_bytes()), None, "{odd}");
        assert!(serde_json::from_str::<Item>(&text)
            .unwrap()
            .unknown_fields
            .is_empty());
    }
    assert_eq!(saved_at(br#"{"saved_at":1,"saved_at":2}"#), None);
}

#[test]
fn an_items_fields_are_fixed_and_one_it_does_not_know_is_kept_after_them() {
    let item: Item = serde_json::from_str(
        r#"{"id":"i","title":"t","kind":"card","username":"","password":"","url":"","notes":"",
            "added_later":"x","totp_secret":null,"custom_fields":{},"tags":[],"favorite":false}"#,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string(&item).unwrap(),
        r#"{"id":"i","title":"t","kind":"card","username":"","password":"","url":"","notes":"","totp_secret":null,"custom_fields":{},"tags":[],"favorite":false,"added_later":"x"}"#
    );
    // Every field has to be there, a kind has to be one of the four, and a
    // field given twice is refused.
    for malformed in [
        r#"{"id":"i","title":"t","kind":"login","username":"","password":"","url":"","notes":"","totp_secret":null,"custom_fields":{},"tags":[]}"#,
        r#"{"id":"i","title":"t","kind":"passkey","username":"","password":"","url":"","notes":"","totp_secret":null,"custom_fields":{},"tags":[],"favorite":false}"#,
        r#"{"id":"i","id":"j","title":"t","kind":"login","username":"","password":"","url":"","notes":"","totp_secret":null,"custom_fields":{},"tags":[],"favorite":false}"#,
    ] {
        assert!(
            serde_json::from_str::<Item>(malformed).is_err(),
            "{malformed}"
        );
    }
    for (kind, text) in [
        (ItemKind::Login, "login"),
        (ItemKind::SecureNote, "secure_note"),
        (ItemKind::Identity, "identity"),
        (ItemKind::Card, "card"),
    ] {
        assert_eq!(serde_json::to_value(kind).unwrap(), text);
    }
}
