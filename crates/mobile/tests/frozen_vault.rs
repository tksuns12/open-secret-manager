//! The interface on a copy of the frozen format 7 vault, whose password and
//! contents are written down (`crates/vault-core/fixtures`). The Swift and
//! Kotlin tests on the simulator and the emulator check the same things
//! through the generated bindings (`scripts/test-mobile.sh`).

use std::path::PathBuf;

use osm_mobile::{Device, DeviceState, ItemDraft, ItemKind, MobileError, SyncState};

const PASSWORD: &str = "fixture password, not a secret";
/// The test vector of RFC 6238 as a base32 secret.
const TOTP: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn draft(title: &str, kind: ItemKind) -> ItemDraft {
    ItemDraft {
        title: title.into(),
        kind,
        username: "me@example.test".into(),
        url: " https://forum.example.test ".into(),
        notes: String::new(),
        favorite: false,
        password: Some("first password".into()),
        one_time_code_secret: None,
    }
}

fn copy_of_the_frozen_vault() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("device");
    std::fs::create_dir_all(&folder).unwrap();
    let frozen = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vault-core/fixtures/format-7/vault.sqlite3");
    std::fs::copy(frozen, folder.join("vault.sqlite3")).unwrap();
    (dir, folder)
}

#[test]
fn the_frozen_vault_reads_through_the_interface() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    let device = Device::open_listening_on(folder, 0).unwrap();
    assert_eq!(device.state(), DeviceState::Locked);
    assert!(matches!(device.items(), Err(MobileError::Locked)));
    assert!(matches!(
        device.unlock("not the password".into()),
        Err(MobileError::InvalidCredentials)
    ));
    device.unlock(PASSWORD.into()).unwrap();
    assert_eq!(device.state(), DeviceState::Unlocked);

    let items = device.items().unwrap();
    let titles: Vec<&str> = items.iter().map(|item| item.title.as_str()).collect();
    assert!(
        titles.contains(&"Bank") && titles.contains(&"Mail"),
        "{titles:?}"
    );
    assert!(items.iter().any(|item| item.conflict), "{titles:?}");

    let bank = device.item("fixture-bank".into()).unwrap();
    assert_eq!(
        (bank.title.as_str(), bank.kind, bank.username.as_str()),
        ("Bank", ItemKind::Login, "account 42")
    );
    assert!(bank.has_password && bank.has_one_time_code && bank.favorite);
    assert_eq!(bank.notes, "line one\nline two");
    assert_eq!(
        device.password("fixture-bank".into()).unwrap(),
        "p@ss \"quoted\" \\ and 🔑"
    );
    let code = device.one_time_code("fixture-bank".into()).unwrap();
    assert!(code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()));
    assert_eq!(
        device.password("fixture-mail".into()).unwrap(),
        "third password, with ünïcödé"
    );
    assert!(matches!(
        device.one_time_code("fixture-mail".into()),
        Err(MobileError::NoOneTimeCode)
    ));
    assert!(matches!(
        device.item("no such item".into()),
        Err(MobileError::NotFound)
    ));

    // Filling: a page gets only the logins for exactly its origin.
    let titles = |origin: &str| -> Vec<String> {
        device
            .logins_for_web(origin.into())
            .unwrap()
            .into_iter()
            .map(|item| item.title)
            .collect()
    };
    assert_eq!(titles("https://mail.example.test"), ["Mail"]);
    assert_eq!(titles("https://bank.example.test:8443"), ["Bank"]);
    assert!(titles("https://bank.example.test").is_empty());
    assert!(titles("https://login.mail.example.test").is_empty());
    assert!(matches!(
        device.logins_for_web("http://mail.example.test".into()),
        Err(MobileError::InvalidOrigin)
    ));
    let filled = device
        .fill_for_web("fixture-mail".into(), "https://mail.example.test".into())
        .unwrap();
    assert_eq!(
        (filled.username.as_str(), filled.password.as_str()),
        ("owner@example.test", "third password, with ünïcödé")
    );
    assert!(matches!(
        device.fill_for_web("fixture-bank".into(), "https://mail.example.test".into()),
        Err(MobileError::NotForThisPage)
    ));
    assert_eq!(format!("{filled:?}"), "FillCredentials { .. }");
    // An app has no origin: the login the owner chose for it.
    assert_eq!(
        device.fill_for_app("fixture-bank".into()).unwrap().username,
        "account 42"
    );

    // A copy of a vault is not a device of its vault's devices.
    assert!(matches!(
        device.go_online(),
        Err(MobileError::Network { .. })
    ));
    assert_eq!(device.sync_status().state, SyncState::Offline);
    device.lock();
    assert!(matches!(
        device.password("fixture-bank".into()),
        Err(MobileError::Locked)
    ));
}

#[test]
fn a_folder_without_a_vault_and_one_with_a_damaged_vault_are_told_apart() {
    let dir = tempfile::tempdir().unwrap();
    let empty = Device::open_listening_on(dir.path().join("empty"), 0).unwrap();
    assert_eq!(empty.state(), DeviceState::NoVault);
    assert!(matches!(empty.go_online(), Err(MobileError::NoVault)));
    assert!(matches!(
        empty.join_finish("long enough password".into()),
        Err(MobileError::NotJoining)
    ));

    let damaged = dir.path().join("damaged");
    std::fs::create_dir_all(&damaged).unwrap();
    std::fs::write(damaged.join("vault.sqlite3"), b"not a vault").unwrap();
    assert!(matches!(
        Device::open_listening_on(damaged, 0),
        Err(MobileError::UnreadableVault { .. })
    ));
}

#[test]
fn an_items_history_shows_its_versions_and_a_login_or_a_note_comes_back() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    let device = Device::open_listening_on(folder, 0).unwrap();
    device.unlock(PASSWORD.into()).unwrap();

    // Mail was edited twice: three versions, newest first, each saying
    // what it changed.
    let history = device.history("fixture-mail".into()).unwrap();
    let seen: Vec<(bool, bool, Vec<String>)> = history
        .iter()
        .map(|version| (version.current, version.first, version.changed.clone()))
        .collect();
    assert_eq!(
        seen,
        [
            (true, false, vec!["password".to_owned(), "notes".to_owned()]),
            (false, false, vec!["password".to_owned()]),
            (false, true, vec![]),
        ]
    );
    assert!(history
        .iter()
        .all(|version| version.title == "Mail" && version.this_device));
    // Which fields changed, never what they held.
    assert!(!format!("{history:?}").contains("first password"));

    // The first version comes back, its password with it.
    let heads = vec![history[0].revision.clone()];
    device
        .restore(
            "fixture-mail".into(),
            history[2].revision.clone(),
            heads.clone(),
        )
        .unwrap();
    assert_eq!(
        device.password("fixture-mail".into()).unwrap(),
        "first password"
    );
    assert_eq!(device.history("fixture-mail".into()).unwrap().len(), 4);
    assert!(matches!(
        device.restore("fixture-mail".into(), history[2].revision.clone(), heads),
        Err(MobileError::ChangedElsewhere)
    ));

    // The frozen vault's deleted note is listed, and comes back.
    let deleted = device.deleted_items().unwrap();
    let note = deleted
        .iter()
        .find(|item| item.title == "A note that was deleted")
        .unwrap();
    assert_eq!(note.kind, ItemKind::SecureNote);
    let note_history = device.history(note.id.clone()).unwrap();
    assert!(note_history[0].deleted && note_history[0].title == "A note that was deleted");
    assert!(matches!(
        device.restore(
            note.id.clone(),
            note_history[0].revision.clone(),
            note.heads.clone()
        ),
        Err(MobileError::InvalidItem { .. })
    ));
    device
        .restore(note.id.clone(), note.last.clone(), note.heads.clone())
        .unwrap();
    assert_eq!(device.item(note.id.clone()).unwrap().notes, "gone");
    assert!(device
        .deleted_items()
        .unwrap()
        .iter()
        .all(|item| item.id != note.id));

    // An item in conflict is left to a computer.
    let conflicted = device
        .items()
        .unwrap()
        .into_iter()
        .find(|item| item.conflict)
        .unwrap();
    let versions = device.history(conflicted.id.clone()).unwrap();
    let oldest = versions.last().unwrap().revision.clone();
    let current: Vec<String> = versions
        .iter()
        .filter(|version| version.current)
        .map(|version| version.revision.clone())
        .collect();
    assert!(matches!(
        device.restore(conflicted.id, oldest, current),
        Err(MobileError::InConflict)
    ));
    device.lock();
    assert!(matches!(
        device.history("fixture-mail".into()),
        Err(MobileError::Locked)
    ));
}

#[test]
fn a_one_time_code_goes_only_where_its_login_would() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    let device = Device::open_listening_on(folder, 0).unwrap();
    device.unlock(PASSWORD.into()).unwrap();
    let ids: Vec<String> = device
        .items()
        .unwrap()
        .into_iter()
        .map(|item| item.id)
        .chain(["no such item".to_owned()])
        .collect();
    let with_codes: Vec<String> = device
        .with_one_time_codes(ids)
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    assert_eq!(with_codes, ["Bank"]);

    let code = device
        .one_time_code_for_web(
            "fixture-bank".into(),
            "https://bank.example.test:8443".into(),
        )
        .unwrap();
    assert!(code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(matches!(
        device.one_time_code_for_web("fixture-bank".into(), "https://bank.example.test".into()),
        Err(MobileError::NotForThisPage)
    ));
    assert!(matches!(
        device.one_time_code_for_web(
            "fixture-bank".into(),
            "http://bank.example.test:8443".into()
        ),
        Err(MobileError::InvalidOrigin)
    ));
    assert!(matches!(
        device.one_time_code_for_web("fixture-mail".into(), "https://mail.example.test".into()),
        Err(MobileError::NoOneTimeCode)
    ));
    device.lock();
    assert!(matches!(
        device.one_time_code_for_web(
            "fixture-bank".into(),
            "https://bank.example.test:8443".into()
        ),
        Err(MobileError::Locked)
    ));
}

#[test]
fn what_a_form_submitted_goes_only_into_a_login_it_could_be_filled_with() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    let device = Device::open_listening_on(folder, 0).unwrap();
    device.unlock(PASSWORD.into()).unwrap();
    let ids = |origin: &str| -> Vec<String> {
        device
            .logins_for_web(origin.into())
            .unwrap()
            .into_iter()
            .map(|item| item.id)
            .collect()
    };
    let candidates = |ids: Vec<String>, username: &str, password: &str| {
        device
            .save_candidates(ids, username.into(), password.into())
            .unwrap()
            .into_iter()
            .map(|candidate| (candidate.title, candidate.has_this_password))
            .collect::<Vec<_>>()
    };
    let mail = ids("https://mail.example.test");
    assert_eq!(
        candidates(mail.clone(), " owner@example.test ", "a new password"),
        [("Mail".to_owned(), false)]
    );
    assert_eq!(
        candidates(
            mail.clone(),
            "owner@example.test",
            "third password, with ünïcödé"
        ),
        [("Mail".to_owned(), true)]
    );
    // Another username is another account; a form without one could be
    // any of the page's.
    assert!(candidates(mail.clone(), "someone else", "a new password").is_empty());
    assert_eq!(
        candidates(mail.clone(), "", "x"),
        [("Mail".to_owned(), false)]
    );
    // Only logins, not in conflict, still in the vault.
    let items = device.items().unwrap();
    let all = device
        .save_candidates(
            items
                .iter()
                .map(|item| item.id.clone())
                .chain(["no such item".to_owned()])
                .collect(),
            String::new(),
            "x".into(),
        )
        .unwrap();
    let logins = items
        .iter()
        .filter(|item| item.kind == ItemKind::Login && !item.conflict);
    assert_eq!(
        all.iter()
            .map(|candidate| &candidate.id)
            .collect::<Vec<_>>(),
        logins.map(|item| &item.id).collect::<Vec<_>>()
    );
    assert!(items
        .iter()
        .any(|item| item.conflict && item.kind == ItemKind::Login));

    // The password changes, and nothing else.
    let bank = device.item("fixture-bank".into()).unwrap();
    device
        .update_password(
            "fixture-bank".into(),
            bank.revision.clone(),
            "a new password".into(),
        )
        .unwrap();
    let updated = device.item("fixture-bank".into()).unwrap();
    assert_eq!(
        device.password("fixture-bank".into()).unwrap(),
        "a new password"
    );
    assert_eq!(
        (
            updated.username.as_str(),
            updated.notes.as_str(),
            updated.has_one_time_code
        ),
        ("account 42", "line one\nline two", true)
    );
    assert!(matches!(
        device.update_password("fixture-bank".into(), bank.revision, "again".into()),
        Err(MobileError::ChangedElsewhere)
    ));
    assert!(matches!(
        device.update_password("fixture-bank".into(), updated.revision.clone(), "".into()),
        Err(MobileError::InvalidItem { .. })
    ));
    let mut note = draft("Recovery codes", ItemKind::SecureNote);
    note.notes = "one".into();
    let note = device.item(device.create_item(note).unwrap()).unwrap();
    assert!(matches!(
        device.update_password(note.id, note.revision, "x".into()),
        Err(MobileError::NotALogin)
    ));
    let conflicted = device
        .items()
        .unwrap()
        .into_iter()
        .find(|item| item.conflict)
        .unwrap();
    let conflicted = device.item(conflicted.id).unwrap();
    assert!(matches!(
        device.update_password(conflicted.id, conflicted.revision, "x".into()),
        Err(MobileError::InConflict)
    ));
}

#[test]
fn logins_and_notes_are_created_edited_and_deleted_and_the_rest_is_left_to_a_computer() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    let device = Device::open_listening_on(folder, 0).unwrap();
    assert!(matches!(
        device.create_item(draft("Forum", ItemKind::Login)),
        Err(MobileError::Locked)
    ));
    device.unlock(PASSWORD.into()).unwrap();

    let id = device
        .create_item(draft("  Forum  ", ItemKind::Login))
        .unwrap();
    let forum = device.item(id.clone()).unwrap();
    assert_eq!(
        (forum.title.as_str(), forum.url.as_str(), forum.kind),
        ("Forum", "https://forum.example.test", ItemKind::Login)
    );
    assert_eq!(device.password(id.clone()).unwrap(), "first password");
    assert_eq!(
        device
            .logins_for_web("https://forum.example.test".into())
            .unwrap()
            .len(),
        1
    );

    // An edit keeps the password unless it names one; a one-time code
    // secret is added, and an empty one removes it.
    let mut edit = draft("Forum", ItemKind::Login);
    edit.username = "someone else".into();
    edit.password = None;
    edit.one_time_code_secret = Some(TOTP.into());
    device
        .update_item(id.clone(), forum.revision.clone(), edit)
        .unwrap();
    let edited = device.item(id.clone()).unwrap();
    assert_eq!(edited.username, "someone else");
    assert!(edited.has_one_time_code);
    assert_eq!(device.password(id.clone()).unwrap(), "first password");
    // An edit of what was read before the last one is refused.
    assert!(matches!(
        device.update_item(
            id.clone(),
            forum.revision.clone(),
            draft("Forum", ItemKind::Login)
        ),
        Err(MobileError::ChangedElsewhere)
    ));
    let mut without_code = draft("Forum", ItemKind::Login);
    without_code.password = None;
    without_code.one_time_code_secret = Some(" ".into());
    device
        .update_item(id.clone(), edited.revision.clone(), without_code)
        .unwrap();
    assert!(!device.item(id.clone()).unwrap().has_one_time_code);

    // A secure note; a title is needed.
    let mut note = draft("Recovery codes", ItemKind::SecureNote);
    note.notes = "one\ntwo".into();
    let note = device.create_item(note).unwrap();
    assert_eq!(device.item(note).unwrap().kind, ItemKind::SecureNote);
    assert!(matches!(
        device.create_item(draft("  ", ItemKind::Login)),
        Err(MobileError::InvalidItem { .. })
    ));

    // Identities, cards, and conflicts are for a computer.
    for kind in [ItemKind::Identity, ItemKind::Card] {
        assert!(matches!(
            device.create_item(draft("Passport", kind)),
            Err(MobileError::NotEditableHere)
        ));
    }
    let conflicted = device
        .items()
        .unwrap()
        .into_iter()
        .find(|item| item.conflict)
        .unwrap();
    let conflicted = device.item(conflicted.id).unwrap();
    assert!(matches!(
        device.update_item(
            conflicted.id.clone(),
            conflicted.revision.clone(),
            draft("Mine", ItemKind::Login)
        ),
        Err(MobileError::InConflict)
    ));
    assert!(matches!(
        device.delete_item(conflicted.id.clone(), conflicted.revision.clone()),
        Err(MobileError::InConflict)
    ));

    // Deleted at its current revision, and not at an old one, it is gone.
    let current = device.item(id.clone()).unwrap();
    assert!(matches!(
        device.delete_item(id.clone(), forum.revision),
        Err(MobileError::ChangedElsewhere)
    ));
    device.delete_item(id.clone(), current.revision).unwrap();
    assert!(matches!(device.item(id), Err(MobileError::NotFound)));

    // New passwords come from the shared generator.
    let generated = osm_mobile::generate_password(24).unwrap();
    assert_eq!(generated.chars().count(), 24);
    assert!(matches!(
        osm_mobile::generate_password(2),
        Err(MobileError::InvalidItem { .. })
    ));
    // A draft prints none of what it holds.
    assert_eq!(
        format!("{:?}", draft("Forum", ItemKind::Login)),
        "ItemDraft { kind: Login, .. }"
    );
}

#[test]
fn an_edit_or_a_saved_password_keeps_the_fields_of_a_later_build() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    // A login a later build wrote, with a field this one does not know.
    {
        let mut vault = osm_vault_core::Vault::open(folder.join("vault.sqlite3")).unwrap();
        vault.unlock(PASSWORD).unwrap();
        let item: osm_vault_core::Item = serde_json::from_str(
            r#"{"id":"later","title":"Later","kind":"login","username":"me","password":"old","url":"https://later.example.test","notes":"","totp_secret":null,"custom_fields":{},"tags":[],"favorite":false,"passkey":{"credential":"secret key"}}"#,
        )
        .unwrap();
        vault.put(item).unwrap();
    }
    let kept = |folder: &std::path::Path| {
        let mut vault = osm_vault_core::Vault::open(folder.join("vault.sqlite3")).unwrap();
        vault.unlock(PASSWORD).unwrap();
        let item = vault.get("later").unwrap().item;
        (
            item.username.clone(),
            item.password.clone(),
            item.unknown_fields["passkey"]["credential"].clone(),
        )
    };

    let device = Device::open_listening_on(folder.clone(), 0).unwrap();
    device.unlock(PASSWORD.into()).unwrap();
    let later = device.item("later".into()).unwrap();
    let mut edit = draft("Later", ItemKind::Login);
    edit.username = "someone else".into();
    edit.password = None;
    device
        .update_item("later".into(), later.revision, edit)
        .unwrap();
    let later = device.item("later".into()).unwrap();
    device
        .update_password("later".into(), later.revision, "saved password".into())
        .unwrap();
    drop(device);

    assert_eq!(
        kept(&folder),
        (
            "someone else".to_owned(),
            "saved password".to_owned(),
            serde_json::json!("secret key")
        )
    );
}

#[test]
fn a_peer_store_of_a_later_version_makes_the_device_unreadable_and_is_left_as_it_is() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    drop(Device::open_listening_on(folder.clone(), 0).unwrap());
    let store = folder.join("peers.sqlite3");
    rusqlite::Connection::open(&store)
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    let before = std::fs::read(&store).unwrap();

    let Err(MobileError::UnreadableVault { reason }) = Device::open_listening_on(folder, 0) else {
        panic!("a peer store of a later version was opened");
    };
    assert_eq!(
        reason,
        "peers.sqlite3 was written by a later version of Open Secret Manager"
    );
    assert_eq!(std::fs::read(&store).unwrap(), before);
}

#[test]
fn records_taken_out_of_the_file_are_said_after_unlocking_until_confirmed() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    // Sealed at its first unlock (format 8), then the first version of Mail
    // taken out past the trigger the app keeps.
    let device = Device::open_listening_on(folder.clone(), 0).unwrap();
    device.unlock(PASSWORD.into()).unwrap();
    assert!(!device.rows_changed());
    drop(device);
    let connection = rusqlite::Connection::open(folder.join("vault.sqlite3")).unwrap();
    connection
        .execute_batch("DROP TRIGGER revisions_no_delete;")
        .unwrap();
    let taken = connection
        .execute(
            "DELETE FROM revisions WHERE item_id='fixture-mail' AND parents=''",
            [],
        )
        .unwrap();
    assert_eq!(taken, 1);
    drop(connection);

    let device = Device::open_listening_on(folder.clone(), 0).unwrap();
    assert!(!device.rows_changed(), "nothing is said while locked");
    device.unlock(PASSWORD.into()).unwrap();
    assert!(device.rows_changed());
    device.lock();
    device.unlock(PASSWORD.into()).unwrap();
    assert!(device.rows_changed(), "said again until confirmed");
    device.confirm_rows_changed().unwrap();
    assert!(!device.rows_changed());
    drop(device);
    let device = Device::open_listening_on(folder, 0).unwrap();
    device.unlock(PASSWORD.into()).unwrap();
    assert!(!device.rows_changed());
}

/// A card's, an identity's, and a login's other fields are named, in the
/// vault's order, and their values given one at a time to copy. A phone
/// edits neither a card nor an identity, and its edit of a login keeps the
/// login's other fields.
#[test]
fn an_items_other_fields_are_named_and_given_one_at_a_time() {
    let (_dir, folder) = copy_of_the_frozen_vault();
    // A card and an identity, as a computer or an import makes them.
    let (card, identity) = {
        let mut vault = osm_vault_core::Vault::open(folder.join("vault.sqlite3")).unwrap();
        vault.unlock(PASSWORD).unwrap();
        let mut card = osm_vault_core::Item::new("Visa");
        card.kind = osm_vault_core::ItemKind::Card;
        card.custom_fields
            .insert("Number".into(), "4111111111111111".into());
        card.custom_fields
            .insert("Security code".into(), "123".into());
        card.custom_fields
            .insert("Cardholder name".into(), "Owner".into());
        let card = vault.put(card).unwrap().item_id;
        let mut identity = osm_vault_core::Item::new("Passport");
        identity.kind = osm_vault_core::ItemKind::Identity;
        identity
            .custom_fields
            .insert("Passport number".into(), "X1234567".into());
        (card, vault.put(identity).unwrap().item_id)
    };

    let device = Device::open_listening_on(folder, 0).unwrap();
    assert!(matches!(
        device.field("fixture-bank".into(), "PIN".into()),
        Err(MobileError::Locked)
    ));
    device.unlock(PASSWORD.into()).unwrap();

    let shown = device.item(card.clone()).unwrap();
    assert_eq!(shown.kind, ItemKind::Card);
    assert_eq!(shown.fields, ["Cardholder name", "Number", "Security code"]);
    assert!(!shown.has_password);
    assert_eq!(
        device.field(card.clone(), "Security code".into()).unwrap(),
        "123"
    );
    assert!(matches!(
        device.field(card.clone(), "security code".into()),
        Err(MobileError::NoSuchField)
    ));
    let shown = device.item(identity.clone()).unwrap();
    assert_eq!(shown.kind, ItemKind::Identity);
    assert_eq!(shown.fields, ["Passport number"]);
    assert_eq!(
        device.field(identity, "Passport number".into()).unwrap(),
        "X1234567"
    );
    assert!(matches!(
        device.field("no such item".into(), "Number".into()),
        Err(MobileError::NotFound)
    ));

    // A login's own: kept by an edit made here.
    let bank = device.item("fixture-bank".into()).unwrap();
    assert_eq!(bank.fields, ["Branch", "PIN"]);
    assert!(device
        .item("fixture-mail".into())
        .unwrap()
        .fields
        .is_empty());
    device
        .update_item(
            "fixture-bank".into(),
            bank.revision,
            ItemDraft {
                title: "Bank".into(),
                kind: ItemKind::Login,
                username: bank.username,
                url: bank.url,
                notes: "edited on a phone".into(),
                favorite: bank.favorite,
                password: None,
                one_time_code_secret: None,
            },
        )
        .unwrap();
    assert_eq!(
        device.item("fixture-bank".into()).unwrap().fields,
        ["Branch", "PIN"]
    );
    assert_eq!(
        device.field("fixture-bank".into(), "PIN".into()).unwrap(),
        "0000"
    );
    // A card is still not edited here.
    let card_now = device.item(card.clone()).unwrap();
    assert!(device
        .update_item(
            card,
            card_now.revision,
            ItemDraft {
                title: "Visa".into(),
                kind: ItemKind::Card,
                username: String::new(),
                url: String::new(),
                notes: String::new(),
                favorite: false,
                password: None,
                one_time_code_secret: None,
            },
        )
        .is_err());
    device.lock();
    assert!(matches!(
        device.field("fixture-bank".into(), "PIN".into()),
        Err(MobileError::Locked)
    ));
}
