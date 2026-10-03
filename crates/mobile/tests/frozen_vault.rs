//! The interface on a copy of the frozen format 7 vault, whose password and
//! contents are written down (`crates/vault-core/fixtures`). The Swift and
//! Kotlin tests on the simulator and the emulator check the same things
//! through the generated bindings (`scripts/test-mobile.sh`).

use std::path::PathBuf;

use osm_mobile::{Device, DeviceState, ItemKind, MobileError, SyncState};

const PASSWORD: &str = "fixture password, not a secret";

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
