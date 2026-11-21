//! A disk that is full, and a folder the vault cannot write in: every write
//! fails as a whole, what was there stays readable, nothing received is
//! lost, and the vault works again once there is room.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tempfile::tempdir;

use crate::{EncryptedRevision, Error, Item, StageOutcome, Vault};

const PASSWORD: &str = "fault test password";

fn full(result: &crate::Result<impl std::fmt::Debug>) -> bool {
    matches!(
        result,
        Err(Error::Database(rusqlite::Error::SqliteFailure(failure, _)))
            if failure.code == rusqlite::ErrorCode::DiskFull
    )
}

/// What the owner sees: every item as it reads.
fn shown(vault: &Vault) -> Vec<String> {
    vault
        .list()
        .unwrap()
        .into_iter()
        .map(|summary| serde_json::to_string(&vault.get(&summary.id).unwrap().item).unwrap())
        .collect()
}

/// A vault, and a second device of it whose revisions the vault accepts.
fn two_devices(dir: &std::path::Path) -> (Vault, Vault) {
    let (mut vault, recovery) = Vault::create(dir.join("vault.sqlite3"), PASSWORD).unwrap();
    vault.put(Item::new("There from the start")).unwrap();
    vault.export_backup(dir.join("backup.json")).unwrap();
    let second = Vault::restore_backup(
        dir.join("backup.json"),
        dir.join("second.sqlite3"),
        &recovery,
        PASSWORD,
    )
    .unwrap();
    vault
        .authorize_device(
            second.device_id().unwrap(),
            second.device_public_key().unwrap(),
        )
        .unwrap();
    (vault, second)
}

/// A revision the second device writes, as the vault would receive it.
fn written_by(second: &mut Vault, title: &str) -> EncryptedRevision {
    let mut item = Item::new(title);
    item.notes = "x".repeat(2000);
    let id = second.put(item).unwrap().revision;
    second.revisions_by_id(&[id]).unwrap().remove(0)
}

#[test]
fn a_full_disk_fails_a_write_whole_and_the_vault_works_again_with_room() {
    let dir = tempdir().unwrap();
    let (mut vault, _) = two_devices(dir.path());
    let before = shown(&vault);
    vault.limit_growth_for_tests(0);

    let mut item = Item::new("Does not fit");
    item.notes = "n".repeat(64 * 1024);
    let attempt = vault.put(item.clone());
    assert!(full(&attempt), "{attempt:?}");
    assert_eq!(shown(&vault), before);
    let found = vault.get(&vault.list().unwrap()[0].id).unwrap();
    let mut edited = found.item.clone();
    edited.notes = "n".repeat(64 * 1024);
    assert!(full(&vault.update(edited.clone(), &found.revision)));
    assert_eq!(shown(&vault), before);

    // Reopened, it is as it was, and with room again it takes the writes.
    drop(vault);
    let mut vault = Vault::open(dir.path().join("vault.sqlite3")).unwrap();
    vault.unlock(PASSWORD).unwrap();
    assert_eq!(shown(&vault), before);
    vault.put(item).unwrap();
    vault.update(edited, &found.revision).unwrap();
}

#[test]
fn a_full_disk_loses_nothing_received_and_processing_resumes_with_room() {
    let dir = tempdir().unwrap();
    let (mut vault, mut second) = two_devices(dir.path());
    let revisions: Vec<EncryptedRevision> = (0..6)
        .map(|n| written_by(&mut second, &format!("Received {n}")))
        .collect();

    // Received while locked until the disk is full: what fits is kept, and
    // the one that does not is refused rather than half stored.
    vault.lock();
    vault.limit_growth_for_tests(3);
    let mut staged = 0;
    let mut refused = None;
    for revision in &revisions {
        match vault.stage_revision(revision.clone()) {
            Ok(StageOutcome::Staged) => staged += 1,
            other => {
                assert!(full(&other), "{other:?}");
                refused = Some(revision.clone());
                break;
            }
        }
    }
    let refused = refused.expect("the disk never filled");
    assert!(staged > 0);
    assert_eq!(vault.staged_revision_ids().unwrap().len(), staged);

    // Processing on a full disk applies what fits, each revision in one
    // transaction, and stops at the first that does not, without dropping
    // anything.
    vault.unlock(PASSWORD).unwrap();
    vault.limit_growth_for_tests(0);
    let before = shown(&vault);
    assert!(full(&vault.process_staged().map(|_| ())));
    let waiting = vault.staged_revision_ids().unwrap().len();
    assert!(waiting > 0);
    assert_eq!(shown(&vault).len(), before.len() + (staged - waiting));

    // With room, everything received is applied, and the refused one can
    // be received again.
    drop(vault);
    let mut vault = Vault::open(dir.path().join("vault.sqlite3")).unwrap();
    vault.unlock(PASSWORD).unwrap();
    assert_eq!(vault.process_staged().unwrap().applied, waiting);
    assert_eq!(vault.stage_revision(refused).unwrap(), StageOutcome::Staged);
    vault.process_staged().unwrap();
    assert_eq!(shown(&vault).len(), before.len() + staged + 1);
    assert!(vault.staged_revision_ids().unwrap().is_empty());
}

// A folder is made unwritable by its Unix mode; Windows has no such mode.
#[cfg(unix)]
#[test]
fn a_folder_the_vault_cannot_write_in_fails_writes_whole() {
    let dir = tempdir().unwrap();
    let (mut vault, mut second) = two_devices(dir.path());
    let revision = written_by(&mut second, "Received while the folder is closed");
    let before = shown(&vault);

    // No journal can be made beside the file, so no write can start.
    let folder = dir.path();
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o500)).unwrap();
    let put = vault.put(Item::new("Not written"));
    let received = vault.apply_encrypted_revision(revision.clone());
    vault.lock();
    let staged = vault.stage_revision(revision.clone());
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(put, Err(Error::Database(_))), "{put:?}");
    assert!(matches!(received, Err(Error::Database(_))), "{received:?}");
    assert!(matches!(staged, Err(Error::Database(_))), "{staged:?}");

    vault.unlock(PASSWORD).unwrap();
    assert_eq!(shown(&vault), before);
    assert!(vault.staged_revision_ids().unwrap().is_empty());
    vault.apply_encrypted_revision(revision).unwrap();
    vault.put(Item::new("Written")).unwrap();
    assert_eq!(shown(&vault).len(), before.len() + 2);
}
