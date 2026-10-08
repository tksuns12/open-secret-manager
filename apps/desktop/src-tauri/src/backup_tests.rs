//! The disaster-recovery exercise, through the real commands on the mock
//! runtime: a backup saved on one device brings the vault back on a new
//! one after every device is lost, a vault file that cannot be opened is
//! put away first, and a forgotten password is replaced with the recovery
//! key. `docs/disaster-recovery.md` is the owner's version of the same.

use osm_vault_core::{Item, Vault};
use tauri::Manager;

use crate::{
    archive, backup, lock_vault,
    network::{self, Restored},
    network_tests::{devices, eventually, pair, record, shell, titles, vault_id, PASSWORD},
    unlock_vault, AppState,
};

const NEW_PASSWORD: &str = "password for the new computer";

fn mail(password: &str) -> Item {
    let mut item = Item::new("Mail");
    item.id = "mail".into();
    item.username = "owner@example.test".into();
    item.password = password.into();
    item
}

/// The refusal's code. What a success holds is not printed: a restore's
/// holds a recovery key.
fn code<T>(result: Result<T, crate::CommandError>) -> &'static str {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error.code,
    }
}

#[test]
fn after_every_device_is_lost_a_backup_and_the_recovery_key_bring_the_vault_back() {
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let apps: Vec<_> = dirs.iter().map(|dir| shell(dir.path())).collect();
    let codes = record(&apps[1], "pairing-code");
    let finished = record(&apps[1], "pairing-finished");
    let handles: Vec<_> = apps.iter().map(|app| app.handle().clone()).collect();
    // The owner's computer, a new computer, and a new second device.
    let (old, new, second) = (handles[0].clone(), handles[1].clone(), handles[2].clone());
    let saved_to = dirs[0].path().join("Open Secret Manager backup.osmbackup");
    let new_dir = dirs[1].path().to_owned();

    tauri::async_runtime::block_on(async move {
        // A vault with an item edited twice and another deleted.
        let recovery_key = crate::create_vault(PASSWORD.into(), old.state(), old.clone())
            .await
            .unwrap();
        {
            let state = old.state::<AppState>();
            let mut vault = state.vault.lock().await;
            let vault = vault.as_mut().unwrap();
            let first = vault.put(mail("first password")).unwrap();
            let second = vault
                .update(mail("second password"), &first.revision)
                .unwrap();
            vault
                .update(mail("third password"), &second.revision)
                .unwrap();
            let gone = vault.put(Item::new("Old note")).unwrap();
            vault.delete(&gone.item_id, &gone.revision).unwrap();
            vault.put(Item::new("Bank")).unwrap();
        }
        let old_vault = vault_id(&old).await;

        // The backup is read back as soon as it is written, and its time is
        // noted for the reminder. An existing file is never replaced.
        let age = || async { backup::backup_age(old.state()).await.unwrap() };
        assert_eq!(age().await.days, None);
        let saved = backup::write(&old.state(), &saved_to).await.unwrap();
        assert_eq!((saved.items, saved.revisions, saved.held), (3, 6, 0));
        assert_eq!((age().await.days, age().await.due), (Some(0), false));
        let written = std::fs::read(&saved_to).unwrap();
        assert_eq!(code(backup::write(&old.state(), &saved_to).await), "exists");
        assert_eq!(std::fs::read(&saved_to).unwrap(), written);
        lock_vault(old.state()).await.unwrap();
        assert_eq!(code(backup::write(&old.state(), &saved_to).await), "locked");

        // The computer is lost.
        network::shutdown(&old).await;

        // On the new computer: a backup must be chosen, the key must be one,
        // and the key of another vault opens nothing and leaves nothing.
        let restore = |key: &str, password: &str| {
            backup::restore_backup(key.into(), password.into(), new.state(), new.clone())
        };
        assert_eq!(
            code(restore(&recovery_key, NEW_PASSWORD).await),
            "no_backup"
        );
        *new.state::<AppState>().chosen_backup.lock().unwrap() = Some(saved_to.clone());
        assert_eq!(
            code(restore("not a recovery key", NEW_PASSWORD).await),
            "invalid_recovery_key"
        );
        let other_vaults_key = Vault::create(new_dir.join("elsewhere.sqlite3"), "x")
            .unwrap()
            .1
            .to_string();
        std::fs::remove_file(new_dir.join("elsewhere.sqlite3")).unwrap();
        assert_eq!(
            code(restore(&other_vaults_key, NEW_PASSWORD).await),
            "invalid_credentials"
        );
        assert!(new.state::<AppState>().vault.lock().await.is_none());
        assert!(!new_dir.join("vault.sqlite3").exists());
        assert!(archive::list_archives(new.state())
            .await
            .unwrap()
            .is_empty());

        let restored: Restored = restore(&recovery_key, NEW_PASSWORD).await.unwrap();
        assert_eq!(
            (
                restored.items,
                restored.conflicts,
                restored.held_left_behind
            ),
            (2, 0, 0)
        );
        assert!(restored.recovery_key.starts_with("OSM-RK1-"));
        assert_ne!(restored.recovery_key, recovery_key);

        // A new vault, unlocked, with the items as they were last, this
        // device its only member, and its own recovery key kept until the
        // owner confirms having stored it.
        assert_eq!(titles(&new).await, ["Bank", "Mail"]);
        {
            let state = new.state::<AppState>();
            let vault = state.vault.lock().await;
            let vault = vault.as_ref().unwrap();
            assert_eq!(vault.get("mail").unwrap().item.password, "third password");
            assert_ne!(vault.vault_id(), old_vault);
        }
        let info = devices(&new).await;
        assert_eq!((info.setup, info.members.len()), ("ready", 1));
        assert_eq!(
            crate::pending_recovery_key(new.state()).await.unwrap(),
            Some(restored.recovery_key.clone())
        );

        // The backup as it was, history included, is in the archive, where
        // the new password opens it; so does the old recovery key.
        let archives = archive::list_archives(new.state()).await.unwrap();
        assert_eq!(archives.len(), 1);
        assert!(archives[0].has_vault);
        assert_eq!(
            std::path::Path::new(&restored.archive).file_name().unwrap(),
            archives[0].name.as_str()
        );
        let shown =
            archive::open_archive(archives[0].name.clone(), NEW_PASSWORD.into(), new.state())
                .await
                .unwrap();
        assert_eq!(shown.len(), 2);
        archive::close_archive(new.state()).await.unwrap();
        {
            let mut copy =
                Vault::open(new_dir.join(&archives[0].name).join("vault.sqlite3")).unwrap();
            copy.unlock_with_recovery(&osm_vault_core::RecoveryKey::parse(&recovery_key).unwrap())
                .unwrap();
            assert_eq!(copy.vault_id(), old_vault);
            assert_eq!(copy.encrypted_revisions().unwrap().len(), 6);
            assert_eq!(copy.versions("mail").unwrap().len(), 1);
        }

        // Only a device without a vault restores.
        assert_eq!(
            code(restore(&recovery_key, NEW_PASSWORD).await),
            "vault_exists"
        );

        // Another new device joins the restored vault and receives it.
        pair(
            &new,
            &codes,
            &finished,
            0,
            &second,
            Some("second device password"),
        )
        .await;
        eventually(&second, &["Bank", "Mail"]).await;
        // It joined without recovery, so it cannot write a backup yet.
        assert_eq!(
            code(backup::write(&second.state(), &dirs[2].path().join("b.osmbackup")).await),
            "recovery_not_enabled"
        );
    });
}

#[test]
fn a_vault_file_that_cannot_be_opened_is_put_away_before_anything_else() {
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let saved_to = source.path().join("backup.osmbackup");
    let recovery = {
        let (mut vault, recovery) =
            Vault::create(source.path().join("vault.sqlite3"), PASSWORD).unwrap();
        vault.put(Item::new("Kept")).unwrap();
        vault.export_backup(&saved_to).unwrap();
        recovery.to_string()
    };
    // What is left of this device's vault is not a vault.
    std::fs::write(target.path().join("vault.sqlite3"), b"not a vault any more").unwrap();
    let app = shell(target.path());
    let handle = app.handle().clone();

    tauri::async_runtime::block_on(async move {
        assert_eq!(
            crate::vault_status(handle.state()).await.unwrap(),
            "missing"
        );
        assert!(crate::vault_problem(handle.state())
            .await
            .unwrap()
            .is_some());
        // Nothing is made over it.
        *handle.state::<AppState>().chosen_backup.lock().unwrap() = Some(saved_to);
        let restore = || {
            backup::restore_backup(
                recovery.clone(),
                NEW_PASSWORD.into(),
                handle.state(),
                handle.clone(),
            )
        };
        assert_eq!(code(restore().await), "unreadable_vault");
        assert!(
            crate::create_vault(PASSWORD.into(), handle.state(), handle.clone())
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read(target.path().join("vault.sqlite3")).unwrap(),
            b"not a vault any more"
        );

        // Put away, with the files that belong to it, nothing deleted.
        let put_away = std::path::PathBuf::from(
            network::put_unreadable_away(handle.state(), handle.clone())
                .await
                .unwrap(),
        );
        assert_eq!(
            std::fs::read(put_away.join("vault.sqlite3")).unwrap(),
            b"not a vault any more"
        );
        assert!(put_away.join("peers.sqlite3").exists());
        assert_eq!(crate::vault_problem(handle.state()).await.unwrap(), None);
        assert_eq!(
            code(network::put_unreadable_away(handle.state(), handle.clone()).await),
            "not_unreadable"
        );

        // Then the device restores like any device without a vault.
        restore().await.unwrap();
        assert_eq!(titles(&handle).await, ["Kept"]);
        let info = devices(&handle).await;
        assert_eq!((info.setup, info.members.len()), ("ready", 1));
        assert_eq!(
            archive::list_archives(handle.state()).await.unwrap().len(),
            2
        );
    });
}

#[test]
fn a_forgotten_password_is_replaced_with_the_recovery_key() {
    let dir = tempfile::tempdir().unwrap();
    let app = shell(dir.path());
    let handle = app.handle().clone();

    tauri::async_runtime::block_on(async move {
        let recovery_key = crate::create_vault(PASSWORD.into(), handle.state(), handle.clone())
            .await
            .unwrap();
        lock_vault(handle.state()).await.unwrap();
        let reset = |key: &str| {
            backup::reset_password(
                key.into(),
                NEW_PASSWORD.into(),
                handle.state(),
                handle.clone(),
            )
        };
        assert_eq!(
            code(reset("not a recovery key").await),
            "invalid_recovery_key"
        );
        let other_vaults_key = Vault::create(dir.path().join("elsewhere.sqlite3"), "x")
            .unwrap()
            .1
            .to_string();
        assert_eq!(code(reset(&other_vaults_key).await), "invalid_credentials");
        assert_eq!(crate::vault_status(handle.state()).await.unwrap(), "locked");

        reset(&recovery_key).await.unwrap();
        assert_eq!(
            crate::vault_status(handle.state()).await.unwrap(),
            "unlocked"
        );
        lock_vault(handle.state()).await.unwrap();
        assert_eq!(
            code(unlock_vault(PASSWORD.into(), handle.state(), handle.clone()).await),
            "invalid_credentials"
        );
        unlock_vault(NEW_PASSWORD.into(), handle.state(), handle.clone())
            .await
            .unwrap();
    });
}
