//! Desktop shells, each with its own vault, peer store, and control-plane
//! database, run a vault's control plane over localhost through the real
//! commands and events. The mock runtime stands in for the webview; the
//! network code is the shipped code.

use std::{
    path::Path,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use osm_vault_core::{Item, PendingDevice, Vault};
use osm_vault_peer::{Peer, PeerStore};
use tauri::{
    test::{mock_builder, mock_context, noop_assets, MockRuntime},
    App, AppHandle, Listener, Manager,
};
use tokio::sync::Mutex;

use crate::{archive, network, AppState};

const PASSWORD: &str = "device password";

fn shell(dir: &Path) -> App<MockRuntime> {
    let path = dir.join("vault.sqlite3");
    let network = network::Network::open(&path).unwrap();
    mock_builder()
        .manage(AppState {
            vault: Mutex::new(Vault::open(&path).ok()),
            archive: Mutex::new(None),
            path,
            network,
        })
        .build(mock_context(noop_assets()))
        .unwrap()
}

type Seen = Arc<StdMutex<Vec<String>>>;

fn record(app: &App<MockRuntime>, event: &str) -> Seen {
    let seen = Seen::default();
    let sink = seen.clone();
    app.listen_any(event, move |event| {
        sink.lock().unwrap().push(event.payload().to_owned());
    });
    seen
}

/// The `index`th payload of an event, once it has arrived.
async fn nth(seen: &Seen, index: usize) -> String {
    for _ in 0..600 {
        if let Some(payload) = seen.lock().unwrap().get(index).cloned() {
            return payload;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("event never arrived");
}

async fn titles(app: &AppHandle<MockRuntime>) -> Vec<String> {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().await;
    let mut titles: Vec<String> = vault
        .as_ref()
        .unwrap()
        .list()
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    titles.sort();
    titles
}

/// Polls until `app` lists exactly `expected`, failing after a minute.
async fn eventually(app: &AppHandle<MockRuntime>, expected: &[&str]) {
    for _ in 0..600 {
        if titles(app).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(titles(app).await, expected);
}

async fn put(app: &AppHandle<MockRuntime>, title: &str) {
    let state = app.state::<AppState>();
    let mut vault = state.vault.lock().await;
    vault.as_mut().unwrap().put(Item::new(title)).unwrap();
}

async fn devices(app: &AppHandle<MockRuntime>) -> network::DevicesInfo {
    network::devices(app.clone()).await.unwrap()
}

/// Polls until the devices `app` reports satisfy `wanted`.
async fn until_devices(
    app: &AppHandle<MockRuntime>,
    what: &str,
    wanted: impl Fn(&network::DevicesInfo) -> bool,
) -> network::DevicesInfo {
    for _ in 0..600 {
        let info = devices(app).await;
        if wanted(&info) {
            return info;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never saw: {what}");
}

async fn current_epoch(app: &AppHandle<MockRuntime>) -> u64 {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().await;
    vault.as_ref().unwrap().current_epoch()
}

/// Invites a device on `inviter` and joins on `joiner`: the owner sees the
/// same code on both and confirms on each. `invites` counts the inviter's
/// earlier invitations in this test.
async fn pair(
    inviter: &AppHandle<MockRuntime>,
    codes: &Seen,
    finished: &Seen,
    invites: usize,
    joiner: &AppHandle<MockRuntime>,
    password: Option<&str>,
) {
    let invitation = network::start_invite(inviter.state(), inviter.clone())
        .await
        .unwrap();
    let joining = network::join_start(invitation.code.clone(), joiner.state(), joiner.clone())
        .await
        .unwrap();
    assert_eq!(joining.keeps_vault, password.is_none());
    assert_eq!(nth(codes, invites).await, format!("\"{}\"", joining.sas));
    network::confirm_invite(true, inviter.state())
        .await
        .unwrap();
    network::join_finish(password.map(Into::into), joiner.state(), joiner.clone())
        .await
        .unwrap();
    assert!(nth(finished, invites).await.contains("\"paired\":true"));
}

#[test]
fn desktop_shells_enroll_sync_remove_and_refuse_without_quorum() {
    let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
    let apps: Vec<_> = dirs.iter().map(|dir| shell(dir.path())).collect();
    let a_codes = record(&apps[0], "pairing-code");
    let a_finished = record(&apps[0], "pairing-finished");
    let b_codes = record(&apps[1], "pairing-code");
    let b_finished = record(&apps[1], "pairing-finished");
    let handles: Vec<_> = apps.iter().map(|app| app.handle().clone()).collect();
    let (a, b, c, d) = (
        handles[0].clone(),
        handles[1].clone(),
        handles[2].clone(),
        handles[3].clone(),
    );

    tauri::async_runtime::block_on(async move {
        // Creating a vault founds its control plane with one member.
        assert_eq!(devices(&a).await.setup, "none");
        crate::create_vault(PASSWORD.into(), a.state(), a.clone())
            .await
            .unwrap();
        put(&a, "Shared").await;
        let info = devices(&a).await;
        assert_eq!(
            (info.setup, info.members.len(), info.epoch),
            ("ready", 1, 1)
        );
        let a_id = info.this_device.clone().unwrap();

        // B joins through A; C joins through B, which is not the leader.
        pair(&a, &a_codes, &a_finished, 0, &b, Some("joiner password")).await;
        eventually(&b, &["Shared"]).await;
        pair(&b, &b_codes, &b_finished, 0, &c, Some("third password")).await;
        eventually(&c, &["Shared"]).await;
        for app in [&a, &b, &c] {
            until_devices(app, "three members", |info| {
                info.setup == "ready" && info.members.len() == 3 && info.pending.is_none()
            })
            .await;
        }
        let b_id = devices(&b).await.this_device.unwrap();
        let c_id = devices(&c).await.this_device.unwrap();
        assert!(devices(&a)
            .await
            .members
            .iter()
            .any(|member| member.id == c_id && !member.this_device));

        // A change on any device reaches the others automatically.
        put(&a, "Added on A").await;
        network::schedule_sync(&a);
        eventually(&b, &["Added on A", "Shared"]).await;
        eventually(&c, &["Added on A", "Shared"]).await;
        put(&c, "Added on C").await;
        network::schedule_sync(&c);
        eventually(&a, &["Added on A", "Added on C", "Shared"]).await;
        eventually(&b, &["Added on A", "Added on C", "Shared"]).await;

        // A is locked. It still takes part: B removes C, which needs two of
        // the three devices to agree.
        crate::lock_vault(a.state()).await.unwrap();
        network::remove_device(c_id.clone(), b.clone())
            .await
            .unwrap();
        for app in [&a, &b] {
            until_devices(app, "the removal completes", |info| {
                info.epoch == 2 && info.members.len() == 2 && info.pending.is_none()
            })
            .await;
        }
        for _ in 0..100 {
            if current_epoch(&b).await == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(current_epoch(&b).await, 2);
        // Locked, A can only stop writing under the old key.
        assert_eq!(current_epoch(&a).await, 1);

        // B writes under the new key; A receives it while locked, along
        // with B's endorsement of the removed device's last edit. At unlock
        // A takes the removal and the new key in first, then reads them.
        put(&b, "After removal").await;
        network::sync_now(b.clone()).await.unwrap();
        {
            let state = a.state::<AppState>();
            let vault = state.vault.lock().await;
            assert_eq!(
                vault.as_ref().unwrap().staged_revision_ids().unwrap().len(),
                2
            );
        }
        crate::unlock_vault(PASSWORD.into(), a.state(), a.clone())
            .await
            .unwrap();
        assert_eq!(current_epoch(&a).await, 2);
        assert_eq!(
            titles(&a).await,
            ["Added on A", "Added on C", "After removal", "Shared"]
        );

        // C learns that it was removed and is reset at once: its copy,
        // which never got the new key or anything written since, is moved
        // aside, and C is a device without a vault again.
        let reset = until_devices(&c, "C is reset after its removal", |info| {
            info.setup == "none" && info.reset_archive.is_some()
        })
        .await;
        assert!(c.state::<AppState>().vault.lock().await.is_none());
        let archive = std::path::PathBuf::from(reset.reset_archive.unwrap());
        let mut archived = Vault::open(archive.join("vault.sqlite3")).unwrap();
        archived.unlock("third password").unwrap();
        assert_eq!(archived.current_epoch(), 1);
        let mut kept: Vec<String> = archived
            .list()
            .unwrap()
            .into_iter()
            .map(|item| item.title)
            .collect();
        kept.sort();
        assert_eq!(kept, ["Added on A", "Added on C", "Shared"]);
        drop(archived);
        let refused = network::start_invite(c.state(), c.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(refused.code, "unmanaged");

        // D starts joining but never finishes. Its enrollment stays
        // pending until a member cancels it; D never received a key.
        let invitation = network::start_invite(a.state(), a.clone()).await.unwrap();
        let joining = network::join_start(invitation.code.clone(), d.state(), d.clone())
            .await
            .unwrap();
        assert_eq!(nth(&a_codes, 1).await, format!("\"{}\"", joining.sas));
        assert_eq!(devices(&d).await.setup, "joining");
        network::confirm_invite(true, a.state()).await.unwrap();
        assert!(nth(&a_finished, 1).await.contains("\"paired\":true"));
        let stalled =
            until_devices(&a, "a pending enrollment", |info| info.pending.is_some()).await;
        assert_eq!(stalled.pending.unwrap().kind, "enroll");
        network::cancel_enrollment(a.clone()).await.unwrap();
        for app in [&a, &b] {
            until_devices(app, "the enrollment is cancelled", |info| {
                info.pending.is_none() && info.members.len() == 2
            })
            .await;
        }
        network::cancel_join(d.state(), d.clone()).await.unwrap();
        assert_eq!(devices(&d).await.setup, "none");
        assert!(d.state::<AppState>().vault.lock().await.is_none());

        // B goes away. With two members both are needed: A cannot remove B,
        // is told why, and nothing changes.
        network::shutdown(&b).await;
        let refused = network::remove_device(b_id.clone(), a.clone())
            .await
            .unwrap_err();
        assert_eq!(refused.code, "quorum_unavailable");
        let info = devices(&a).await;
        assert_eq!((info.members.len(), info.epoch, info.quorum), (2, 2, 2));
        assert!(info.members.iter().any(|member| member.id == b_id));
        assert!(info
            .members
            .iter()
            .any(|member| member.id == a_id && member.this_device));
        for app in [&a, &c, &d] {
            network::shutdown(app).await;
        }
    });
}

#[test]
fn a_pair_from_an_older_build_moves_onto_the_control_plane() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // What an older build left behind: two vaults that accept each other's
    // revisions, each peer store naming the other device, no control plane.
    let (mut vault_a, _) = Vault::create(dir_a.path().join("vault.sqlite3"), PASSWORD).unwrap();
    let device = PendingDevice::generate();
    let material = vault_a.enrollment_material().unwrap();
    vault_a
        .authorize_device(device.device_id(), device.public_key())
        .unwrap();
    let mut vault_b = Vault::join(
        dir_b.path().join("vault.sqlite3"),
        PASSWORD,
        device,
        material,
    )
    .unwrap();
    vault_a.put(Item::new("From A")).unwrap();
    vault_b.put(Item::new("Unsynced on B")).unwrap();
    let b_device = vault_b.device_id().unwrap();
    {
        let mut peers_a = PeerStore::open(dir_a.path().join("peers.sqlite3")).unwrap();
        let mut peers_b = PeerStore::open(dir_b.path().join("peers.sqlite3")).unwrap();
        let pin_a = peers_a.transport_identity().unwrap().pin();
        let pin_b = peers_b.transport_identity().unwrap().pin();
        peers_a
            .insert_legacy_peer(&Peer {
                device_id: b_device,
                public_key: vault_b.device_public_key().unwrap(),
                transport_pin: pin_b,
                address: None,
                paired_at: 1,
            })
            .unwrap();
        peers_b
            .insert_legacy_peer(&Peer {
                device_id: vault_a.device_id().unwrap(),
                public_key: vault_a.device_public_key().unwrap(),
                transport_pin: pin_a,
                address: None,
                paired_at: 1,
            })
            .unwrap();
    }
    drop((vault_a, vault_b));

    let (app_a, app_b) = (shell(dir_a.path()), shell(dir_b.path()));
    let codes = record(&app_a, "pairing-code");
    let finished = record(&app_a, "pairing-finished");
    let (a, b) = (app_a.handle().clone(), app_b.handle().clone());
    tauri::async_runtime::block_on(async move {
        // Unlocking does not set device management up on its own here: the
        // owner chooses which of the two devices does.
        for app in [&a, &b] {
            crate::unlock_vault(PASSWORD.into(), app.state(), app.clone())
                .await
                .unwrap();
            assert_eq!(devices(app).await.setup, "paired-before");
        }
        network::found_control_plane(a.clone()).await.unwrap();
        let info = devices(&a).await;
        assert_eq!((info.setup, info.members.len()), ("ready", 1));

        // B joins with the vault it has: no new password, the same device,
        // and its unsynced edit survives and reaches A.
        pair(&a, &codes, &finished, 0, &b, None).await;
        for app in [&a, &b] {
            until_devices(app, "two members", |info| {
                info.setup == "ready" && info.members.len() == 2 && info.pending.is_none()
            })
            .await;
        }
        let hex: String = b_device.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(devices(&b).await.this_device, Some(hex));
        eventually(&a, &["From A", "Unsynced on B"]).await;
        eventually(&b, &["From A", "Unsynced on B"]).await;

        // It cannot be set up twice.
        let refused = network::found_control_plane(b.clone()).await.unwrap_err();
        assert_eq!(refused.code, "already_managed");
        for app in [&a, &b] {
            network::shutdown(app).await;
        }
    });
}

#[test]
fn an_existing_vault_is_set_up_at_unlock_and_resumes_while_locked() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = Vault::create(dir.path().join("vault.sqlite3"), PASSWORD).unwrap();
    vault.put(Item::new("Before")).unwrap();
    drop(vault);

    // A vault from before device management, never paired: unlocking sets
    // it up with this device as the only member.
    let app = shell(dir.path());
    let handle = app.handle().clone();
    tauri::async_runtime::block_on(async move {
        assert_eq!(devices(&handle).await.setup, "unmanaged");
        crate::unlock_vault(PASSWORD.into(), handle.state(), handle.clone())
            .await
            .unwrap();
        let info = devices(&handle).await;
        assert_eq!(
            (info.setup, info.members.len(), info.epoch),
            ("ready", 1, 1)
        );
        network::shutdown(&handle).await;
    });
    drop(app);

    // The app starts again and stays locked: the control plane runs anyway.
    let app = shell(dir.path());
    let handle = app.handle().clone();
    tauri::async_runtime::block_on(async move {
        network::start(&handle);
        let info = until_devices(&handle, "the control plane resumes", |info| {
            info.setup == "ready"
        })
        .await;
        assert_eq!(info.members.len(), 1);
        let state = handle.state::<AppState>();
        assert!(!state.vault.lock().await.as_ref().unwrap().is_unlocked());
        network::shutdown(&handle).await;
    });
}

/// A device that was removed keeps writing before it has heard. Its changes
/// reach the members through one that had not heard either, and are held.
/// The owner reviews them on one device; the others follow.
#[test]
fn changes_held_for_review_are_kept_or_rejected_on_every_device() {
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let apps: Vec<_> = dirs.iter().map(|dir| shell(dir.path())).collect();
    let codes = record(&apps[0], "pairing-code");
    let finished = record(&apps[0], "pairing-finished");
    let handles: Vec<_> = apps.iter().map(|app| app.handle().clone()).collect();
    let (a, b, d) = (handles[0].clone(), handles[1].clone(), handles[2].clone());

    async fn password_of(app: &AppHandle<MockRuntime>, title: &str) -> String {
        let state = app.state::<AppState>();
        let vault = state.vault.lock().await;
        let vault = vault.as_ref().unwrap();
        let id = vault
            .list()
            .unwrap()
            .into_iter()
            .find(|item| item.title == title)
            .unwrap()
            .id;
        vault.get(&id).unwrap().item.password.clone()
    }

    tauri::async_runtime::block_on(async move {
        crate::create_vault(PASSWORD.into(), a.state(), a.clone())
            .await
            .unwrap();
        put(&a, "Shared").await;
        pair(&a, &codes, &finished, 0, &b, Some("joiner password")).await;
        pair(&a, &codes, &finished, 1, &d, Some("third password")).await;
        for app in [&a, &b, &d] {
            until_devices(app, "three members", |info| {
                info.setup == "ready" && info.members.len() == 3 && info.pending.is_none()
            })
            .await;
            eventually(app, &["Shared"]).await;
        }
        let d_id = devices(&d).await.this_device.unwrap();

        // D is closed and then removed, so it does not hear of it.
        network::shutdown(&d).await;
        network::remove_device(d_id.clone(), a.clone())
            .await
            .unwrap();
        for app in [&a, &b] {
            until_devices(app, "the removal completes", |info| {
                info.epoch == 2 && info.members.len() == 2 && info.pending.is_none()
            })
            .await;
            for _ in 0..100 {
                if current_epoch(app).await == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(current_epoch(app).await, 2);
        }

        // D adds an item and changes a password.
        let late = {
            let state = d.state::<AppState>();
            let mut vault = state.vault.lock().await;
            let vault = vault.as_mut().unwrap();
            vault.put(Item::new("Made after removal")).unwrap();
            let shared = vault
                .list()
                .unwrap()
                .into_iter()
                .find(|item| item.title == "Shared")
                .unwrap();
            let mut changed = vault.get(&shared.id).unwrap().item.clone();
            changed.password = "changed by the removed device".into();
            vault.update(changed, &shared.revision).unwrap();
            let author = vault.device_id().unwrap();
            let late: Vec<_> = vault
                .encrypted_revisions()
                .unwrap()
                .into_iter()
                .filter(|revision| revision.author_device_id == author)
                .collect();
            assert_eq!(late.len(), 2);
            late
        };
        // They arrive as they would through a device that had taken them
        // in: staged, then verified against committed membership.
        for app in [&a, &b] {
            let state = app.state::<AppState>();
            let mut vault = state.vault.lock().await;
            let vault = vault.as_mut().unwrap();
            for revision in &late {
                vault.stage_revision(revision.clone()).unwrap();
            }
            let processed = vault.process_staged().unwrap();
            assert_eq!((processed.applied, processed.quarantined), (0, 2));
        }
        assert_eq!(titles(&a).await, ["Shared"]);

        // The owner sees what each one would change, without the secrets.
        let held = crate::list_held(a.state()).await.unwrap();
        assert_eq!(held.len(), 2);
        assert!(held.iter().all(|change| change.removed_device));
        assert!(held.iter().all(|change| d_id.starts_with(&change.device)));
        let created = held.iter().find(|change| change.change == "new").unwrap();
        assert_eq!(created.title, "Made after removal");
        let edited = held.iter().find(|change| change.change == "edit").unwrap();
        assert_eq!(
            (edited.title.as_str(), &edited.changed),
            ("Shared", &vec!["password"])
        );

        // One is kept and one rejected, on A.
        crate::accept_held(created.revision.clone(), a.state(), a.clone())
            .await
            .unwrap();
        crate::discard_held(edited.revision.clone(), a.state(), a.clone())
            .await
            .unwrap();
        assert!(crate::list_held(a.state()).await.unwrap().is_empty());
        assert_eq!(titles(&a).await, ["Made after removal", "Shared"]);
        assert_eq!(password_of(&a, "Shared").await, "");
        let again = crate::accept_held(edited.revision.clone(), a.state(), a.clone())
            .await
            .unwrap_err();
        assert_eq!(again.code, "not_found");

        // B, which held the same two, follows without being asked.
        eventually(&b, &["Made after removal", "Shared"]).await;
        for _ in 0..100 {
            if crate::list_held(b.state()).await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(crate::list_held(b.state()).await.unwrap().is_empty());
        assert_eq!(password_of(&b, "Shared").await, "");
        assert!(!{
            let state = b.state::<AppState>();
            let vault = state.vault.lock().await;
            let conflict = vault
                .as_ref()
                .unwrap()
                .list()
                .unwrap()
                .iter()
                .any(|item| item.conflict);
            conflict
        });

        // A locked vault shows nothing to review.
        crate::lock_vault(a.state()).await.unwrap();
        let locked = crate::list_held(a.state()).await.err().unwrap();
        assert_eq!(locked.code, "locked");
        for app in [&a, &b, &d] {
            network::shutdown(app).await;
        }
    });
}

async fn vault_id(app: &AppHandle<MockRuntime>) -> [u8; 32] {
    let state = app.state::<AppState>();
    let vault = state.vault.lock().await;
    vault.as_ref().unwrap().vault_id()
}

#[test]
fn a_vault_that_lost_a_device_starts_over_as_a_new_vault() {
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let apps: Vec<_> = dirs.iter().map(|dir| shell(dir.path())).collect();
    let codes = record(&apps[0], "pairing-code");
    let finished = record(&apps[0], "pairing-finished");
    let handles: Vec<_> = apps.iter().map(|app| app.handle().clone()).collect();
    let (a, b, c) = (handles[0].clone(), handles[1].clone(), handles[2].clone());
    let a_dir = dirs[0].path().to_owned();
    let b_dir = dirs[1].path().to_owned();

    tauri::async_runtime::block_on(async move {
        // A new vault keeps its recovery key until the owner confirms
        // having stored it.
        let first_key = crate::create_vault(PASSWORD.into(), a.state(), a.clone())
            .await
            .unwrap();
        assert_eq!(
            crate::pending_recovery_key(a.state()).await.unwrap(),
            Some(first_key)
        );
        crate::confirm_recovery_key(a.state()).await.unwrap();
        assert_eq!(crate::pending_recovery_key(a.state()).await.unwrap(), None);
        put(&a, "From A").await;
        pair(&a, &codes, &finished, 0, &b, Some("joiner password")).await;
        eventually(&b, &["From A"]).await;
        put(&b, "From B").await;
        network::schedule_sync(&b);
        eventually(&a, &["From A", "From B"]).await;
        until_devices(&a, "two members", |info| {
            info.members.len() == 2 && info.pending.is_none()
        })
        .await;
        let old_vault = vault_id(&a).await;
        let old_device = devices(&a).await.this_device.unwrap();
        let b_id = devices(&b).await.this_device.unwrap();

        // B is lost. Two devices need both for any change, so A cannot
        // remove it.
        network::shutdown(&b).await;
        let refused = network::remove_device(b_id.clone(), a.clone())
            .await
            .unwrap_err();
        assert_eq!(refused.code, "quorum_unavailable");

        // Starting over asks for the password; a wrong one changes nothing.
        let wrong = network::recover_vault("not the password".into(), a.state(), a.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(wrong.code, "invalid_credentials");
        assert_eq!(vault_id(&a).await, old_vault);
        assert_eq!(devices(&a).await.members.len(), 2);

        let recovered = network::recover_vault(PASSWORD.into(), a.state(), a.clone())
            .await
            .unwrap();
        assert_eq!((recovered.items, recovered.conflicts), (2, 0));
        assert!(recovered.recovery_key.starts_with("OSM-RK1-"));

        // A new vault: new identity, this device its only member, the same
        // contents, unlocked under the same password.
        assert_ne!(vault_id(&a).await, old_vault);
        let info = devices(&a).await;
        assert_eq!(
            (info.setup, info.members.len(), info.epoch),
            ("ready", 1, 1)
        );
        assert_ne!(info.this_device.clone().unwrap(), old_device);
        assert_eq!(titles(&a).await, ["From A", "From B"]);
        {
            let state = a.state::<AppState>();
            let mut vault = state.vault.lock().await;
            let vault = vault.as_mut().unwrap();
            assert_eq!(vault.encrypted_revisions().unwrap().len(), 2);
            vault.lock();
            vault.unlock(PASSWORD).unwrap();
        }
        // Its recovery key is still there after locking and unlocking,
        // until the owner confirms having stored it.
        assert_eq!(
            crate::pending_recovery_key(a.state()).await.unwrap(),
            Some(recovered.recovery_key.clone())
        );
        crate::confirm_recovery_key(a.state()).await.unwrap();
        assert_eq!(crate::pending_recovery_key(a.state()).await.unwrap(), None);

        // The old vault and its files were moved aside, not destroyed.
        let archive = std::path::PathBuf::from(&recovered.archive);
        assert_eq!(archive.parent(), Some(a_dir.as_path()));
        for file in ["vault.sqlite3", "control.sqlite3", "peers.sqlite3"] {
            assert!(archive.join(file).exists(), "{file} was not archived");
        }
        let mut archived = Vault::open(archive.join("vault.sqlite3")).unwrap();
        assert_eq!(archived.vault_id(), old_vault);
        archived.unlock(PASSWORD).unwrap();
        assert_eq!(archived.list().unwrap().len(), 2);
        assert!(!a_dir.join("recovered.sqlite3").exists());

        // The lost device turns up again. It is not part of the new vault:
        // it reaches no one, and A takes nothing from it.
        network::start(&b);
        until_devices(&b, "B's control plane resumes", |info| {
            info.setup == "ready"
        })
        .await;
        put(&b, "Written on the lost device").await;
        assert!(network::sync_now(b.clone()).await.is_err());
        assert_eq!(titles(&a).await, ["From A", "From B"]);
        assert_eq!(devices(&a).await.members.len(), 1);

        // Nothing removed B, so nothing resets it. The owner has its copy
        // put away, which takes B's password; a wrong one changes nothing,
        // and the only device of a vault has nothing to leave for.
        let wrong = network::leave_vault("not the password".into(), b.state(), b.clone())
            .await
            .unwrap_err();
        assert_eq!(wrong.code, "invalid_credentials");
        assert_eq!(vault_id(&b).await, old_vault);
        let alone = network::leave_vault(PASSWORD.into(), a.state(), a.clone())
            .await
            .unwrap_err();
        assert_eq!(alone.code, "only_device");
        let archive = network::leave_vault("joiner password".into(), b.state(), b.clone())
            .await
            .unwrap();
        let info = devices(&b).await;
        assert_eq!(
            (info.setup, info.reset_reason, info.reset_archive.as_deref()),
            ("none", Some("left"), Some(archive.as_str()))
        );
        assert!(b.state::<AppState>().vault.lock().await.is_none());
        // Its copy, with the edit that reached no one, is in the archive.
        let archive = std::path::PathBuf::from(archive);
        assert_eq!(archive.parent(), Some(b_dir.as_path()));
        let mut archived = Vault::open(archive.join("vault.sqlite3")).unwrap();
        assert_eq!(archived.vault_id(), old_vault);
        archived.unlock("joiner password").unwrap();
        assert_eq!(archived.list().unwrap().len(), 3);
        drop(archived);
        for gone in ["vault.sqlite3", "control.sqlite3", "putting-away"] {
            assert!(!b_dir.join(gone).exists(), "{gone} was left behind");
        }

        // Devices join the new vault by pairing, as with any vault: the one
        // that was left behind, and one that is new.
        pair(&a, &codes, &finished, 1, &b, Some("second password")).await;
        eventually(&b, &["From A", "From B"]).await;
        assert_eq!(devices(&b).await.reset_archive, None);
        assert!(!b_dir.join("left-vault").exists());
        for app in [&a, &b] {
            until_devices(app, "two members of the new vault", |info| {
                info.members.len() == 2 && info.pending.is_none()
            })
            .await;
        }
        pair(&a, &codes, &finished, 2, &c, Some("third password")).await;
        eventually(&c, &["From A", "From B"]).await;
        for app in [&b, &c] {
            assert_eq!(vault_id(app).await, vault_id(&a).await);
        }
        for app in [&a, &b, &c] {
            until_devices(app, "three members of the new vault", |info| {
                info.members.len() == 3 && info.pending.is_none()
            })
            .await;
        }
        for app in [&a, &b, &c] {
            network::shutdown(app).await;
        }
    });
}

#[test]
fn an_interrupted_recovery_is_finished_or_discarded_at_launch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite3");
    let (mut vault, _) = Vault::create(&path, PASSWORD).unwrap();
    vault.put(Item::new("Kept")).unwrap();
    let old_vault = vault.vault_id();
    std::fs::write(dir.path().join("control.sqlite3"), b"old control").unwrap();

    // Stopped while the new vault was still being written: it is discarded
    // and the vault is as it was.
    let partial = dir.path().join("recovered.sqlite3.partial");
    drop(vault.fork(&partial, PASSWORD).unwrap());
    network::finish_interrupted_recovery(&path);
    assert!(!partial.exists());
    assert_eq!(Vault::open(&path).unwrap().vault_id(), old_vault);
    assert!(dir.path().join("control.sqlite3").exists());

    // Stopped after the new vault was complete, before its recovery key
    // was shown: the swap is finished, and the key is still to be had.
    let (mut fork, recovery, _) = vault
        .fork(dir.path().join("recovered.sqlite3"), PASSWORD)
        .unwrap();
    fork.keep_recovery_key_until_confirmed(&recovery).unwrap();
    let new_vault = fork.vault_id();
    drop((fork, vault));
    network::finish_interrupted_recovery(&path);
    let mut current = Vault::open(&path).unwrap();
    assert_eq!(current.vault_id(), new_vault);
    current.unlock(PASSWORD).unwrap();
    assert_eq!(current.list().unwrap().len(), 1);
    assert_eq!(
        current
            .unconfirmed_recovery_key()
            .unwrap()
            .map(|kept| kept.to_string()),
        Some(recovery.to_string())
    );
    assert!(!dir.path().join("recovered.sqlite3").exists());
    assert!(!dir.path().join("control.sqlite3").exists());
    let archive = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("archive-"))
        .unwrap()
        .path();
    assert_eq!(
        Vault::open(archive.join("vault.sqlite3"))
            .unwrap()
            .vault_id(),
        old_vault
    );
    assert!(archive.join("control.sqlite3").exists());

    // Nothing to do on an ordinary launch.
    network::finish_interrupted_recovery(&path);
    assert_eq!(Vault::open(&path).unwrap().vault_id(), new_vault);
}

#[test]
fn a_removed_device_is_reset_and_joins_again() {
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (app_a, app_b) = (shell(dir_a.path()), shell(dir_b.path()));
    let codes = record(&app_a, "pairing-code");
    let finished = record(&app_a, "pairing-finished");
    let resets = record(&app_b, "device-reset");
    let (a, b) = (app_a.handle().clone(), app_b.handle().clone());
    let b_dir = dir_b.path().to_owned();

    tauri::async_runtime::block_on(async move {
        crate::create_vault(PASSWORD.into(), a.state(), a.clone())
            .await
            .unwrap();
        put(&a, "Shared").await;
        pair(&a, &codes, &finished, 0, &b, Some("joiner password")).await;
        eventually(&b, &["Shared"]).await;
        until_devices(&a, "two members", |info| {
            info.members.len() == 2 && info.pending.is_none()
        })
        .await;
        let old_b = devices(&b).await.this_device.unwrap();
        let old_vault_on_b = vault_id(&b).await;
        // B has an edit that never reaches A.
        put(&b, "Only on B").await;

        // A device that is still a member is never reset.
        let refused = network::reset_device(b.clone()).await.unwrap_err();
        assert_eq!(refused.code, "not_removed");

        // A removes B, and writes something B never gets.
        network::remove_device(old_b.clone(), a.clone())
            .await
            .unwrap();
        until_devices(&a, "the removal completes", |info| {
            info.epoch == 2 && info.members.len() == 1 && info.pending.is_none()
        })
        .await;
        for _ in 0..100 {
            if current_epoch(&a).await == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        put(&a, "After removal").await;

        // As soon as B learns of it, B is reset: its copy is moved to an
        // archive folder, untouched, and B is a device without a vault.
        let reset = until_devices(&b, "B is reset after its removal", |info| {
            info.setup == "none" && info.reset_archive.is_some()
        })
        .await;
        let archive = std::path::PathBuf::from(reset.reset_archive.unwrap());
        assert_eq!(
            nth(&resets, 0).await,
            format!("{:?}", archive.to_string_lossy())
        );
        assert_eq!(archive.parent(), Some(b_dir.as_path()));
        let mut archived = Vault::open(archive.join("vault.sqlite3")).unwrap();
        assert_eq!(archived.vault_id(), old_vault_on_b);
        archived.unlock("joiner password").unwrap();
        assert_eq!(archived.list().unwrap().len(), 2);
        drop(archived);
        assert!(archive.join("control.sqlite3").exists());
        for gone in ["vault.sqlite3", "control.sqlite3", "removed"] {
            assert!(!b_dir.join(gone).exists(), "{gone} was left behind");
        }
        assert!(b.state::<AppState>().vault.lock().await.is_none());
        assert_eq!(devices(&b).await.this_device, None);

        // It joins like any new device, and the note about the reset goes.
        pair(&a, &codes, &finished, 1, &b, Some("second password")).await;
        eventually(&b, &["After removal", "Shared"]).await;
        assert_eq!(current_epoch(&b).await, 2);
        for app in [&a, &b] {
            until_devices(app, "two members again", |info| {
                info.setup == "ready" && info.members.len() == 2 && info.pending.is_none()
            })
            .await;
        }
        assert_eq!(devices(&b).await.reset_archive, None);
        assert!(!b_dir.join("reset-after-removal").exists());
        // It is a new device to the vault: the old identity stays removed.
        let new_b = devices(&b).await.this_device.unwrap();
        assert_ne!(new_b, old_b);
        assert!(!devices(&a)
            .await
            .members
            .iter()
            .any(|member| member.id == old_b));

        // The copy that was put away still holds the edit that reached no
        // one. The owner opens it with the password it had and sees how
        // each item relates to the vault B has now.
        let archives = archive::list_archives(b.state()).await.unwrap();
        assert_eq!(archives.len(), 1);
        assert!(archives[0].has_vault);
        let name = archives[0].name.clone();
        let wrong = archive::open_archive(name.clone(), "second password".into(), b.state())
            .await
            .err()
            .unwrap();
        assert_eq!(wrong.code, "invalid_credentials");
        let relations = |items: &[archive::ArchivedItem]| -> Vec<(String, Option<&'static str>)> {
            items
                .iter()
                .map(|item| (item.title.clone(), item.relation))
                .collect()
        };
        let held = archive::open_archive(name.clone(), "joiner password".into(), b.state())
            .await
            .unwrap();
        assert_eq!(
            relations(&held),
            [
                ("Only on B".to_owned(), Some("absent")),
                ("Shared".to_owned(), Some("same"))
            ]
        );

        // Copied into the vault, the item is an ordinary item: it syncs.
        let after = archive::copy_from_archive(held[0].id.clone(), b.state(), b.clone())
            .await
            .unwrap();
        assert!(after.iter().all(|item| item.relation == Some("same")));
        for app in [&a, &b] {
            eventually(app, &["After removal", "Only on B", "Shared"]).await;
        }
        // An item the vault already has is copied under a telling title.
        archive::copy_from_archive(held[1].id.clone(), b.state(), b.clone())
            .await
            .unwrap();
        eventually(
            &b,
            &[
                "After removal",
                "Only on B",
                "Shared",
                "Shared (archived copy)",
            ],
        )
        .await;

        // Locking the vault closes the archived copy.
        crate::lock_vault(b.state()).await.unwrap();
        let closed = archive::copy_from_archive(held[0].id.clone(), b.state(), b.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(closed.code, "no_archive");

        // Only a folder this app made is ever opened or deleted.
        for bad in [
            "..",
            "../vault.sqlite3",
            "archive-",
            "archive-x",
            "archive-1-2-3",
        ] {
            let refused = archive::open_archive(bad.into(), "joiner password".into(), b.state())
                .await
                .err()
                .unwrap();
            assert_eq!(refused.code, "no_archive", "{bad}");
            let refused = archive::delete_archive(bad.into(), b.state(), b.clone())
                .await
                .unwrap_err();
            assert_eq!(refused.code, "no_archive", "{bad}");
        }
        assert!(b_dir.join("vault.sqlite3").exists());

        // Deleted, the copy is gone for good.
        archive::delete_archive(name.clone(), b.state(), b.clone())
            .await
            .unwrap();
        assert!(!archive.exists());
        assert!(archive::list_archives(b.state()).await.unwrap().is_empty());
        let gone = archive::delete_archive(name, b.state(), b.clone())
            .await
            .unwrap_err();
        assert_eq!(gone.code, "no_archive");
        for app in [&a, &b] {
            network::shutdown(app).await;
        }
    });
}

#[test]
fn a_reset_interrupted_after_removal_is_finished_at_launch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite3");
    let (mut vault, _) = Vault::create(&path, PASSWORD).unwrap();
    vault.put(Item::new("Kept in the archive")).unwrap();
    let old_vault = vault.vault_id();
    drop(vault);
    // The app stopped right after recording that this device was removed.
    std::fs::write(dir.path().join("control.sqlite3"), b"old control").unwrap();
    std::fs::write(dir.path().join("removed"), b"").unwrap();

    let app = shell(dir.path());
    let handle = app.handle().clone();
    let directory = dir.path().to_owned();
    tauri::async_runtime::block_on(async move {
        assert_eq!(devices(&handle).await.setup, "removed");
        network::start(&handle);
        let reset = until_devices(&handle, "the reset is finished", |info| {
            info.setup == "none" && info.reset_archive.is_some()
        })
        .await;
        let archive = std::path::PathBuf::from(reset.reset_archive.unwrap());
        assert_eq!(
            Vault::open(archive.join("vault.sqlite3"))
                .unwrap()
                .vault_id(),
            old_vault
        );
        for gone in ["vault.sqlite3", "control.sqlite3", "removed"] {
            assert!(!directory.join(gone).exists(), "{gone} was left behind");
        }

        // A new vault here is an ordinary vault: nothing of the removal
        // carries over to it.
        crate::create_vault(PASSWORD.into(), handle.state(), handle.clone())
            .await
            .unwrap();
        let info = devices(&handle).await;
        assert_eq!((info.setup, info.members.len()), ("ready", 1));
        assert_eq!(info.reset_archive, None);
        network::shutdown(&handle).await;
    });
}

#[test]
fn putting_a_copy_away_is_finished_at_launch_if_it_was_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite3");
    let (mut vault, _) = Vault::create(&path, PASSWORD).unwrap();
    vault.put(Item::new("Kept in the archive")).unwrap();
    let old_vault = vault.vault_id();
    drop(vault);
    std::fs::write(dir.path().join("control.sqlite3"), b"old control").unwrap();
    drop(PeerStore::open(dir.path().join("peers.sqlite3")).unwrap());
    let old_peers = std::fs::read(dir.path().join("peers.sqlite3")).unwrap();

    // The app stopped after moving the vault file and before the rest.
    let archive = dir.path().join("archive-1");
    std::fs::create_dir(&archive).unwrap();
    std::fs::write(
        dir.path().join("putting-away"),
        format!("left\n{}", archive.to_string_lossy()),
    )
    .unwrap();
    std::fs::rename(&path, archive.join("vault.sqlite3")).unwrap();

    network::finish_interrupted_recovery(&path);
    for gone in [
        "vault.sqlite3",
        "control.sqlite3",
        "peers.sqlite3",
        "putting-away",
    ] {
        assert!(!dir.path().join(gone).exists(), "{gone} was left behind");
    }
    assert_eq!(
        Vault::open(archive.join("vault.sqlite3"))
            .unwrap()
            .vault_id(),
        old_vault
    );
    assert_eq!(
        std::fs::read(archive.join("peers.sqlite3")).unwrap(),
        old_peers
    );

    // The device starts as one without a vault and says what happened.
    let app = shell(dir.path());
    let handle = app.handle().clone();
    let expected = archive.to_string_lossy().into_owned();
    tauri::async_runtime::block_on(async move {
        let info = devices(&handle).await;
        assert_eq!(
            (info.setup, info.reset_reason, info.reset_archive),
            ("none", Some("left"), Some(expected))
        );

        // Without a vault here the copy can still be looked into, though
        // there is nothing to compare it with or copy into.
        let held = archive::open_archive("archive-1".into(), PASSWORD.into(), handle.state())
            .await
            .unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(
            (held[0].title.as_str(), held[0].relation),
            ("Kept in the archive", None)
        );
        let nowhere =
            archive::copy_from_archive(held[0].id.clone(), handle.state(), handle.clone())
                .await
                .err()
                .unwrap();
        assert_eq!(nowhere.code, "locked");

        // Deleting it also drops the note that pointed to it.
        archive::delete_archive("archive-1".into(), handle.state(), handle.clone())
            .await
            .unwrap();
        assert_eq!(devices(&handle).await.reset_archive, None);
    });
    assert!(!archive.exists());
    assert!(!dir.path().join("left-vault").exists());

    // A later launch moves nothing more: the stores made since stay.
    network::finish_interrupted_recovery(&path);
    assert!(dir.path().join("peers.sqlite3").exists());

    // A marker that names no folder of this app's is dropped, not followed.
    std::fs::write(dir.path().join("putting-away"), "left\n/tmp").unwrap();
    network::finish_interrupted_recovery(&path);
    assert!(!dir.path().join("putting-away").exists());
    assert!(dir.path().join("peers.sqlite3").exists());
}
