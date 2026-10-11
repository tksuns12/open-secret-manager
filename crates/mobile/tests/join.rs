//! A phone, through the interface the apps use, joins a vault from a
//! desktop without a vote, reads and copies what it holds, stays in sync,
//! survives a restart, and learns when it is removed; and what it writes
//! reaches the desktop, while a change made on both at once waits for the
//! desktop to resolve it. The desktop runs in this process on the shared
//! code's public interface, as the desktop app does; the two talk over
//! pinned TLS on localhost.

use std::{
    path::{Path, PathBuf},
    sync::{mpsc as std_mpsc, Arc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use osm_mobile::{Device, DeviceState, ItemDraft, ItemKind, MobileError, SyncState};
use osm_vault_core::{Item, ItemKind as CoreKind, Vault};
use osm_vault_membership::{device_id_from_bytes, ControlNode, DeviceId, NodeOptions};
use osm_vault_peer::{
    control, invite, serve_members, start_node, AddressBook, Keystore, MemberEndpoint,
    MemoryKeystore, NoKeystore, PairingListener, PeerStore, Voting,
};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use tokio::{net::TcpListener, sync::Mutex};

const DESKTOP_PASSWORD: &str = "desktop password";
const PHONE_PASSWORD: &str = "phone password, long enough";
/// The test vector of RFC 6238 as a base32 secret.
const TOTP: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn login(title: &str, password: &str) -> Item {
    let mut item = Item::new(title);
    item.username = format!("{title}@example.test");
    item.password = password.into();
    item.url = format!("https://{}.example.test/", title.to_lowercase());
    item
}

/// The desktop's side: a vault, its control plane, and the members'
/// listener, with a loop that gives members the keys they lack, as the
/// desktop app's does.
struct Desktop {
    vault: Arc<Mutex<Vault>>,
    peers: Mutex<PeerStore>,
    invitations: Mutex<InvitationStore>,
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    device: DeviceId,
}

impl Desktop {
    async fn found(dir: &Path) -> Arc<Self> {
        let (vault, _) = Vault::create(dir.join("desktop.sqlite3"), DESKTOP_PASSWORD).unwrap();
        let peers_path = dir.join("desktop-peers.sqlite3");
        let mut peers = PeerStore::open(&peers_path, Arc::new(NoKeystore)).unwrap();
        let endpoint = MemberEndpoint::new(
            vault.vault_id(),
            &mut peers,
            AddressBook::open(&peers_path).unwrap(),
        )
        .unwrap();
        let device = device_id_from_bytes(vault.device_id().unwrap());
        let node = start_node(
            dir.join("desktop-control.sqlite3"),
            device,
            &endpoint,
            NodeOptions::default(),
        )
        .await
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        endpoint.set_listen_port(listener.local_addr().unwrap().port());
        control::found(&vault, &mut peers, &node).await.unwrap();
        let desktop = Arc::new(Self {
            vault: Arc::new(Mutex::new(vault)),
            peers: Mutex::new(peers),
            invitations: Mutex::new(
                InvitationStore::open_in_memory(InvitationPolicy::default()).unwrap(),
            ),
            endpoint: endpoint.clone(),
            node: node.clone(),
            device,
        });
        let (sync, mut incoming) = tokio::sync::mpsc::channel(4);
        tokio::spawn(serve_members(listener, endpoint, node, Some(sync)));
        let serving = desktop.clone();
        tokio::spawn(async move {
            while let Some(connection) = incoming.recv().await {
                let state = serving.node.state();
                let _ = connection.run_shared(&*serving.vault, &state).await;
            }
        });
        let granting = desktop.clone();
        tokio::spawn(async move {
            loop {
                let state = granting.node.state();
                let grants = {
                    let mut vault = granting.vault.lock().await;
                    let _ = control::reconcile(&mut vault, &state);
                    control::grant_requests(&vault, &state).unwrap_or_default()
                };
                for request in grants {
                    let _ = control::submit(&granting.node, request).await;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        desktop
    }

    async fn put(&self, item: Item) {
        self.vault.lock().await.put(item).unwrap();
    }

    /// Makes an invitation and waits for the joiner in the background: it
    /// sends the code the joiner showed, and proposes the enrollment, as a
    /// device without a vote, once the test says the codes match.
    async fn invite(
        self: &Arc<Self>,
    ) -> (String, std_mpsc::Receiver<String>, std_mpsc::Sender<bool>) {
        let listener = PairingListener::bind("127.0.0.1:0", &mut *self.peers.lock().await)
            .await
            .unwrap();
        let code = {
            let vault = self.vault.lock().await;
            invite(
                &vault,
                &mut *self.invitations.lock().await,
                &mut *self.peers.lock().await,
                vec![listener.local_addr().unwrap().to_string()],
                now(),
                300,
            )
            .unwrap()
            .encode()
            .unwrap()
            .to_string()
        };
        let (shown, codes) = std_mpsc::channel();
        let (answer, answers) = std_mpsc::channel::<bool>();
        let desktop = self.clone();
        tokio::spawn(async move {
            let incoming = listener.next_request().await.unwrap();
            let pending = {
                // Every guard first: a `&Vault` cannot be held across an
                // await.
                let vault = desktop.vault.lock().await;
                let invitations = desktop.invitations.lock().await;
                let mut peers = desktop.peers.lock().await;
                incoming
                    .review(&vault, &invitations, &mut peers, now())
                    .unwrap()
            };
            shown.send(pending.sas()).unwrap();
            let confirmed = tokio::task::spawn_blocking(move || answers.recv().unwrap_or(false))
                .await
                .unwrap();
            if !confirmed {
                let _ = pending.decline().await;
                return;
            }
            let (proposal, approved) = {
                let vault = desktop.vault.lock().await;
                let mut invitations = desktop.invitations.lock().await;
                pending
                    .approve_enrollment(
                        &vault,
                        &mut invitations,
                        desktop.endpoint.roster(),
                        Voting::WithoutVote,
                        desktop.endpoint.listen_port(),
                        now(),
                    )
                    .unwrap()
            };
            control::submit(&desktop.node, proposal).await.unwrap();
            approved.send().await.unwrap();
        });
        (code, codes, answer)
    }

    async fn remove(&self, device: DeviceId) {
        let request = {
            let vault = self.vault.lock().await;
            control::removal_request(&vault, &self.node.state(), device.to_be_bytes()).unwrap()
        };
        control::submit(&self.node, request).await.unwrap();
    }
}

/// Retries `check` for up to a minute.
fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..240 {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("never saw: {what}");
}

#[test]
fn a_phone_joins_without_a_vote_reads_copies_stays_in_sync_and_learns_its_removal() {
    let dir = tempfile::tempdir().unwrap();
    // The desktop runs on a runtime of its own; the phone's interface is
    // blocking and runs its own.
    let desktop_runtime = tokio::runtime::Runtime::new().unwrap();
    let desktop = desktop_runtime.block_on(Desktop::found(dir.path()));
    let mut mail = login("Mail", "mail password");
    mail.totp_secret = Some(TOTP.into());
    desktop_runtime.block_on(desktop.put(mail));

    let folder = dir.path().join("phone");
    let phone = Device::open_listening_on(folder.clone(), 0).unwrap();
    assert_eq!(phone.state(), DeviceState::NoVault);
    assert!(matches!(phone.items(), Err(MobileError::NoVault)));
    assert!(matches!(
        phone.join_start("not an invitation".into()),
        Err(MobileError::InvalidInvitation)
    ));

    // The owner compares the codes on both devices and confirms on each.
    let (code, codes, answer) = desktop_runtime.block_on(desktop.invite());
    let shown = phone.join_start(code).unwrap();
    assert_eq!(phone.state(), DeviceState::Joining);
    assert_eq!(codes.recv_timeout(Duration::from_secs(30)).unwrap(), shown);
    answer.send(true).unwrap();
    assert!(matches!(
        phone.join_finish("short".into()),
        Err(MobileError::PasswordTooShort { minimum: 12 })
    ));
    phone.join_finish(PHONE_PASSWORD.into()).unwrap();
    assert_eq!(phone.state(), DeviceState::Unlocked);

    // On the desktop it is a member without a vote.
    let phone_id = {
        let state = desktop.node.state();
        assert_eq!(
            state.voters().into_iter().collect::<Vec<_>>(),
            [desktop.device]
        );
        assert_eq!(state.without_vote.len(), 1);
        *state.without_vote.iter().next().unwrap()
    };

    // What the vault holds arrives, to read and to copy.
    eventually("the vault's item reaches the phone", || {
        let _ = phone.sync_now();
        phone.items().is_ok_and(|items| items.len() == 1)
    });
    let items = phone.items().unwrap();
    assert_eq!(
        (
            items[0].title.as_str(),
            items[0].kind,
            items[0].username.as_str()
        ),
        ("Mail", ItemKind::Login, "Mail@example.test")
    );
    let detail = phone.item(items[0].id.clone()).unwrap();
    assert!(detail.has_password && detail.has_one_time_code && !detail.conflict);
    assert_eq!(
        phone.password(items[0].id.clone()).unwrap(),
        "mail password"
    );
    let code = phone.one_time_code(items[0].id.clone()).unwrap();
    assert!(
        code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
        "{code}"
    );
    assert!(matches!(
        phone.item("no such item".into()),
        Err(MobileError::NotFound)
    ));
    let status = phone.sync_status();
    assert_eq!((status.state, status.members), (SyncState::Synced, 1));
    assert!(status.last_synced_at.is_some());

    // An edit on the desktop reaches it.
    desktop_runtime.block_on(desktop.put(login("Bank", "bank password")));
    eventually("the desktop's edit reaches the phone", || {
        let _ = phone.sync_now();
        phone.items().is_ok_and(|items| items.len() == 2)
    });

    // Locked, it shows nothing; its own password unlocks it.
    phone.lock();
    assert_eq!(phone.state(), DeviceState::Locked);
    assert!(matches!(phone.items(), Err(MobileError::Locked)));
    assert!(matches!(
        phone.password(items[0].id.clone()),
        Err(MobileError::Locked)
    ));
    assert!(matches!(
        phone.unlock(DESKTOP_PASSWORD.into()),
        Err(MobileError::InvalidCredentials)
    ));
    phone.unlock(PHONE_PASSWORD.into()).unwrap();

    // Closed and opened again, it is the same device of the same vault.
    drop(phone);
    let phone = Device::open_listening_on(folder.clone(), 0).unwrap();
    assert_eq!(phone.state(), DeviceState::Locked);
    phone.unlock(PHONE_PASSWORD.into()).unwrap();
    phone.go_online().unwrap();
    desktop_runtime.block_on(desktop.put(login("Shop", "shop password")));
    eventually("an edit reaches the phone after a restart", || {
        let _ = phone.sync_now();
        phone.items().is_ok_and(|items| items.len() == 3)
    });

    // Removed while it is offline, it learns so when it next syncs, and
    // remembers it.
    phone.go_offline();
    assert_eq!(phone.sync_status().state, SyncState::Offline);
    desktop_runtime.block_on(desktop.remove(phone_id));
    eventually("the desktop completes the removal", || {
        let state = desktop.node.state();
        state.pending.is_none() && state.removed.contains_key(&phone_id)
    });
    eventually("the phone learns it was removed", || {
        matches!(phone.sync_now(), Err(MobileError::Removed))
    });
    assert_eq!(phone.state(), DeviceState::Removed);
    assert_eq!(phone.sync_status().state, SyncState::Removed);
    // What it already held stays readable.
    assert_eq!(phone.items().unwrap().len(), 3);
    drop(phone);
    let phone = Device::open_listening_on(folder, 0).unwrap();
    assert_eq!(phone.state(), DeviceState::Removed);
    assert!(matches!(phone.go_online(), Err(MobileError::Removed)));
}

/// Joins a phone in `folder` to `desktop`, the codes compared and
/// confirmed, without checking each step on the way as the first test does.
fn joined_phone(
    desktop_runtime: &tokio::runtime::Runtime,
    desktop: &Arc<Desktop>,
    folder: PathBuf,
) -> Device {
    joined_phone_with(desktop_runtime, desktop, folder, Arc::new(NoKeystore))
}

/// As [`joined_phone`], with `keystore` sealing the phone's network key.
fn joined_phone_with(
    desktop_runtime: &tokio::runtime::Runtime,
    desktop: &Arc<Desktop>,
    folder: PathBuf,
    keystore: Arc<dyn Keystore>,
) -> Device {
    let phone = Device::open_with_keystore(folder, 0, keystore).unwrap();
    let (code, codes, answer) = desktop_runtime.block_on(desktop.invite());
    let shown = phone.join_start(code).unwrap();
    assert_eq!(codes.recv_timeout(Duration::from_secs(30)).unwrap(), shown);
    answer.send(true).unwrap();
    phone.join_finish(PHONE_PASSWORD.into()).unwrap();
    phone
}

fn draft(title: &str, username: &str, password: Option<&str>) -> ItemDraft {
    ItemDraft {
        title: title.into(),
        kind: ItemKind::Login,
        username: username.into(),
        url: format!("https://{}.example.test", title.to_lowercase()),
        notes: String::new(),
        favorite: false,
        password: password.map(Into::into),
        one_time_code_secret: None,
    }
}

#[test]
fn what_a_phone_writes_reaches_the_desktop_and_a_change_made_on_both_waits_for_the_desktop() {
    let dir = tempfile::tempdir().unwrap();
    let desktop_runtime = tokio::runtime::Runtime::new().unwrap();
    let desktop = desktop_runtime.block_on(Desktop::found(dir.path()));
    let mail = login("Mail", "mail password");
    let mail_id = mail.id.clone();
    desktop_runtime.block_on(desktop.put(mail));
    let mut passport = Item::new("Passport");
    passport.kind = CoreKind::Identity;
    let passport_id = passport.id.clone();
    desktop_runtime.block_on(desktop.put(passport));
    let on_desktop =
        |id: &str| desktop_runtime.block_on(async { desktop.vault.lock().await.get(id).ok() });

    let phone = joined_phone(&desktop_runtime, &desktop, dir.path().join("phone"));
    eventually("the vault reaches the phone", || {
        let _ = phone.sync_now();
        phone.items().is_ok_and(|items| items.len() == 2)
    });

    // A login made on the phone reaches the desktop, password and all: the
    // phone syncs at once, without being asked.
    let forum = phone
        .create_item(draft(
            "Forum",
            "me@forum.example.test",
            Some("forum password"),
        ))
        .unwrap();
    eventually("the phone's new login reaches the desktop", || {
        on_desktop(&forum).is_some()
    });
    let item = on_desktop(&forum).unwrap().item;
    assert_eq!(
        (item.username.as_str(), item.password.as_str()),
        ("me@forum.example.test", "forum password")
    );

    // So does an edit, which keeps the password it does not name.
    let read = phone.item(mail_id.clone()).unwrap();
    phone
        .update_item(
            mail_id.clone(),
            read.revision.clone(),
            draft("Mail", "new name", None),
        )
        .unwrap();
    eventually("the phone's edit reaches the desktop", || {
        let _ = phone.sync_now();
        on_desktop(&mail_id).is_some_and(|found| found.item.username == "new name")
    });
    assert_eq!(on_desktop(&mail_id).unwrap().item.password, "mail password");

    // Changed on the desktop and on the phone while the phone was offline,
    // it is in conflict on both, and only the desktop resolves it.
    phone.go_offline();
    let current = on_desktop(&mail_id).unwrap();
    let mut on_the_desktop = current.item.clone();
    on_the_desktop.title = "Mail, renamed on the desktop".into();
    desktop_runtime.block_on(async {
        desktop
            .vault
            .lock()
            .await
            .update(on_the_desktop, &current.revision)
            .unwrap();
    });
    let read = phone.item(mail_id.clone()).unwrap();
    phone
        .update_item(
            mail_id.clone(),
            read.revision.clone(),
            draft("Mail", "renamed on the phone", None),
        )
        .unwrap();
    phone.go_online().unwrap();
    eventually("both see the conflict", || {
        let _ = phone.sync_now();
        phone.item(mail_id.clone()).is_ok_and(|item| item.conflict)
            && on_desktop(&mail_id).is_some_and(|found| found.conflict)
    });
    let conflicted = phone.item(mail_id.clone()).unwrap();
    assert!(matches!(
        phone.update_item(
            mail_id.clone(),
            conflicted.revision.clone(),
            draft("Mail", "again", None)
        ),
        Err(MobileError::InConflict)
    ));
    assert!(matches!(
        phone.delete_item(mail_id.clone(), conflicted.revision),
        Err(MobileError::InConflict)
    ));
    desktop_runtime.block_on(async {
        let mut vault = desktop.vault.lock().await;
        let versions = vault.versions(&mail_id).unwrap();
        let heads: Vec<String> = versions.iter().map(|v| v.revision.clone()).collect();
        let kept = versions
            .iter()
            .find_map(|version| {
                version
                    .item
                    .clone()
                    .filter(|item| item.username == "renamed on the phone")
            })
            .unwrap();
        vault.resolve(&mail_id, Some(kept), &heads).unwrap();
    });
    eventually("the desktop's resolution reaches the phone", || {
        let _ = phone.sync_now();
        phone
            .item(mail_id.clone())
            .is_ok_and(|item| !item.conflict && item.username == "renamed on the phone")
    });

    // An identity is read on the phone, and edited on a computer.
    let identity = phone.item(passport_id.clone()).unwrap();
    assert_eq!(identity.kind, ItemKind::Identity);
    assert!(matches!(
        phone.update_item(
            passport_id.clone(),
            identity.revision.clone(),
            draft("Passport", "", None)
        ),
        Err(MobileError::NotEditableHere)
    ));
    assert!(matches!(
        phone.delete_item(passport_id, identity.revision),
        Err(MobileError::NotEditableHere)
    ));

    // Deleted on the phone, it is gone from the desktop.
    let read = phone.item(forum.clone()).unwrap();
    phone.delete_item(forum.clone(), read.revision).unwrap();
    eventually("the phone's deletion reaches the desktop", || {
        let _ = phone.sync_now();
        on_desktop(&forum).is_none()
    });
}

#[test]
fn a_locked_phone_away_from_the_screen_syncs_both_ways_and_stays_locked() {
    let dir = tempfile::tempdir().unwrap();
    let desktop_runtime = tokio::runtime::Runtime::new().unwrap();
    let desktop = desktop_runtime.block_on(Desktop::found(dir.path()));
    let on_desktop = |title: &str| {
        desktop_runtime.block_on(async {
            desktop
                .vault
                .lock()
                .await
                .list()
                .unwrap()
                .iter()
                .any(|item| item.title == title)
        })
    };
    // The phone's network key is sealed by its keystore, which opens it
    // without the vault's password.
    let keystore = Arc::new(MemoryKeystore::default());
    let folder = dir.path().join("phone");
    let phone = joined_phone_with(&desktop_runtime, &desktop, folder.clone(), keystore.clone());
    assert_eq!(keystore.len(), 1);

    // Written on the phone while it could reach nobody, then the app left
    // the screen: locked and offline. The desktop writes meanwhile.
    phone.go_offline();
    phone
        .create_item(draft("Written on the phone", "", Some("phone password")))
        .unwrap();
    phone.lock();
    desktop_runtime.block_on(desktop.put(login("Written on the desktop", "desktop password")));
    assert!(!on_desktop("Written on the phone"));
    assert_eq!(phone.sync_status().state, SyncState::Offline);

    // A sync in the background sends what the phone wrote, takes in what
    // the desktop wrote for the next unlock, and stops again, locked.
    let status = phone.sync_in_background().unwrap();
    assert!(status.last_synced_at.is_some());
    assert!(status.pending > 0, "{status:?}");
    assert!(on_desktop("Written on the phone"));
    assert_eq!(phone.state(), DeviceState::Locked);
    assert_eq!(phone.sync_status().state, SyncState::Offline);
    // Back in front, unlocked and online, as the app does, the phone
    // verifies what waited and shows it.
    phone.unlock(PHONE_PASSWORD.into()).unwrap();
    phone.go_online().unwrap();
    let titles: Vec<String> = phone
        .items()
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    assert!(
        titles.contains(&"Written on the desktop".to_owned()),
        "{titles:?}"
    );
    assert_eq!(phone.sync_status().pending, 0);

    // While the app is in front, it stays online after one.
    phone.sync_in_background().unwrap();
    assert_ne!(phone.sync_status().state, SyncState::Offline);
    phone.go_offline();

    // Started afresh and never unlocked, as when the system wakes the app
    // only to sync, the phone opens its sealed key and syncs.
    drop(phone);
    desktop_runtime.block_on(desktop.put(login("Written while the phone slept", "p")));
    let phone = Device::open_with_keystore(folder.clone(), 0, keystore.clone()).unwrap();
    assert_eq!(phone.state(), DeviceState::Locked);
    let status = phone.sync_in_background().unwrap();
    assert!(status.pending > 0, "{status:?}");
    drop(phone);

    // A keystore that lost the key, as after the files were restored onto
    // another phone: the phone says so, and makes no new identity.
    keystore.lose_everything();
    let phone = Device::open_with_keystore(folder, 0, keystore.clone()).unwrap();
    assert!(matches!(
        phone.sync_in_background(),
        Err(MobileError::KeystoreLost)
    ));
    assert!(keystore.is_empty());
}
