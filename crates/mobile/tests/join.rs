//! A phone, through the interface the apps use, joins a vault from a
//! desktop without a vote, reads and copies what it holds, stays in sync,
//! survives a restart, and learns when it is removed. The desktop runs in
//! this process on the shared code's public interface, as the desktop app
//! does; the two talk over pinned TLS on localhost.

use std::{
    path::Path,
    sync::{mpsc as std_mpsc, Arc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use osm_mobile::{Device, DeviceState, ItemKind, MobileError, SyncState};
use osm_vault_core::{Item, Vault};
use osm_vault_membership::{device_id_from_bytes, ControlNode, DeviceId, NodeOptions};
use osm_vault_peer::{
    control, invite, serve_members, start_node, AddressBook, MemberEndpoint, PairingListener,
    PeerStore, Voting,
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
        let mut peers = PeerStore::open(&peers_path).unwrap();
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
