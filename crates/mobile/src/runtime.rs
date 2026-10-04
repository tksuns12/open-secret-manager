//! The phone's side of a vault: the same steps as the desktop app's, over
//! the same shared code, without a window. While online it runs its
//! control-plane node, which follows the vault's decisions as a member
//! without a vote, and accepts the other members on one port; it keeps the
//! vault in line with what was decided, and syncs. Offline, nothing runs.
//!
//! Network waits never hold the vault: a sync session takes it one message
//! at a time, and nothing is locked while the owner compares the codes.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use osm_vault_core::{Item, ItemKind, Origin, Vault, VaultItem};
use osm_vault_membership::{ControlNode, DeviceId, NodeOptions};
use osm_vault_peer::{
    control, serve_members, start_node, AddressBook, Invitation, MemberEndpoint, MemberSync,
    PairingConnection, PeerStore, PreparedJoin, SyncReport,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

use crate::{
    DeviceState, FillCredentials, ItemDetail, ItemDraft, ItemSummary, MobileError, SyncState,
    SyncStatus,
};

/// The files of one device, as the desktop app names them.
const VAULT_FILE: &str = "vault.sqlite3";
const PEERS_FILE: &str = "peers.sqlite3";
const CONTROL_FILE: &str = "control.sqlite3";
/// Present once this device has learned that it was removed.
const REMOVED_MARKER: &str = "removed";
/// How long a joining device waits for the vault's devices to enroll it.
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(120);
/// How often an online device checks whether a member said it was removed.
const WATCH_INTERVAL: Duration = Duration::from_secs(5);
/// While online, how often it syncs without being asked.
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
const MIN_PASSWORD_CHARS: usize = 12;

struct Control {
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl Control {
    async fn stop(&self) {
        let tasks = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for task in tasks {
            task.abort();
        }
        self.node.shutdown().await;
    }
}

/// A join between showing the code and finishing.
struct JoinState {
    connection: PairingConnection,
    control: Arc<Control>,
}

pub(crate) struct Runtime {
    directory: PathBuf,
    port: u16,
    vault: Mutex<Option<Vault>>,
    peers: Mutex<PeerStore>,
    addresses: AddressBook,
    control: Mutex<Option<Arc<Control>>>,
    join: Mutex<Option<JoinState>>,
    status: StdMutex<SyncStatus>,
    removed: AtomicBool,
    syncing: AtomicBool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

impl Runtime {
    pub(crate) async fn open(directory: PathBuf, port: u16) -> Result<Self, MobileError> {
        std::fs::create_dir_all(&directory)?;
        let vault_path = directory.join(VAULT_FILE);
        let vault = if vault_path.symlink_metadata().is_ok() {
            Some(
                Vault::open(&vault_path).map_err(|error| MobileError::UnreadableVault {
                    reason: error.to_string(),
                })?,
            )
        } else {
            // Without a vault, a control database is what an unfinished
            // join left: its device identity is gone.
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let _ = std::fs::remove_file(directory.join(format!("{CONTROL_FILE}{suffix}")));
            }
            None
        };
        let peers_path = directory.join(PEERS_FILE);
        let peers = PeerStore::open(&peers_path)?;
        let addresses = AddressBook::open(&peers_path)?;
        let removed = directory.join(REMOVED_MARKER).exists();
        Ok(Self {
            port,
            vault: Mutex::new(vault),
            peers: Mutex::new(peers),
            addresses,
            control: Mutex::new(None),
            join: Mutex::new(None),
            status: StdMutex::new(SyncStatus {
                state: if removed {
                    SyncState::Removed
                } else {
                    SyncState::Offline
                },
                members: 0,
                last_synced_at: None,
                pending: 0,
                message: None,
            }),
            removed: AtomicBool::new(removed),
            syncing: AtomicBool::new(false),
            directory,
        })
    }

    pub(crate) async fn state(&self) -> DeviceState {
        if self.removed.load(Ordering::SeqCst) {
            return DeviceState::Removed;
        }
        if self.join.lock().await.is_some() {
            return DeviceState::Joining;
        }
        match self.vault.lock().await.as_ref().map(Vault::is_unlocked) {
            None => DeviceState::NoVault,
            Some(false) => DeviceState::Locked,
            Some(true) => DeviceState::Unlocked,
        }
    }

    pub(crate) async fn unlock(self: &Arc<Self>, password: &str) -> Result<(), MobileError> {
        {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            if !vault.is_unlocked() {
                vault.unlock(password)?;
            }
        }
        // Membership first, then what arrived while locked.
        if let Some(control) = self.control.lock().await.clone() {
            self.maintain(&control).await;
        }
        Ok(())
    }

    pub(crate) async fn lock(&self) {
        if let Some(vault) = self.vault.lock().await.as_mut() {
            vault.lock();
        }
    }

    pub(crate) async fn items(&self) -> Result<Vec<ItemSummary>, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        Ok(vault
            .list()?
            .into_iter()
            .map(|item| ItemSummary {
                id: item.id.clone(),
                title: item.title.clone(),
                kind: item.kind.into(),
                username: item.username.clone(),
                url: item.url.clone(),
                favorite: item.favorite,
                conflict: item.conflict,
            })
            .collect())
    }

    pub(crate) async fn item(&self, id: &str) -> Result<ItemDetail, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let found = vault.get(id)?;
        let item = &found.item;
        Ok(ItemDetail {
            id: item.id.clone(),
            title: item.title.clone(),
            kind: item.kind.into(),
            username: item.username.clone(),
            url: item.url.clone(),
            notes: item.notes.clone(),
            favorite: item.favorite,
            has_password: !item.password.is_empty(),
            has_one_time_code: item.totp_secret.is_some(),
            conflict: found.conflict,
            revision: found.revision.clone(),
        })
    }

    pub(crate) async fn create_item(
        self: &Arc<Self>,
        draft: ItemDraft,
    ) -> Result<String, MobileError> {
        if !draft.kind.editable_here() {
            return Err(MobileError::NotEditableHere);
        }
        let id = {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            let mut item = Item::default();
            draft.apply_to(&mut item);
            let id = item.id.clone();
            vault.put(item)?;
            id
        };
        self.sync_soon();
        Ok(id)
    }

    pub(crate) async fn update_item(
        self: &Arc<Self>,
        id: &str,
        revision: &str,
        draft: ItemDraft,
    ) -> Result<(), MobileError> {
        if !draft.kind.editable_here() {
            return Err(MobileError::NotEditableHere);
        }
        {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            // From the stored item, so that what the draft does not carry
            // (custom fields, tags) stays.
            let VaultItem {
                mut item, conflict, ..
            } = vault.get(id)?;
            if conflict {
                return Err(MobileError::InConflict);
            }
            if !crate::ItemKind::from(item.kind).editable_here() {
                return Err(MobileError::NotEditableHere);
            }
            draft.apply_to(&mut item);
            vault.update(item, revision)?;
        }
        self.sync_soon();
        Ok(())
    }

    pub(crate) async fn delete_item(
        self: &Arc<Self>,
        id: &str,
        revision: &str,
    ) -> Result<(), MobileError> {
        {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            let found = vault.get(id)?;
            if found.conflict {
                return Err(MobileError::InConflict);
            }
            if !crate::ItemKind::from(found.item.kind).editable_here() {
                return Err(MobileError::NotEditableHere);
            }
            vault.delete(id, revision)?;
        }
        self.sync_soon();
        Ok(())
    }

    /// After a change here, online: syncs at once rather than at the next
    /// interval, without making the caller wait.
    fn sync_soon(self: &Arc<Self>) {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let _ = runtime.sync_with_members().await;
        });
    }

    pub(crate) async fn password(&self, id: &str) -> Result<String, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        Ok(vault.get(id)?.item.password.clone())
    }

    pub(crate) async fn one_time_code(&self, id: &str) -> Result<String, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        if vault.get(id)?.item.totp_secret.is_none() {
            return Err(MobileError::NoOneTimeCode);
        }
        Ok(vault.item_totp_code(id, now())?)
    }

    pub(crate) async fn logins_for_web(
        &self,
        origin: &str,
    ) -> Result<Vec<ItemSummary>, MobileError> {
        let origin = Origin::parse(origin).ok_or(MobileError::InvalidOrigin)?;
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        Ok(vault
            .logins_for_origin(&origin)?
            .into_iter()
            .map(|item| ItemSummary {
                id: item.id.clone(),
                title: item.title.clone(),
                kind: item.kind.into(),
                username: item.username.clone(),
                url: item.url.clone(),
                favorite: item.favorite,
                conflict: item.conflict,
            })
            .collect())
    }

    pub(crate) async fn fill_for_web(
        &self,
        id: &str,
        origin: &str,
    ) -> Result<FillCredentials, MobileError> {
        let origin = Origin::parse(origin).ok_or(MobileError::InvalidOrigin)?;
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let found = vault.credentials_for_origin(id, &origin)?;
        Ok(FillCredentials {
            username: found.username.clone(),
            password: found.password.clone(),
        })
    }

    pub(crate) async fn fill_for_app(&self, id: &str) -> Result<FillCredentials, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let found = vault.get(id)?;
        if found.item.kind != ItemKind::Login {
            return Err(MobileError::NotALogin);
        }
        Ok(FillCredentials {
            username: found.item.username.clone(),
            password: found.item.password.clone(),
        })
    }

    pub(crate) async fn join_start(self: &Arc<Self>, code: &str) -> Result<String, MobileError> {
        if self.removed.load(Ordering::SeqCst) {
            return Err(MobileError::Removed);
        }
        if self.vault.lock().await.is_some() {
            return Err(MobileError::VaultExists);
        }
        if let Some(earlier) = self.join.lock().await.take() {
            earlier.control.stop().await;
            self.forget_control().await;
        }
        let invitation = Invitation::decode(code).map_err(|_| MobileError::InvalidInvitation)?;
        let prepared = PreparedJoin::new(invitation, &mut *self.peers.lock().await, now())?;
        let connection = prepared.connect().await?;
        // The node runs from here on so that the leader can bring this
        // device up to date. It accepts no one until the inviting device
        // names the members.
        let joiner = connection.joiner();
        let control = self
            .start_control(joiner.vault_id(), joiner.control_device())
            .await?;
        let sas = connection.sas();
        *self.join.lock().await = Some(JoinState {
            connection,
            control,
        });
        Ok(sas)
    }

    pub(crate) async fn join_finish(self: &Arc<Self>, password: &str) -> Result<(), MobileError> {
        if password.chars().count() < MIN_PASSWORD_CHARS {
            return Err(MobileError::PasswordTooShort {
                minimum: MIN_PASSWORD_CHARS as u32,
            });
        }
        let Some(JoinState {
            connection,
            control,
        }) = self.join.lock().await.take()
        else {
            return Err(MobileError::NotJoining);
        };
        if let Err(error) = self.finish_join(connection, &control, password).await {
            control.stop().await;
            self.forget_control().await;
            return Err(error);
        }
        self.maintain(&control).await;
        // Fetch the vault's contents right away.
        let runtime = self.clone();
        tokio::spawn(async move {
            let _ = runtime.sync_with_members().await;
        });
        Ok(())
    }

    async fn finish_join(
        &self,
        connection: PairingConnection,
        control: &Control,
        password: &str,
    ) -> Result<(), MobileError> {
        let (joiner, grant) = connection.receive_enrollment().await?;
        // The grant names the members: accept them, and keep telling them
        // where this device listens until one of them has brought it up to
        // date and the keys have arrived.
        let members = joiner.members(&grant)?;
        control.endpoint.introduce(&members)?;
        let deadline = tokio::time::Instant::now() + ENROLLMENT_TIMEOUT;
        while !joiner.enrolled(&control.node.state()) {
            if tokio::time::Instant::now() > deadline {
                return Err(MobileError::EnrollmentTimeout);
            }
            control.endpoint.announce_all().await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let committed = control.node.state();
        let mut vault = self.vault.lock().await;
        if vault.is_some() {
            return Err(MobileError::VaultExists);
        }
        *vault = Some(joiner.finish_enrollment(
            &grant,
            true,
            &committed,
            self.directory.join(VAULT_FILE),
            password,
        )?);
        Ok(())
    }

    pub(crate) async fn cancel_join(&self) {
        if let Some(join) = self.join.lock().await.take() {
            join.control.stop().await;
            self.forget_control().await;
        }
    }

    /// Stops the control plane of a join that did not finish and deletes
    /// its database: its device identity belongs to no vault.
    async fn forget_control(&self) {
        if let Some(control) = self.control.lock().await.take() {
            control.stop().await;
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(self.directory.join(format!("{CONTROL_FILE}{suffix}")));
        }
    }

    pub(crate) async fn go_online(self: &Arc<Self>) -> Result<(), MobileError> {
        if self.removed.load(Ordering::SeqCst) {
            return Err(MobileError::Removed);
        }
        if self.control.lock().await.is_some() {
            return Ok(());
        }
        let identity = {
            let vault = self.vault.lock().await;
            let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
            vault.device_id().map(|device| (vault.vault_id(), device))
        };
        let Some((vault_id, device)) = identity else {
            return Err(MobileError::NoVault);
        };
        if !self.directory.join(CONTROL_FILE).exists() {
            return Err(MobileError::Network {
                reason: "this device does not belong to a vault's devices".into(),
            });
        }
        let control = self
            .start_control(vault_id, osm_vault_membership::device_id_from_bytes(device))
            .await?;
        self.update_status(|status| status.state = SyncState::Idle);
        self.maintain(&control).await;
        let runtime = self.clone();
        tokio::spawn(async move {
            let _ = runtime.sync_with_members().await;
        });
        Ok(())
    }

    pub(crate) async fn go_offline(&self) {
        if let Some(join) = self.join.lock().await.take() {
            join.control.stop().await;
        }
        if let Some(control) = self.control.lock().await.take() {
            control.stop().await;
        }
        self.update_status(|status| {
            if status.state != SyncState::Removed {
                status.state = SyncState::Offline;
            }
        });
    }

    pub(crate) async fn sync_now(self: &Arc<Self>) -> Result<SyncStatus, MobileError> {
        if self.control.lock().await.is_none() {
            self.go_online().await?;
        }
        self.sync_with_members().await?;
        Ok(self.status())
    }

    pub(crate) fn status(&self) -> SyncStatus {
        self.status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn update_status(&self, change: impl FnOnce(&mut SyncStatus)) {
        change(
            &mut self
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
    }

    /// Starts this device's control-plane node and listener, if they are
    /// not running.
    async fn start_control(
        self: &Arc<Self>,
        vault_id: [u8; 32],
        device: DeviceId,
    ) -> Result<Arc<Control>, MobileError> {
        let mut slot = self.control.lock().await;
        if let Some(control) = slot.as_ref() {
            return Ok(control.clone());
        }
        let endpoint = {
            let mut peers = self.peers.lock().await;
            MemberEndpoint::new(vault_id, &mut peers, self.addresses.clone())?
        };
        let node = start_node(
            self.directory.join(CONTROL_FILE),
            device,
            &endpoint,
            NodeOptions::default(),
        )
        .await?;
        let listener = match TcpListener::bind(("0.0.0.0", self.port)).await {
            Ok(listener) => listener,
            Err(_) => TcpListener::bind(("0.0.0.0", 0)).await?,
        };
        endpoint.set_listen_port(listener.local_addr()?.port());
        let control = Arc::new(Control {
            endpoint: endpoint.clone(),
            node: node.clone(),
            tasks: StdMutex::new(Vec::new()),
        });
        let (sync, incoming) = mpsc::channel(4);
        let tasks = vec![
            tokio::spawn(serve_members(listener, endpoint, node, Some(sync))),
            tokio::spawn(self.clone().receive(control.clone(), incoming)),
            tokio::spawn(self.clone().watch(control.clone())),
            tokio::spawn(self.clone().sync_now_and_then()),
        ];
        *control
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = tasks;
        *slot = Some(control.clone());
        drop(slot);
        // Tell the members it knows where it listens now: a phone's
        // address changes from one network to the next.
        let announcer = control.clone();
        tokio::spawn(async move {
            announcer.endpoint.announce_all().await;
        });
        Ok(control)
    }

    /// Runs the sync connections other members open to this device.
    async fn receive(
        self: Arc<Self>,
        control: Arc<Control>,
        mut incoming: mpsc::Receiver<MemberSync>,
    ) {
        while let Some(connection) = incoming.recv().await {
            self.update_status(|status| status.state = SyncState::Syncing);
            let result = connection
                .run_shared(&self.vault, &control.node.state())
                .await;
            self.finish_sync(&control, result.map(|report| vec![report]));
        }
    }

    /// Keeps the vault in line with committed membership whenever it
    /// changes, and checks at intervals whether a member said this device
    /// was removed.
    async fn watch(self: Arc<Self>, control: Arc<Control>) {
        let mut applied = control.node.subscribe();
        loop {
            tokio::select! {
                changed = applied.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    self.maintain(&control).await;
                }
                _ = tokio::time::sleep(WATCH_INTERVAL) => {
                    if control.endpoint.told_removed() {
                        self.maintain(&control).await;
                    }
                }
            }
            if self.removed.load(Ordering::SeqCst) {
                return;
            }
        }
    }

    /// Syncs at intervals while online.
    async fn sync_now_and_then(self: Arc<Self>) {
        loop {
            tokio::time::sleep(SYNC_INTERVAL).await;
            let _ = self.sync_with_members().await;
        }
    }

    /// Brings the vault in line with committed control state. Unlocked, it
    /// also verifies what was received while locked and gives members the
    /// keys they lack.
    async fn maintain(&self, control: &Control) {
        let state = control.node.state();
        let mut removed = control.endpoint.told_removed();
        let mut grants = Vec::new();
        let mut pending = None;
        let mut failure = None;
        {
            let mut vault = self.vault.lock().await;
            if let Some(vault) = vault.as_mut() {
                match control::reconcile(vault, &state) {
                    Ok(reconciled) => removed |= reconciled.removed,
                    Err(error) => failure = Some(error.to_string()),
                }
                if failure.is_none() && !removed && vault.is_unlocked() {
                    match vault.process_staged() {
                        Ok(processed) => pending = Some(processed.pending),
                        Err(error) => failure = Some(error.to_string()),
                    }
                    grants = control::grant_requests(vault, &state).unwrap_or_default();
                }
            }
        }
        for request in grants {
            // Every unlocked member offers the same grant; all but one are
            // refused or recognized as already made.
            let _ = control::submit(&control.node, request).await;
        }
        if removed {
            self.mark_removed();
        }
        let members = control.endpoint.sync_peers().len() as u32;
        self.update_status(|status| {
            status.members = members;
            if let Some(pending) = pending {
                status.pending = pending as u32;
            }
            if removed {
                status.state = SyncState::Removed;
                status.message = Some("this device was removed from the vault".into());
            } else if let Some(failure) = failure {
                status.state = SyncState::Error;
                status.message = Some(failure);
            }
        });
    }

    /// Remembers, also across a restart, that this device was removed. It
    /// stops taking part; its copy stays as it was.
    fn mark_removed(&self) {
        if !self.removed.swap(true, Ordering::SeqCst) {
            let _ = std::fs::write(self.directory.join(REMOVED_MARKER), b"");
        }
    }

    /// Syncs with every other member it knows an address for. At most one
    /// round runs at a time.
    async fn sync_with_members(&self) -> Result<(), MobileError> {
        if self.removed.load(Ordering::SeqCst) {
            return Err(MobileError::Removed);
        }
        let Some(control) = self.control.lock().await.clone() else {
            return Ok(());
        };
        if self.syncing.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let peers = control.endpoint.sync_peers();
        if !peers.is_empty() {
            self.update_status(|status| status.state = SyncState::Syncing);
        }
        let mut reports = Vec::new();
        let mut failure = None;
        for device in peers {
            let session = async {
                let connection = control.endpoint.connect_sync(device).await?;
                connection
                    .run_shared(&self.vault, &control.node.state())
                    .await
            };
            match session.await {
                Ok(report) => reports.push(report),
                Err(osm_vault_peer::Error::Removed) => {
                    failure = Some(osm_vault_peer::Error::Removed);
                    break;
                }
                Err(error) => failure = Some(error),
            }
        }
        self.syncing.store(false, Ordering::SeqCst);
        // One member being away is not a failed sync if another answered.
        let result = match failure {
            Some(osm_vault_peer::Error::Removed) => Err(osm_vault_peer::Error::Removed),
            Some(error) if reports.is_empty() => Err(error),
            _ => Ok(reports),
        };
        let outcome = match &result {
            Err(osm_vault_peer::Error::Removed) => Err(MobileError::Removed),
            Err(error) => Err(MobileError::Network {
                reason: error.to_string(),
            }),
            Ok(_) => Ok(()),
        };
        self.finish_sync(&control, result);
        outcome
    }

    fn finish_sync(
        &self,
        control: &Control,
        result: Result<Vec<SyncReport>, osm_vault_peer::Error>,
    ) {
        let members = control.endpoint.sync_peers().len() as u32;
        match result {
            Ok(reports) => self.update_status(|status| {
                status.members = members;
                if status.state == SyncState::Removed {
                    return;
                }
                status.state = SyncState::Synced;
                status.last_synced_at = Some(now());
                status.message = None;
                if let Some(pending) = reports.iter().map(|report| report.pending).max() {
                    status.pending = pending as u32;
                }
            }),
            Err(osm_vault_peer::Error::Removed) => {
                self.mark_removed();
                self.update_status(|status| {
                    status.state = SyncState::Removed;
                    status.message = Some("this device was removed from the vault".into());
                });
            }
            Err(error) => self.update_status(|status| {
                status.members = members;
                if status.state != SyncState::Removed {
                    status.state = SyncState::Error;
                    status.message = Some(error.to_string());
                }
            }),
        }
    }
}
