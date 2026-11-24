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

use osm_vault_core::{
    passkey::{self, Ceremony, Registering, Signing, UserVerification},
    Item, ItemKind, Origin, Vault, VaultItem,
};
use osm_vault_membership::{ControlNode, DeviceId, NodeOptions};
use osm_vault_peer::{
    control, serve_members, serve_relayed, start_node, AddressBook, Invitation, MemberEndpoint,
    MemberSync, PairingConnection, PeerStore, PreparedJoin, Relay, RelayCode, SyncReport,
};
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

use zeroize::Zeroizing;

use crate::{
    fill::{self, AppChoices, Asks, Filled, Offer, Requester},
    CardDetail, CardFill, DeletedEntry, DeviceState, HistoryEntry, ItemDetail, ItemDraft,
    ItemSummary, MobileError, PasskeyCaller, PasskeyChoice, PasskeyCreation, PasskeyRefusal,
    PasskeySignIn, PasswordHealth, RebasedEdit, ReusedPassword, SaveCandidate, SyncState,
    SyncStatus, WeakPassword, Weakness,
};

/// The first eight hex digits of a device's ID, as the screens name it.
fn short_device(id: &[u8; 16]) -> String {
    id[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

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
    /// Where sync connections are handed to be run against the vault.
    sync: mpsc::Sender<MemberSync>,
    /// The relay this device reaches others through, while it uses one: its
    /// code, and what serves the connections that come through it.
    relay: StdMutex<Option<(Zeroizing<String>, JoinHandle<()>)>>,
}

impl Control {
    fn stop_relay(&self) {
        if let Some((_, serving)) = self
            .relay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            serving.abort();
        }
        self.endpoint.set_relay(None);
    }

    async fn stop(&self) {
        self.stop_relay();
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

/// Marks a sync under way until it ends, also when its task is stopped
/// part-way, as going offline stops it: a mark left behind would make
/// every later sync do nothing, and a sync in the background wait for it
/// without end.
struct SyncUnderWay<'a>(&'a AtomicBool);

impl Drop for SyncUnderWay<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
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
    app_choices: AppChoices,
}

/// Who asks for a passkey, read: the page whose domains it may use, the
/// origin its client data names, and the hash of the client data a browser
/// made, if it did.
pub(crate) struct Asking {
    pub(crate) page: Option<Origin>,
    origin: String,
    client_data_hash: Option<[u8; 32]>,
}

impl Asking {
    pub(crate) fn of(caller: &PasskeyCaller) -> Result<Self, MobileError> {
        match caller {
            PasskeyCaller::Page {
                origin,
                client_data_hash,
            } => {
                let page = Origin::of_url(origin).ok_or(MobileError::InvalidOrigin)?;
                let client_data_hash = client_data_hash
                    .as_deref()
                    .map(|hash| {
                        <[u8; 32]>::try_from(hash).map_err(|_| MobileError::PasskeyRefused {
                            refusal: PasskeyRefusal::Malformed,
                            reason: "the browser's client data hash is not one".into(),
                        })
                    })
                    .transpose()?;
                Ok(Self {
                    origin: page.to_string(),
                    page: Some(page),
                    client_data_hash,
                })
            }
            PasskeyCaller::App { certificate_sha256 } => {
                let certificate = <[u8; 32]>::try_from(certificate_sha256.as_slice())
                    .map_err(|_| MobileError::InvalidOrigin)?;
                Ok(Self {
                    page: None,
                    origin: passkey::android_app_origin(&certificate),
                    client_data_hash: None,
                })
            }
        }
    }

    /// The client data the site is sent, and the hash that is signed. A
    /// browser that made its own sends the site that one, so the response
    /// holds a placeholder, as Android's guide for providers says; otherwise
    /// it is made here.
    fn client_data(&self, ceremony: Ceremony, challenge: &[u8]) -> (Vec<u8>, [u8; 32]) {
        match self.client_data_hash {
            Some(hash) => (b"{}".to_vec(), hash),
            None => {
                let data = passkey::client_data(ceremony, challenge, &self.origin);
                let hash = passkey::client_data_hash(&data);
                (data, hash)
            }
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// A device store that would not open: the device cannot be used, as with a
/// vault file it cannot open, and the store is named, and said to be a later
/// version's when it is. It is left as it is.
fn store_problem(file: &str, error: osm_vault_peer::Error) -> MobileError {
    let reason = if matches!(
        error,
        osm_vault_peer::Error::Sync(osm_vault_sync::Error::UnsupportedVersion)
    ) {
        format!("{file} was written by a later version of Open Secret Manager")
    } else {
        format!("{file} cannot be opened: {error}")
    };
    MobileError::UnreadableVault { reason }
}

impl Runtime {
    pub(crate) async fn open(
        directory: PathBuf,
        port: u16,
        keystore: Arc<dyn osm_vault_peer::Keystore>,
    ) -> Result<Self, MobileError> {
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
        let peers = PeerStore::open(&peers_path, keystore)
            .map_err(|error| store_problem(PEERS_FILE, error))?;
        let addresses =
            AddressBook::open(&peers_path).map_err(|error| store_problem(PEERS_FILE, error))?;
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
            app_choices: AppChoices::in_folder(&directory),
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

    pub(crate) async fn change_password(
        &self,
        current: &str,
        new: &str,
    ) -> Result<(), MobileError> {
        if new.chars().count() < MIN_PASSWORD_CHARS {
            return Err(MobileError::PasswordTooShort {
                minimum: MIN_PASSWORD_CHARS as u32,
            });
        }
        let mut vault = self.vault.lock().await;
        let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
        vault.change_password(current, new)?;
        Ok(())
    }

    pub(crate) async fn rows_changed(&self) -> bool {
        self.vault
            .lock()
            .await
            .as_ref()
            .is_some_and(|vault| vault.is_unlocked() && vault.rows_changed())
    }

    pub(crate) async fn confirm_rows_changed(&self) -> Result<(), MobileError> {
        let mut vault = self.vault.lock().await;
        let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
        vault.confirm_rows_changed()?;
        Ok(())
    }

    pub(crate) async fn items(&self) -> Result<Vec<ItemSummary>, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        Ok(vault.list()?.into_iter().map(ItemSummary::from).collect())
    }

    pub(crate) async fn password_health(&self) -> Result<PasswordHealth, MobileError> {
        use osm_vault_core::health::Weakness as Core;
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let health = vault.password_health()?;
        Ok(PasswordHealth {
            weak: health
                .weak
                .into_iter()
                .map(|weak| WeakPassword {
                    id: weak.id,
                    reasons: weak
                        .reasons
                        .into_iter()
                        .map(|reason| match reason {
                            Core::TooShort => Weakness::TooShort,
                            Core::OneKind => Weakness::OneKind,
                            Core::Common => Weakness::Common,
                            Core::HoldsOwnName => Weakness::HoldsOwnName,
                        })
                        .collect(),
                })
                .collect(),
            reused: health
                .reused
                .into_iter()
                .map(|ids| ReusedPassword { ids })
                .collect(),
        })
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
            fields: item
                .custom_fields
                .keys()
                .filter(|name| {
                    item.kind != osm_vault_core::ItemKind::Card
                        || !osm_vault_core::card::CARD_FIELDS.contains(&name.as_str())
                })
                .cloned()
                .collect(),
            card: (item.kind == osm_vault_core::ItemKind::Card).then(|| CardDetail::of(item)),
            passkeys: item
                .passkeys
                .iter()
                .map(|passkey| passkey.summary().into())
                .collect(),
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

    pub(crate) async fn rebase_edit(
        &self,
        id: &str,
        revision: &str,
        draft: ItemDraft,
    ) -> Result<RebasedEdit, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let VaultItem {
            item: now,
            revision: current,
            conflict,
        } = vault.get(id)?;
        if conflict {
            return Err(MobileError::InConflict);
        }
        let read = vault
            .history(id)?
            .into_iter()
            .find(|version| version.revision == revision)
            .and_then(|version| version.item)
            .ok_or(MobileError::NotFound)?;
        Ok(RebasedEdit {
            changed_elsewhere: now
                .changed_from(&read)
                .into_iter()
                .map(str::to_owned)
                .collect(),
            draft: draft.rebased(&read, &now),
            revision: current,
        })
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

    pub(crate) async fn remove_passkey(
        self: &Arc<Self>,
        id: &str,
        revision: &str,
        credential_id: &str,
    ) -> Result<(), MobileError> {
        {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            if vault.get(id)?.conflict {
                return Err(MobileError::InConflict);
            }
            vault.remove_passkey(id, revision, credential_id)?;
        }
        self.sync_soon();
        Ok(())
    }

    pub(crate) async fn history(&self, id: &str) -> Result<Vec<HistoryEntry>, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let this_device = vault.device_id();
        let history = vault.history(id)?;
        Ok(history
            .iter()
            .map(|version| {
                // What a deletion deleted: the version it followed.
                let shown = version.item.as_ref().or_else(|| {
                    version.parents.iter().find_map(|parent| {
                        history
                            .iter()
                            .find(|other| &other.revision == parent)
                            .and_then(|other| other.item.as_ref())
                    })
                });
                HistoryEntry {
                    revision: version.revision.clone(),
                    deleted: version.item.is_none(),
                    current: version.current,
                    first: version.parents.is_empty(),
                    merged: version.parents.len() > 1,
                    title: shown.map(|item| item.title.clone()).unwrap_or_default(),
                    username: shown.map(|item| item.username.clone()).unwrap_or_default(),
                    url: shown.map(|item| item.url.clone()).unwrap_or_default(),
                    changed: version
                        .changed
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect(),
                    device: short_device(&version.author_device_id),
                    this_device: Some(version.author_device_id) == this_device,
                    saved_at: version.saved_at,
                }
            })
            .collect())
    }

    pub(crate) async fn deleted_items(&self) -> Result<Vec<DeletedEntry>, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let this_device = vault.device_id();
        Ok(vault
            .deleted_items()?
            .into_iter()
            .filter_map(|deleted| {
                let item = deleted.last.item.as_ref()?;
                Some(DeletedEntry {
                    id: deleted.item_id.clone(),
                    title: item.title.clone(),
                    kind: item.kind.into(),
                    username: item.username.clone(),
                    url: item.url.clone(),
                    last: deleted.last.revision.clone(),
                    device: short_device(&deleted.deleted_by),
                    this_device: Some(deleted.deleted_by) == this_device,
                    deleted_at: deleted.deleted_at,
                    heads: deleted.heads,
                })
            })
            .collect())
    }

    pub(crate) async fn restore(
        self: &Arc<Self>,
        id: &str,
        revision: &str,
        heads: &[String],
    ) -> Result<(), MobileError> {
        {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            let history = vault.history(id)?;
            if history.iter().filter(|version| version.current).count() > 1 {
                return Err(MobileError::InConflict);
            }
            let version = history
                .iter()
                .find(|version| version.revision == revision)
                .ok_or(MobileError::NotFound)?;
            let item = version
                .item
                .as_ref()
                .ok_or_else(|| MobileError::InvalidItem {
                    reason: "that version deletes the item: choose one before it".into(),
                })?;
            if !crate::ItemKind::from(item.kind).editable_here() {
                return Err(MobileError::NotEditableHere);
            }
            vault.restore(id, revision, heads)?;
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

    pub(crate) async fn field(&self, id: &str, name: &str) -> Result<String, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let item = vault.get(id)?.item;
        item.custom_fields
            .get(name)
            .cloned()
            .ok_or(MobileError::NoSuchField)
    }

    pub(crate) async fn one_time_code(&self, id: &str) -> Result<String, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        if vault.get(id)?.item.totp_secret.is_none() {
            return Err(MobileError::NoOneTimeCode);
        }
        Ok(vault.item_totp_code(id, now())?)
    }

    pub(crate) async fn passkey_creation(
        &self,
        options: &str,
        caller: &PasskeyCaller,
    ) -> Result<PasskeyCreation, MobileError> {
        let asking = Asking::of(caller)?;
        let request = Registering::from_options(options, asking.page.as_ref())?;
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let logins = vault
            .logins_for_site(&request.rp_id)?
            .into_iter()
            .map(ItemSummary::from)
            .collect();
        Ok(PasskeyCreation {
            rp_id: request.rp_id.clone(),
            rp_name: request.rp_name.clone(),
            user_name: request.user_name.clone(),
            user_display_name: request.user_display_name.clone(),
            verification: request.user_verification.into(),
            logins,
        })
    }

    pub(crate) async fn create_passkey(
        self: &Arc<Self>,
        options: &str,
        caller: &PasskeyCaller,
        verified: bool,
        into: Option<&str>,
    ) -> Result<String, MobileError> {
        let asking = Asking::of(caller)?;
        let request = Registering::from_options(options, asking.page.as_ref())?;
        if request.user_verification == UserVerification::Required && !verified {
            return Err(MobileError::NotVerified);
        }
        let response = {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            // Asked only now that the owner chose to save, so that a site
            // learns nothing of the vault before.
            if vault.holds_passkey(&request.rp_id, &request.exclude)? {
                return Err(MobileError::PasskeyExists);
            }
            let created = request.create(verified, now())?;
            let (client_data, _) = asking.client_data(Ceremony::Create, &request.challenge);
            let response = created.registration.response_json(&client_data);
            match into {
                Some(id) => {
                    let found = vault.get(id)?;
                    if found.conflict {
                        return Err(MobileError::InConflict);
                    }
                    if found.item.kind != ItemKind::Login {
                        return Err(MobileError::NotALogin);
                    }
                    vault.add_passkey(id, &found.revision, created.passkey)?;
                }
                None => {
                    vault.save_passkey_as_login(created.passkey, &request.rp_id)?;
                }
            }
            response
        };
        self.sync_soon();
        Ok(response)
    }

    pub(crate) async fn passkey_sign_in(
        &self,
        options: &str,
        caller: &PasskeyCaller,
    ) -> Result<PasskeySignIn, MobileError> {
        let asking = Asking::of(caller)?;
        let request = Signing::from_options(options, asking.page.as_ref())?;
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        let passkeys = vault
            .passkeys_for(&request.rp_id, &request.allowed)?
            .into_iter()
            .map(|found| PasskeyChoice {
                item_id: found.item_id,
                title: found.title,
                credential_id: found.passkey.credential_id,
                user_name: found.passkey.user_name,
                user_display_name: found.passkey.user_display_name,
            })
            .collect();
        Ok(PasskeySignIn {
            rp_id: request.rp_id,
            verification: request.user_verification.into(),
            passkeys,
        })
    }

    pub(crate) async fn sign_in_with_passkey(
        &self,
        options: &str,
        caller: &PasskeyCaller,
        item_id: &str,
        credential_id: &str,
        verified: bool,
    ) -> Result<String, MobileError> {
        let asking = Asking::of(caller)?;
        let request = Signing::from_options(options, asking.page.as_ref())?;
        if request.user_verification == UserVerification::Required && !verified {
            return Err(MobileError::NotVerified);
        }
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        // Only one the site takes, whatever was chosen.
        if !vault
            .passkeys_for(&request.rp_id, &request.allowed)?
            .iter()
            .any(|found| found.item_id == item_id && found.passkey.credential_id == credential_id)
        {
            return Err(MobileError::NotFound);
        }
        let (client_data, hash) = asking.client_data(Ceremony::Get, &request.challenge);
        let assertion = vault.sign_with_passkey(
            item_id,
            credential_id,
            &request.rp_id,
            &hash,
            verified,
            now(),
        )?;
        Ok(assertion.response_json(&client_data))
    }

    pub(crate) async fn offer(
        &self,
        requester: &Requester,
        asks: Asks,
    ) -> Result<Offer, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        fill::offer(vault, &self.app_choices, requester, asks)
    }

    pub(crate) async fn fill(
        &self,
        requester: &Requester,
        id: &str,
        asks: Asks,
        owner_chose: bool,
    ) -> Result<Filled, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        fill::fill(
            vault,
            &self.app_choices,
            requester,
            id,
            asks,
            owner_chose,
            now(),
        )
    }

    pub(crate) async fn logins_to_choose(
        &self,
        asks: Asks,
    ) -> Result<Vec<ItemSummary>, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        fill::logins_to_choose(vault, asks)
    }

    pub(crate) async fn offer_cards(&self) -> Result<Vec<ItemSummary>, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        fill::offer_cards(vault)
    }

    pub(crate) async fn fill_card(&self, id: &str) -> Result<CardFill, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        fill::fill_card(vault, id)
    }

    pub(crate) async fn save_candidates_for(
        &self,
        requester: &Requester,
        username: &str,
        password: &str,
    ) -> Result<Vec<SaveCandidate>, MobileError> {
        let vault = self.vault.lock().await;
        let vault = vault.as_ref().ok_or(MobileError::NoVault)?;
        fill::save_candidates(vault, &self.app_choices, requester, username, password)
    }

    pub(crate) async fn update_saved(
        self: &Arc<Self>,
        requester: &Requester,
        id: &str,
        revision: &str,
        username: &str,
        password: String,
    ) -> Result<(), MobileError> {
        {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            fill::update_saved(
                vault,
                &self.app_choices,
                requester,
                id,
                revision,
                username,
                password,
            )?;
        }
        self.sync_soon();
        Ok(())
    }

    pub(crate) async fn save_new(
        self: &Arc<Self>,
        requester: &Requester,
        title: String,
        username: String,
        password: String,
    ) -> Result<String, MobileError> {
        let id = {
            let mut vault = self.vault.lock().await;
            let vault = vault.as_mut().ok_or(MobileError::NoVault)?;
            fill::save_new(
                vault,
                &self.app_choices,
                requester,
                title,
                username,
                password,
            )?
        };
        self.sync_soon();
        Ok(id)
    }

    pub(crate) fn import_app_choices(
        &self,
        earlier: std::collections::HashMap<String, Vec<String>>,
    ) -> Result<(), MobileError> {
        Ok(self.app_choices.import(earlier)?)
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
        let mut connection = prepared.connect().await?;
        // The relay an invitation for a device that is away names: this
        // device is registered at it already, and the vault's devices reach
        // it there while they enroll it.
        let relay = connection.take_relay();
        let relay_code = connection
            .joiner()
            .invitation_relay()
            .and_then(|code| code.encode().ok());
        // The node runs from here on so that the leader can bring this
        // device up to date. It accepts no one until the inviting device
        // names the members.
        let joiner = connection.joiner();
        let control = self
            .start_control(joiner.vault_id(), joiner.control_device())
            .await?;
        if let (Some((relay, relayed)), Some(code)) = (relay, relay_code) {
            // Kept in memory while the join lasts, and in the peer store once
            // it has succeeded (`join_finish`): a join that is given up, or
            // quit, leaves nothing behind for the next vault to use.
            control.stop_relay();
            control.endpoint.set_relay(Some(relay));
            let serving = tokio::spawn(serve_relayed(
                relayed,
                control.endpoint.clone(),
                control.node.clone(),
                Some(control.sync.clone()),
            ));
            *control
                .relay
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((code, serving));
        }
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
        // The relay the invitation named is this device's until the vault
        // says otherwise; kept now, for a start before the first sync.
        let from_invitation = control
            .relay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|(code, _)| code.clone());
        if let Some(code) = from_invitation {
            let _ = self.peers.lock().await.set_relay_code(Some(&code));
        }
        self.maintain(&control).await;
        // Fetch the vault's contents right away.
        self.sync_once(&control);
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
        control.endpoint.introduce_grant(&joiner, &grant)?;
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
        let _ = self.peers.lock().await.set_relay_code(None);
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
        self.sync_once(&control);
        Ok(())
    }

    /// Starts a sync with the members as one of the control plane's tasks,
    /// so that going offline stops it with the others: one left running
    /// would still send what was written after.
    fn sync_once(self: &Arc<Self>, control: &Control) {
        let runtime = self.clone();
        let sync = tokio::spawn(async move {
            let _ = runtime.sync_with_members().await;
        });
        control
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(sync);
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

    pub(crate) async fn sync_in_background(self: &Arc<Self>) -> Result<SyncStatus, MobileError> {
        let was_online = self.control.lock().await.is_some();
        if !was_online {
            // Going online starts a sync of its own.
            self.go_online().await?;
        }
        // A sync of its own once none is under way (one under way would make
        // it a no-op), and none under way when it goes offline again.
        self.no_sync_under_way().await;
        let result = self.sync_with_members().await;
        self.no_sync_under_way().await;
        if !was_online {
            self.go_offline().await;
        }
        result.map(|()| self.status())
    }

    async fn no_sync_under_way(&self) {
        while self.syncing.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
        // Over IPv6 and IPv4 alike.
        let listener = match osm_vault_peer::listen(self.port) {
            Ok(listener) => listener,
            Err(_) => osm_vault_peer::listen(0)?,
        };
        endpoint.set_listen_port(listener.local_addr()?.port());
        let (sync, incoming) = mpsc::channel(4);
        let control = Arc::new(Control {
            endpoint: endpoint.clone(),
            node: node.clone(),
            tasks: StdMutex::new(Vec::new()),
            sync: sync.clone(),
            relay: StdMutex::new(None),
        });
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
        // The relay the vault named when it was last unlocked here, if any.
        let cached = self.peers.lock().await.relay_code().ok().flatten();
        self.use_relay(&control, cached).await;
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
            self.refresh_relay(&control).await;
        }
    }

    /// Uses the relay `code` names, or none. A code that does not read as
    /// one is not used.
    async fn use_relay(&self, control: &Control, code: Option<Zeroizing<String>>) {
        let running = control
            .relay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|(code, _)| code.clone());
        if running.as_deref() == code.as_deref() {
            return;
        }
        control.stop_relay();
        let Some(code) = code else {
            return;
        };
        let Ok(relay_code) = RelayCode::decode(&code) else {
            return;
        };
        let Ok(identity) = self.peers.lock().await.transport_identity() else {
            return;
        };
        let (relay, relayed) = Relay::start(relay_code, identity);
        control.endpoint.set_relay(Some(relay));
        let serving = tokio::spawn(serve_relayed(
            relayed,
            control.endpoint.clone(),
            control.node.clone(),
            Some(control.sync.clone()),
        ));
        *control
            .relay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((code, serving));
    }

    /// While the vault is unlocked, brings this device's relay in line with
    /// the vault's: keeps its code for when the vault is locked, and uses it.
    async fn refresh_relay(&self, control: &Control) {
        let wanted = {
            let vault = self.vault.lock().await;
            match vault.as_ref().filter(|vault| vault.is_unlocked()) {
                Some(vault) => match (vault.relay(), vault.has_relay_setting()) {
                    (Ok(wanted), Ok(said)) if said || wanted.is_some() => wanted,
                    // The vault has not said yet: a device that joined
                    // through an invitation's relay keeps it until it does.
                    _ => return,
                },
                None => return,
            }
        };
        {
            let mut peers = self.peers.lock().await;
            if peers.relay_code().ok().flatten().as_deref() != wanted.as_deref() {
                let _ = peers.set_relay_code(wanted.as_deref().map(String::as_str));
            }
        }
        self.use_relay(control, wanted).await;
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
        control.endpoint.forget_departed(&state);
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
        self.refresh_relay(control).await;
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
        let under_way = SyncUnderWay(&self.syncing);
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
        drop(under_way);
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
        self.refresh_relay(&control).await;
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
