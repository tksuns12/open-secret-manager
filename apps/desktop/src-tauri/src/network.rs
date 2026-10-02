//! Devices, pairing, and sync for the desktop shell.
//!
//! Which devices belong to a vault is decided by its control plane, in
//! which a majority of the devices must agree to every change. While the
//! app is open, locked or unlocked, this device runs its control-plane node
//! and one listener for the other members. Only their certificates are
//! accepted; anything else fails the TLS handshake before the vault is
//! touched. A locked vault still takes part in decisions and still
//! receives: revisions are staged and verified at the next unlock.
//!
//! Whenever committed membership changes, and right after unlock before
//! anything received is verified, the vault is brought in line with it:
//! authors, removed devices, and key epochs. This device syncs with every
//! member shortly after a local change, at unlock, and when the owner asks.
//! Status reaches the interface as `sync-status` and `devices-changed`
//! events.
//!
//! Network waits never hold the vault: handshakes happen first, a sync
//! session takes the vault one message at a time, and while the owner
//! compares pairing codes nothing is locked.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use osm_vault_membership::{
    device_id_from_bytes, device_id_to_bytes, ControlNode, DeviceId, MembershipChange, NodeOptions,
    Rejection,
};
use osm_vault_peer::{
    control, invite, serve_members, start_node, AddressBook, Invitation, MemberEndpoint,
    MemberSync, PairingConnection, PairingListener, PeerStore, PendingJoin, PreparedJoin,
    MAX_INVITATION_TTL_SECS,
};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use serde::Serialize;
use tauri::{async_runtime::JoinHandle, AppHandle, Emitter, Manager, Runtime};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, Mutex},
};

use crate::{AppState, CommandError};

/// Preferred port for the other members; another is used if it is taken.
const SYNC_PORT: u16 = 47_820;
/// Wait after a local change before dialing, so a burst of edits syncs once.
const SYNC_DELAY: Duration = Duration::from_secs(2);
/// How long a joining device waits to be enrolled and given the keys once
/// the inviting device has accepted it.
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(120);
/// How often a device with nothing else to do checks whether a member has
/// told it that it was removed.
const WATCH_INTERVAL: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 5 });

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// `local` (no other device to sync with), `idle`, `syncing`, `synced`,
    /// `received`, `error`, or `removed`.
    state: &'static str,
    last_synced_at: Option<u64>,
    message: Option<String>,
    /// How many other devices this one syncs with.
    devices: usize,
    /// Revisions received while locked, waiting for unlock.
    pending: usize,
}

/// This device's running control plane: its node, its endpoint, and the
/// tasks serving them.
struct Control {
    device: DeviceId,
    endpoint: MemberEndpoint,
    node: Arc<ControlNode>,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl Control {
    fn stop_tasks(&self) {
        let tasks = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for task in tasks {
            task.abort();
        }
    }

    async fn stop(&self) {
        self.stop_tasks();
        self.node.shutdown().await;
    }
}

pub struct Network {
    directory: PathBuf,
    peers: Mutex<PeerStore>,
    invitations: Mutex<InvitationStore>,
    addresses: StdMutex<AddressBook>,
    status: StdMutex<SyncStatus>,
    control: Mutex<Option<Arc<Control>>>,
    /// The inviter's pending decision, while a joiner waits.
    invite: Mutex<Option<InviteState>>,
    /// This device's own join, between showing the code and finishing.
    join: Mutex<Option<JoinState>>,
    /// A member said this device was removed, or committed state does.
    removed: AtomicBool,
    /// A reset after removal is under way.
    resetting: AtomicBool,
    syncing: AtomicBool,
    sync_generation: AtomicU64,
}

struct InviteState {
    decision: Option<oneshot::Sender<bool>>,
    task: JoinHandle<()>,
}

struct JoinState {
    connection: PairingConnection,
    control: Arc<Control>,
}

impl Network {
    pub fn open(vault_path: &Path) -> Result<Self, CommandError> {
        let directory = vault_path.parent().unwrap_or(Path::new(".")).to_owned();
        std::fs::create_dir_all(&directory).map_err(storage_error)?;
        let peers_path = directory.join("peers.sqlite3");
        let peers = PeerStore::open(&peers_path).map_err(network_error)?;
        let addresses = AddressBook::open(&peers_path).map_err(network_error)?;
        // One-use invitation tokens are recorded durably so a restart
        // cannot make a used token valid again.
        let invitations = InvitationStore::open(
            directory.join("invitations.sqlite3"),
            InvitationPolicy::default(),
        )
        .map_err(|error| network_error(error.into()))?;
        let removed = directory.join(REMOVED_MARKER).exists();
        Ok(Self {
            directory,
            peers: Mutex::new(peers),
            invitations: Mutex::new(invitations),
            addresses: StdMutex::new(addresses),
            status: StdMutex::new(SyncStatus {
                state: if removed { "removed" } else { "local" },
                message: removed.then(|| "this device was removed from the vault".into()),
                ..SyncStatus::default()
            }),
            control: Mutex::new(None),
            invite: Mutex::new(None),
            join: Mutex::new(None),
            removed: AtomicBool::new(removed),
            resetting: AtomicBool::new(false),
            syncing: AtomicBool::new(false),
            sync_generation: AtomicU64::new(0),
        })
    }

    /// Records that this device was removed, durably.
    fn mark_removed(&self) {
        self.removed.store(true, Ordering::SeqCst);
        let _ = std::fs::write(self.directory.join(REMOVED_MARKER), b"");
    }

    fn is_removed(&self) -> bool {
        self.removed.load(Ordering::SeqCst)
    }

    /// Forgets a removal that no longer concerns the vault on this device.
    fn clear_removed(&self) {
        self.removed.store(false, Ordering::SeqCst);
        let _ = std::fs::remove_file(self.directory.join(REMOVED_MARKER));
    }

    /// Why this device's copy of a vault was put away and where it was
    /// moved, if this device has had no vault since.
    fn reset_note(&self) -> Option<(PutAway, String)> {
        [PutAway::Removed, PutAway::Left]
            .into_iter()
            .find_map(|reason| {
                let archive = std::fs::read_to_string(self.directory.join(reason.note())).ok()?;
                Some((reason, archive))
            })
    }

    /// This device has a vault again: what happened to the last one no
    /// longer needs saying.
    fn clear_reset_note(&self) {
        for reason in [PutAway::Removed, PutAway::Left] {
            let _ = std::fs::remove_file(self.directory.join(reason.note()));
        }
        self.clear_removed();
    }

    fn control_path(&self) -> PathBuf {
        self.directory.join("control.sqlite3")
    }

    async fn control(&self) -> Option<Arc<Control>> {
        self.control.lock().await.clone()
    }

    /// Deletes the control-plane database of a node that never became part
    /// of a control plane.
    fn delete_control_database(&self) {
        let path = self.control_path();
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.clone().into_os_string();
            file.push(suffix);
            let _ = std::fs::remove_file(file);
        }
    }
}

/// The vault a recovery has finished writing, waiting to take the old
/// vault's place, and the same file while it is still being written.
const RECOVERED: &str = "recovered.sqlite3";
const RECOVERED_PARTIAL: &str = "recovered.sqlite3.partial";
/// Present once this device has learned that its vault's devices removed
/// it, so that it still knows after a restart: its own log may never say.
const REMOVED_MARKER: &str = "removed";
/// Left after a removed device was reset, naming the folder its copy was
/// moved to, until this device has a vault again. It lets the app say what
/// happened to the vault that was here.
const RESET_NOTE: &str = "reset-after-removal";
/// Left after the owner had this device's copy put away so that the device
/// can join another vault, naming the archive folder, until this device has
/// a vault again.
const LEFT_NOTE: &str = "left-vault";
/// Present while a copy is being put away: why, and the archive folder it
/// is going to, on two lines. An interruption is finished at the next
/// launch from this.
const PUTTING_AWAY: &str = "putting-away";
/// The files that belong to one vault on this device.
const VAULT_FILES: [&str; 4] = [
    "control.sqlite3",
    "peers.sqlite3",
    "invitations.sqlite3",
    REMOVED_MARKER,
];

/// Why a device's copy of its vault was put away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PutAway {
    /// The vault's devices removed this one.
    Removed,
    /// The owner asked for it on this device, to join another vault.
    Left,
}

impl PutAway {
    /// The note file that says so until this device has a vault again.
    fn note(self) -> &'static str {
        match self {
            Self::Removed => RESET_NOTE,
            Self::Left => LEFT_NOTE,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Left => "left",
        }
    }

    fn named(name: &str) -> Option<Self> {
        [Self::Removed, Self::Left]
            .into_iter()
            .find(|reason| reason.name() == name)
    }
}

/// Makes a new, empty archive folder beside the vault.
fn new_archive(directory: &Path) -> std::io::Result<PathBuf> {
    let mut archive = directory.join(format!("archive-{}", now()));
    let mut attempt = 1;
    while archive.exists() {
        archive = directory.join(format!("archive-{}-{attempt}", now()));
        attempt += 1;
    }
    std::fs::create_dir(&archive)?;
    Ok(archive)
}

/// Moves the vault and everything that belongs to it into a new archive
/// folder beside it.
fn archive_vault_files(vault_path: &Path, vault_first: bool) -> std::io::Result<PathBuf> {
    let archive = new_archive(vault_path.parent().unwrap_or(Path::new(".")))?;
    move_vault_files(vault_path, &archive, vault_first)?;
    Ok(archive)
}

/// Moves the vault and everything that belongs to it into `archive`. Each
/// step is a rename, and the steps can be repeated.
///
/// The vault file goes last when another vault is about to take its place,
/// so that a vault is there until then, and first when the device is being
/// reset, so that what an interruption leaves is a device without a vault
/// rather than a vault that has lost its control plane.
fn move_vault_files(vault_path: &Path, archive: &Path, vault_first: bool) -> std::io::Result<()> {
    let directory = vault_path.parent().unwrap_or(Path::new("."));
    let vault_name = vault_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut names: Vec<&str> = VAULT_FILES.to_vec();
    if vault_first {
        names.insert(0, &vault_name);
    } else {
        names.push(&vault_name);
    }
    for name in names {
        // The main file after its side files in either order.
        for suffix in ["-wal", "-shm", "-journal", ""] {
            let file = format!("{name}{suffix}");
            let from = directory.join(&file);
            if from.exists() {
                std::fs::rename(from, archive.join(&file))?;
            }
        }
    }
    Ok(())
}

/// Puts this device's copy of its vault away: everything moves to a new
/// archive folder, and a note says why and where. What is under way is
/// written down first, so that an interruption is finished at the next
/// launch instead of leaving half of the files behind.
fn put_away(vault_path: &Path, reason: PutAway) -> std::io::Result<PathBuf> {
    let directory = vault_path.parent().unwrap_or(Path::new("."));
    let archive = new_archive(directory)?;
    std::fs::write(
        directory.join(PUTTING_AWAY),
        format!("{}\n{}", reason.name(), archive.to_string_lossy()),
    )?;
    finish_put_away(vault_path, reason, &archive)?;
    Ok(archive)
}

fn finish_put_away(vault_path: &Path, reason: PutAway, archive: &Path) -> std::io::Result<()> {
    let directory = vault_path.parent().unwrap_or(Path::new("."));
    move_vault_files(vault_path, archive, true)?;
    std::fs::write(
        directory.join(reason.note()),
        archive.to_string_lossy().as_bytes(),
    )?;
    std::fs::remove_file(directory.join(PUTTING_AWAY))
}

/// Archives the old vault and puts the recovered vault in its place.
fn replace_with_recovered(vault_path: &Path) -> std::io::Result<PathBuf> {
    let directory = vault_path.parent().unwrap_or(Path::new("."));
    let archive = archive_vault_files(vault_path, false)?;
    std::fs::rename(directory.join(RECOVERED), vault_path)?;
    Ok(archive)
}

/// At launch, before the vault or any of its stores is opened: finishes a
/// recovery that was interrupted after the new vault was complete, discards
/// one that was interrupted before, and finishes putting a copy away.
pub fn finish_interrupted_recovery(vault_path: &Path) {
    let directory = vault_path.parent().unwrap_or(Path::new("."));
    let _ = std::fs::remove_file(directory.join(RECOVERED_PARTIAL));
    if directory.join(RECOVERED).exists() {
        let _ = replace_with_recovered(vault_path);
    }
    let marker = directory.join(PUTTING_AWAY);
    if let Ok(under_way) = std::fs::read_to_string(&marker) {
        let finished = under_way.split_once('\n').and_then(|(reason, archive)| {
            let archive = Path::new(archive);
            // Only a folder this app made beside the vault is trusted.
            (archive.parent() == Some(directory) && archive.is_dir())
                .then(|| finish_put_away(vault_path, PutAway::named(reason)?, archive).ok())
                .flatten()
        });
        if finished.is_none() {
            let _ = std::fs::remove_file(marker);
        }
    }
}

fn network<R: Runtime>(app: &AppHandle<R>) -> &Network {
    &app.state::<AppState>().inner().network
}

fn update_status<R: Runtime>(app: &AppHandle<R>, change: impl FnOnce(&mut SyncStatus)) {
    let snapshot = {
        let mut status = network(app)
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        change(&mut status);
        status.clone()
    };
    let _ = app.emit("sync-status", snapshot);
}

fn node_options() -> NodeOptions {
    if cfg!(test) {
        // Tests run several shells in one process and should not wait out
        // production election timeouts.
        NodeOptions {
            config: osm_vault_membership::timing(100, 600, 1200)
                .expect("test Raft timing is valid"),
            write_timeout: Duration::from_secs(4),
            ..NodeOptions::default()
        }
    } else {
        NodeOptions::default()
    }
}

/// Starts this device's control-plane node and listener, if they are not
/// running: the node under `device` in the control plane of `vault_id`.
async fn start_control<R: Runtime>(
    app: &AppHandle<R>,
    vault_id: [u8; 32],
    device: DeviceId,
) -> Result<Arc<Control>, CommandError> {
    let net = network(app);
    let mut slot = net.control.lock().await;
    if let Some(control) = slot.as_ref() {
        return Ok(control.clone());
    }
    let endpoint = {
        let mut peers = net.peers.lock().await;
        let addresses = net
            .addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        MemberEndpoint::new(vault_id, &mut peers, addresses).map_err(network_error)?
    };
    let node = start_node(net.control_path(), device, &endpoint, node_options())
        .await
        .map_err(network_error)?;
    let listener = match TcpListener::bind(("0.0.0.0", SYNC_PORT)).await {
        Ok(listener) => listener,
        Err(_) => TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(storage_error)?,
    };
    endpoint.set_listen_port(listener.local_addr().map_err(storage_error)?.port());
    let control = Arc::new(Control {
        device,
        endpoint: endpoint.clone(),
        node: node.clone(),
        tasks: StdMutex::new(Vec::new()),
    });
    let (sync, incoming) = mpsc::channel(4);
    let tasks = vec![
        tauri::async_runtime::spawn(serve_members(listener, endpoint, node, Some(sync))),
        tauri::async_runtime::spawn(receive(app.clone(), control.clone(), incoming)),
        tauri::async_runtime::spawn(watch(app.clone(), control.clone())),
    ];
    *control
        .tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = tasks;
    *slot = Some(control.clone());
    drop(slot);
    // Tell the members this device already knows where it listens now.
    let announcer = control.clone();
    tauri::async_runtime::spawn(async move {
        announcer.endpoint.announce_all().await;
    });
    Ok(control)
}

/// Stops the control plane and forgets a node that never joined one. Used
/// when a join is abandoned.
async fn abandon_control<R: Runtime>(app: &AppHandle<R>) {
    let net = network(app);
    if let Some(control) = net.control.lock().await.take() {
        control.stop().await;
    }
    net.delete_control_database();
}

/// Stops this device's control plane, as closing the app does.
#[cfg(test)]
pub async fn shutdown<R: Runtime>(app: &AppHandle<R>) {
    if let Some(control) = network(app).control.lock().await.take() {
        control.stop().await;
    }
}

/// At launch: resumes the control plane this device belongs to, locked or
/// not, and clears what an abandoned join left behind.
pub fn start<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let net = network(&app);
        let identity = {
            let app_state = app.state::<AppState>();
            let vault = app_state.vault.lock().await;
            vault
                .as_ref()
                .and_then(|vault| Some((vault.vault_id(), vault.device_id()?)))
        };
        let Some((vault_id, device)) = identity else {
            // Without a vault, a control database is what an unfinished
            // join left: its device identity is gone.
            net.delete_control_database();
            net.clear_removed();
            return;
        };
        // The app stopped after learning this device was removed and
        // before it was reset: finish that.
        if net.is_removed() {
            let _ = reset_removed(&app).await;
            return;
        }
        if !net.control_path().exists() {
            return;
        }
        let Ok(control) = start_control(&app, vault_id, device_id_from_bytes(device)).await else {
            return;
        };
        // A node that was never initialized and received nothing belongs
        // to no control plane: an in-place join was abandoned.
        let initialized = control.node.raft().is_initialized().await.unwrap_or(true);
        if !initialized && control.node.state().epoch == 0 {
            abandon_control(&app).await;
            return;
        }
        maintain(&app, &control).await;
    });
}

/// Runs the sync connections other members open to this device.
async fn receive<R: Runtime>(
    app: AppHandle<R>,
    control: Arc<Control>,
    mut incoming: mpsc::Receiver<MemberSync>,
) {
    while let Some(connection) = incoming.recv().await {
        update_status(&app, |status| status.state = "syncing");
        let state = app.state::<AppState>();
        let result = connection
            .run_shared(&state.vault, &control.node.state())
            .await;
        finish_sync(&app, result.map(|report| vec![report])).await;
    }
}

/// Keeps the vault in line with committed membership: whenever applied
/// state changes, and at intervals in case a member said this device was
/// removed. Ends, stopping the control plane, once it was.
async fn watch<R: Runtime>(app: AppHandle<R>, control: Arc<Control>) {
    let mut applied = control.node.subscribe();
    loop {
        tokio::select! {
            changed = applied.changed() => {
                if changed.is_err() {
                    return;
                }
                maintain(&app, &control).await;
            }
            _ = tokio::time::sleep(WATCH_INTERVAL) => {
                if control.endpoint.told_removed() {
                    maintain(&app, &control).await;
                }
            }
        }
        if network(&app).is_removed() {
            // The reset that follows stops this device's control plane.
            return;
        }
    }
}

/// Brings the vault in line with committed control state. While locked
/// that only stops writes under a superseded key. Unlocked, it also takes
/// in authors, removals, and epoch keys, then verifies what was received
/// and waiting, and gives members the keys they lack.
async fn maintain<R: Runtime>(app: &AppHandle<R>, control: &Control) {
    let net = network(app);
    let state = control.node.state();
    let app_state = app.state::<AppState>();
    let mut removed = control.endpoint.told_removed();
    let mut grants = Vec::new();
    let mut vault_changed = false;
    let mut pending = None;
    let mut failure = None;
    {
        let mut vault = app_state.vault.lock().await;
        if let Some(vault) = vault.as_mut() {
            match control::reconcile(vault, &state) {
                Ok(reconciled) => removed |= reconciled.removed,
                Err(error) => failure = Some(error.to_string()),
            }
            if failure.is_none() && !removed && vault.is_unlocked() {
                match vault.process_staged() {
                    Ok(processed) => {
                        vault_changed = processed.applied > 0 || processed.quarantined > 0;
                        pending = Some(processed.pending);
                        if processed.rejected > 0 {
                            failure = Some(format!(
                                "{} received revisions failed verification and were discarded",
                                processed.rejected
                            ));
                        }
                    }
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
        net.mark_removed();
        reset_soon(app);
    }
    let devices = control.endpoint.sync_peers().len();
    update_status(app, |status| {
        status.devices = devices;
        if let Some(pending) = pending {
            status.pending = pending;
            if status.state == "received" {
                status.state = "synced";
            }
        }
        if removed {
            status.state = "removed";
            status.message = Some("this device was removed from the vault".into());
        } else if let Some(failure) = failure {
            status.state = "error";
            status.message = Some(failure);
        } else if devices == 0 {
            status.state = "local";
        } else if status.state == "local" {
            status.state = "idle";
        }
    });
    let _ = app.emit("devices-changed", ());
    if vault_changed {
        let _ = app.emit("vault-changed", ());
    }
}

/// Founds the vault's control plane with this device as its first member.
async fn found<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<Control>, CommandError> {
    let net = network(app);
    let (vault_id, device, founding) = {
        // Both guards first: a `&Vault` cannot be held across an await.
        let app_state = app.state::<AppState>();
        let vault = app_state.vault.lock().await;
        let mut peers = net.peers.lock().await;
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?;
        let device = vault.device_id().ok_or_else(locked)?;
        let founding = control::Founding::prepare(vault, &mut peers).map_err(network_error)?;
        (vault.vault_id(), device_id_from_bytes(device), founding)
    };
    let control = start_control(app, vault_id, device).await?;
    founding
        .commit(&control.node)
        .await
        .map_err(network_error)?;
    // The device paired with before is an author from genesis on; it joins
    // as a member by invitation.
    net.peers
        .lock()
        .await
        .clear_legacy_peers()
        .map_err(network_error)?;
    maintain(app, &control).await;
    Ok(control)
}

/// Whether this device was paired by an older build, before vaults had a
/// control plane. The owner then chooses which of the two devices founds
/// it; the other joins with the vault it has.
async fn paired_before<R: Runtime>(app: &AppHandle<R>) -> bool {
    network(app)
        .peers
        .lock()
        .await
        .legacy_peers()
        .is_ok_and(|peers| !peers.is_empty())
}

/// Sets this vault up for device management if nothing stands in the way:
/// a vault that was never paired is founded here without asking.
async fn ensure_control<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<Control>> {
    let net = network(app);
    if let Some(control) = net.control().await {
        // Founding was interrupted before genesis: finish it.
        let joining = net.join.lock().await.is_some();
        if control.node.state().epoch == 0 && !joining {
            let _ = found(app).await;
        }
        return Some(control);
    }
    // A removed device still holds its vault but belongs to no control
    // plane; it must not found one for a vault that is not its to run.
    if net.is_removed() || net.join.lock().await.is_some() || paired_before(app).await {
        return None;
    }
    found(app).await.ok()
}

/// After this device creates a vault: its control plane starts with this
/// device as the only member. If that fails now, the next unlock does it.
pub async fn after_create<R: Runtime>(app: &AppHandle<R>) {
    network(app).clear_reset_note();
    let _ = ensure_control(app).await;
}

/// After unlock: the vault is first brought in line with committed
/// membership, only then is what arrived while locked verified, and then
/// this device catches up with the others.
pub async fn after_unlock<R: Runtime>(app: &AppHandle<R>) {
    match ensure_control(app).await {
        Some(control) => maintain(app, &control).await,
        None => {
            // No control plane yet, so no membership to judge against.
            let app_state = app.state::<AppState>();
            let mut vault = app_state.vault.lock().await;
            if let Some(vault) = vault.as_mut().filter(|vault| vault.is_unlocked()) {
                let _ = vault.process_staged();
            }
        }
    }
    let _ = app.emit("vault-changed", ());
    schedule_sync(app);
}

/// Records how a sync ended, for one or more sessions.
async fn finish_sync<R: Runtime>(
    app: &AppHandle<R>,
    result: Result<Vec<osm_vault_peer::SyncReport>, osm_vault_peer::Error>,
) {
    let unlocked = app
        .state::<AppState>()
        .vault
        .lock()
        .await
        .as_ref()
        .is_some_and(|vault| vault.is_unlocked());
    match result {
        Ok(reports) => {
            let received: usize = reports.iter().map(|report| report.received).sum();
            let changed = reports
                .iter()
                .any(|report| report.applied > 0 || report.quarantined > 0);
            let pending = reports.iter().map(|report| report.pending).max();
            update_status(app, |status| {
                if status.state == "removed" {
                    return;
                }
                status.state = if unlocked || received == 0 {
                    "synced"
                } else {
                    "received"
                };
                status.last_synced_at = Some(now());
                status.message = None;
                if let Some(pending) = pending {
                    status.pending = pending;
                }
            });
            if changed {
                let _ = app.emit("vault-changed", ());
            }
        }
        Err(osm_vault_peer::Error::Removed) => {
            network(app).mark_removed();
            update_status(app, |status| {
                status.state = "removed";
                status.message = Some("this device was removed from the vault".into());
            });
            let _ = app.emit("devices-changed", ());
            reset_soon(app);
        }
        Err(error) => update_status(app, |status| {
            if status.state != "removed" {
                status.state = "error";
                status.message = Some(error.to_string());
            }
        }),
    }
}

/// Syncs with every other member. At most one round runs at a time.
async fn sync_with_members<R: Runtime>(app: &AppHandle<R>) -> Result<(), CommandError> {
    let net = network(app);
    if net.is_removed() {
        return Err(network_error(osm_vault_peer::Error::Removed));
    }
    let Some(control) = net.control().await else {
        return Ok(());
    };
    if net.syncing.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let peers = control.endpoint.sync_peers();
    let mut reports = Vec::new();
    let mut failure = None;
    if !peers.is_empty() {
        update_status(app, |status| status.state = "syncing");
    }
    for device in peers {
        let session = async {
            let connection = control.endpoint.connect_sync(device).await?;
            let state = app.state::<AppState>();
            connection
                .run_shared(&state.vault, &control.node.state())
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
    net.syncing.store(false, Ordering::SeqCst);
    // One member being away is not a failed sync if another answered.
    let result = match failure {
        Some(osm_vault_peer::Error::Removed) => Err(osm_vault_peer::Error::Removed),
        Some(error) if reports.is_empty() => Err(error),
        _ => Ok(reports),
    };
    let outcome = match &result {
        Err(osm_vault_peer::Error::Removed) => Err(network_error(osm_vault_peer::Error::Removed)),
        Err(error) => Err(CommandError {
            code: "network",
            message: error.to_string(),
        }),
        Ok(_) => Ok(()),
    };
    if control.endpoint.sync_peers().is_empty() && result.is_ok() {
        return Ok(());
    }
    finish_sync(app, result).await;
    outcome
}

/// Syncs shortly after a local change. A newer change restarts the wait.
pub fn schedule_sync<R: Runtime>(app: &AppHandle<R>) {
    let net = network(app);
    let generation = net.sync_generation.fetch_add(1, Ordering::SeqCst) + 1;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SYNC_DELAY).await;
        if network(&app).sync_generation.load(Ordering::SeqCst) == generation {
            let _ = sync_with_members(&app).await;
        }
    });
}

#[tauri::command]
pub async fn sync_status(state: tauri::State<'_, AppState>) -> Result<SyncStatus, CommandError> {
    Ok(state
        .network
        .status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone())
}

#[tauri::command]
pub async fn sync_now<R: Runtime>(app: AppHandle<R>) -> Result<(), CommandError> {
    sync_with_members(&app).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInfo {
    /// The device ID in hex.
    pub(crate) id: String,
    pub(crate) this_device: bool,
    address: Option<String>,
    leader: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingInfo {
    /// `enroll` or `remove`.
    pub(crate) kind: &'static str,
    pub(crate) device: String,
    /// An enrollment that was cancelled and is being undone.
    cancelled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesInfo {
    /// `none`: no vault. `unmanaged`: a vault without device management,
    /// set up at the next unlock. `paired-before`: paired by an older
    /// build; the owner chooses which device sets management up. `joining`,
    /// `ready`, or `removed`.
    pub(crate) setup: &'static str,
    pub(crate) this_device: Option<String>,
    pub(crate) members: Vec<MemberInfo>,
    pub(crate) pending: Option<PendingInfo>,
    /// The key epoch committed membership has reached.
    pub(crate) epoch: u64,
    /// How many members must be reachable for any change.
    pub(crate) quorum: usize,
    /// For a device without a vault whose copy of one was put away: the
    /// folder it was moved to.
    pub(crate) reset_archive: Option<String>,
    /// Why it was put away: `removed` by the vault's devices, or `left` at
    /// the owner's request on this device.
    pub(crate) reset_reason: Option<&'static str>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_device(text: &str) -> Result<[u8; 16], CommandError> {
    let invalid = || CommandError {
        code: "invalid_device",
        message: "that is not a device of this vault".into(),
    };
    if text.len() != 32 || !text.is_ascii() {
        return Err(invalid());
    }
    let mut device = [0; 16];
    for (index, byte) in device.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(device)
}

/// The vault's devices as committed membership records them.
#[tauri::command]
pub async fn devices<R: Runtime>(app: AppHandle<R>) -> Result<DevicesInfo, CommandError> {
    let net = network(&app);
    let this_device = app
        .state::<AppState>()
        .vault
        .lock()
        .await
        .as_ref()
        .and_then(|vault| vault.device_id());
    let has_vault = this_device.is_some();
    let joining = net.join.lock().await.is_some();
    let note = if has_vault { None } else { net.reset_note() };
    let empty = |setup| DevicesInfo {
        setup,
        this_device: this_device.map(|device| hex(&device)),
        members: Vec::new(),
        pending: None,
        epoch: 0,
        quorum: 0,
        reset_reason: note.as_ref().map(|(reason, _)| reason.name()),
        reset_archive: note.as_ref().map(|(_, archive)| archive.clone()),
    };
    if has_vault && net.is_removed() {
        return Ok(empty("removed"));
    }
    let Some(control) = net.control().await else {
        return Ok(empty(if !has_vault {
            "none"
        } else if paired_before(&app).await {
            "paired-before"
        } else {
            "unmanaged"
        }));
    };
    let state = control.node.state();
    if joining || state.epoch == 0 {
        return Ok(empty("joining"));
    }
    let leader = control.node.current_leader();
    let members: Vec<MemberInfo> = state
        .members()
        .into_iter()
        .map(|device| MemberInfo {
            id: hex(&device_id_to_bytes(device)),
            this_device: device == control.device,
            address: control.endpoint.addresses().get(device),
            leader: leader == Some(device),
        })
        .collect();
    let pending = state.pending.as_ref().map(|pending| PendingInfo {
        kind: match pending.change {
            MembershipChange::Enroll { .. } => "enroll",
            MembershipChange::Remove { .. } => "remove",
        },
        device: hex(&device_id_to_bytes(pending.subject())),
        cancelled: pending.cancelled,
    });
    Ok(DevicesInfo {
        setup: if net.is_removed() { "removed" } else { "ready" },
        this_device: this_device.map(|device| hex(&device)),
        quorum: state.voters().len() / 2 + 1,
        members,
        pending,
        epoch: state.epoch,
        reset_archive: None,
        reset_reason: None,
    })
}

/// The running control plane of a vault that is unlocked and still a
/// member, for commands that change membership.
async fn member_control<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<Control>, CommandError> {
    let net = network(app);
    if net.is_removed() {
        return Err(network_error(osm_vault_peer::Error::Removed));
    }
    net.control().await.ok_or(CommandError {
        code: "unmanaged",
        message: "this vault is not set up for more than one device yet".into(),
    })
}

/// Sets device management up on this device, for a vault that was paired
/// by an older build. Do this on one of the two devices only; the other
/// joins by invitation, keeping its vault.
#[tauri::command]
pub async fn found_control_plane<R: Runtime>(app: AppHandle<R>) -> Result<(), CommandError> {
    let net = network(&app);
    if net.control().await.is_some() || net.join.lock().await.is_some() {
        return Err(CommandError {
            code: "already_managed",
            message: "device management is already set up or being joined".into(),
        });
    }
    found(&app).await.map(|_| ())
}

/// Removes a device: the others agree on it and move to a new key, which
/// the removed device never receives.
#[tauri::command]
pub async fn remove_device<R: Runtime>(
    device: String,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    let control = member_control(&app).await?;
    let device = parse_device(&device)?;
    let request = {
        let app_state = app.state::<AppState>();
        let vault = app_state.vault.lock().await;
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?;
        control::removal_request(vault, &control.node.state(), device).map_err(network_error)?
    };
    control::submit(&control.node, request)
        .await
        .map_err(network_error)?;
    let _ = app.emit("devices-changed", ());
    Ok(())
}

/// Abandons an enrollment whose device never caught up. It never received
/// a key.
#[tauri::command]
pub async fn cancel_enrollment<R: Runtime>(app: AppHandle<R>) -> Result<(), CommandError> {
    let control = member_control(&app).await?;
    let pending = control
        .node
        .state()
        .pending
        .filter(|pending| {
            matches!(pending.change, MembershipChange::Enroll { .. }) && !pending.cancelled
        })
        .ok_or(CommandError {
            code: "no_enrollment",
            message: "no device is waiting to be enrolled".into(),
        })?;
    let request = {
        let app_state = app.state::<AppState>();
        let vault = app_state.vault.lock().await;
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?;
        control::cancel_request(vault, pending.request_id).map_err(network_error)?
    };
    control::submit(&control.node, request)
        .await
        .map_err(network_error)?;
    let _ = app.emit("devices-changed", ());
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recovered {
    /// The new vault's recovery key, to show the owner once.
    pub(crate) recovery_key: String,
    pub(crate) items: usize,
    /// Items carried with more than one version, still to be resolved.
    pub(crate) conflicts: usize,
    /// Revisions that were held for review and stay in the old vault.
    pub(crate) held_left_behind: usize,
    /// Where the old vault and its files were moved.
    pub(crate) archive: String,
}

/// Starts over from this device when too many of the vault's devices are
/// lost for the rest to remove them: a new vault, with a new identity and
/// new keys, holding what this one shows now. The old vault and its files
/// are moved aside untouched, and this device becomes the first member of
/// the new vault. The other devices are not part of it until they join
/// again.
///
/// This is not a way around the other devices' agreement: nothing in the
/// old vault's membership changes, and the new vault is a different vault.
#[tauri::command]
pub async fn recover_vault<R: Runtime>(
    password: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<Recovered, CommandError> {
    let net = &state.network;
    if net.join.lock().await.is_some() {
        return Err(CommandError {
            code: "joining",
            message: "finish or cancel joining first".into(),
        });
    }
    if net.is_removed() {
        return Err(network_error(osm_vault_peer::Error::Removed));
    }
    if net.control().await.is_none() {
        return Err(CommandError {
            code: "unmanaged",
            message: "this vault has no other devices to start over from".into(),
        });
    }
    // The password is asked again: it confirms the owner's intent and
    // becomes the new vault's password.
    {
        let mut vault = state.vault.lock().await;
        let vault = vault.as_mut().ok_or(CommandError {
            code: "vault_missing",
            message: "vault has not been configured".into(),
        })?;
        if vault.is_unlocked() {
            osm_vault_core::Vault::open(&state.path)?.unlock(&password)?;
        } else {
            vault.unlock(&password)?;
        }
    }
    if let Some(invite) = net.invite.lock().await.take() {
        invite.task.abort();
    }
    // Take in whatever committed state and received revisions this device
    // already has, then stop taking part in the old vault.
    if let Some(control) = net.control().await {
        if !net.is_removed() {
            maintain(&app, &control).await;
        }
    }
    if let Some(control) = net.control.lock().await.take() {
        control.stop().await;
    }

    let directory = net.directory.clone();
    let (partial, complete) = (directory.join(RECOVERED_PARTIAL), directory.join(RECOVERED));
    let (recovery_key, report) = {
        let vault = state.vault.lock().await;
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?;
        let _ = std::fs::remove_file(&partial);
        let (fork, recovery, report) = vault.fork(&partial, &password)?;
        drop(fork);
        // From here on the recovery is finished at the next launch even if
        // the app stops.
        std::fs::rename(&partial, &complete).map_err(storage_error)?;
        (recovery.to_string(), report)
    };

    let archive = {
        let mut vault = state.vault.lock().await;
        let mut invitations = net.invitations.lock().await;
        let mut peers = net.peers.lock().await;
        // Close every file of the old vault before moving it.
        *vault = None;
        *peers = PeerStore::open_in_memory().map_err(network_error)?;
        *invitations = InvitationStore::open_in_memory(InvitationPolicy::default())
            .map_err(|error| network_error(error.into()))?;
        let archive = replace_with_recovered(&state.path).map_err(storage_error)?;
        // The new vault has its own transport identity and address book.
        let peers_path = directory.join("peers.sqlite3");
        *peers = PeerStore::open(&peers_path).map_err(network_error)?;
        *net.addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            AddressBook::open(&peers_path).map_err(network_error)?;
        *invitations = InvitationStore::open(
            directory.join("invitations.sqlite3"),
            InvitationPolicy::default(),
        )
        .map_err(|error| network_error(error.into()))?;
        let mut recovered = osm_vault_core::Vault::open(&state.path)?;
        recovered.unlock(&password)?;
        *vault = Some(recovered);
        archive
    };
    net.removed.store(false, Ordering::SeqCst);
    update_status(&app, |status| {
        *status = SyncStatus {
            state: "local",
            ..SyncStatus::default()
        }
    });
    // The new vault's control plane starts with this device alone.
    found(&app).await?;
    let _ = app.emit("vault-changed", ());
    let _ = app.emit("devices-changed", ());
    Ok(Recovered {
        recovery_key,
        items: report.items,
        conflicts: report.conflicts,
        held_left_behind: report.held_left_behind,
        archive: archive.to_string_lossy().into_owned(),
    })
}

/// Returns a removed device to the state of a device without a vault, so
/// that it can join again. Its copy of the vault, which the other devices
/// no longer accept anything from, is moved to an archive folder, not
/// deleted; the device then gets a new transport identity and, on joining,
/// a new device identity. Returns the archive folder.
///
/// This happens on its own as soon as the device learns that it was
/// removed, and at the next launch if the app stopped before it finished.
async fn reset_removed<R: Runtime>(app: &AppHandle<R>) -> Result<String, CommandError> {
    put_copy_away(app, PutAway::Removed).await
}

/// Stops taking part in the vault on this device and moves its copy and
/// everything that belongs to it to an archive folder, leaving a device
/// without a vault. Returns the archive folder.
async fn put_copy_away<R: Runtime>(
    app: &AppHandle<R>,
    reason: PutAway,
) -> Result<String, CommandError> {
    let state = app.state::<AppState>();
    let net = &state.network;
    if net.resetting.swap(true, Ordering::SeqCst) {
        return Err(CommandError {
            code: "resetting",
            message: "this device is already being reset".into(),
        });
    }
    let result = async {
        if let Some(invite) = net.invite.lock().await.take() {
            invite.task.abort();
        }
        net.join.lock().await.take();
        if let Some(control) = net.control.lock().await.take() {
            control.stop().await;
        }
        let directory = net.directory.clone();
        let mut vault = state.vault.lock().await;
        let mut invitations = net.invitations.lock().await;
        let mut peers = net.peers.lock().await;
        if vault.is_none() {
            return Err(CommandError {
                code: "vault_missing",
                message: "this device has no vault to reset".into(),
            });
        }
        // Close every file before moving it.
        *vault = None;
        *peers = PeerStore::open_in_memory().map_err(network_error)?;
        *invitations = InvitationStore::open_in_memory(InvitationPolicy::default())
            .map_err(|error| network_error(error.into()))?;
        let archive = put_away(&state.path, reason).map_err(storage_error)?;
        let archive = archive.to_string_lossy().into_owned();
        let peers_path = directory.join("peers.sqlite3");
        *peers = PeerStore::open(&peers_path).map_err(network_error)?;
        *net.addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            AddressBook::open(&peers_path).map_err(network_error)?;
        *invitations = InvitationStore::open(
            directory.join("invitations.sqlite3"),
            InvitationPolicy::default(),
        )
        .map_err(|error| network_error(error.into()))?;
        Ok(archive)
    }
    .await;
    net.resetting.store(false, Ordering::SeqCst);
    let archive = result?;
    net.clear_removed();
    update_status(app, |status| {
        *status = SyncStatus {
            state: "local",
            ..SyncStatus::default()
        }
    });
    let _ = app.emit("device-reset", archive.clone());
    let _ = app.emit("vault-changed", ());
    let _ = app.emit("devices-changed", ());
    Ok(archive)
}

/// Resets this device in the background once it has learned that it was
/// removed. If that fails, the device stays in the removed state, from
/// which the owner can ask for the reset again.
fn reset_soon<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = reset_removed(&app).await;
    });
}

/// Resets a removed device on request, for when the reset that follows a
/// removal did not go through.
#[tauri::command]
pub async fn reset_device<R: Runtime>(app: AppHandle<R>) -> Result<String, CommandError> {
    if !network(&app).is_removed() {
        return Err(CommandError {
            code: "not_removed",
            message: "only a device that was removed from its vault can be reset".into(),
        });
    }
    reset_removed(&app).await
}

/// Puts this device's copy of its vault away at the owner's request, so
/// that the device can join another vault: the one another device started
/// over as when this vault's devices could no longer agree. Nothing tells a
/// device that this happened, and nothing removed it, so only the owner can
/// say so, on this device, with its password. The copy is moved to an
/// archive folder, not deleted. Returns that folder.
///
/// It changes nothing in the vault's membership: the devices that still
/// use this vault keep counting this one, which no longer answers. That is
/// why it is for a vault that was replaced, and why a device of a vault
/// still in use is removed from another device instead.
#[tauri::command]
pub async fn leave_vault<R: Runtime>(
    password: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<String, CommandError> {
    let net = &state.network;
    if net.join.lock().await.is_some() {
        return Err(CommandError {
            code: "joining",
            message: "finish or cancel joining first".into(),
        });
    }
    let others = match net.control().await {
        Some(control) => control.node.state().members().len() > 1,
        None => false,
    };
    if !others {
        return Err(CommandError {
            code: "only_device",
            message: "this device is the only device of its vault".into(),
        });
    }
    {
        // The password is the owner's confirmation. It is checked on a
        // second handle, so a locked vault stays locked if it is wrong.
        let vault = state.vault.lock().await;
        if vault.is_none() {
            return Err(CommandError {
                code: "vault_missing",
                message: "this device has no vault".into(),
            });
        }
        osm_vault_core::Vault::open(&state.path)?.unlock(&password)?;
    }
    put_copy_away(&app, PutAway::Left).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteInfo {
    pub(crate) code: String,
    expires_at: u64,
}

/// Issues an invitation and waits in the background for the joiner. When
/// one arrives with a valid request, the short code is sent to the interface
/// as `pairing-code`, and the owner answers with [`confirm_invite`].
#[tauri::command]
pub async fn start_invite<R: Runtime>(
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<InviteInfo, CommandError> {
    let net = &state.network;
    let control = member_control(&app).await?;
    let mut invite_slot = net.invite.lock().await;
    if let Some(previous) = invite_slot.take() {
        previous.task.abort();
    }
    let (listener, invitation) = {
        // Take every guard before borrowing the vault: a shared `&Vault`
        // cannot be held across an await. Order: vault, invitations, peers.
        let vault = state.vault.lock().await;
        let mut invitations = net.invitations.lock().await;
        let mut peers = net.peers.lock().await;
        let listener = PairingListener::bind("0.0.0.0:0", &mut peers)
            .await
            .map_err(network_error)?;
        let port = listener.local_addr().map_err(network_error)?.port();
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?;
        let invitation = invite(
            vault,
            &mut invitations,
            &mut peers,
            vec![format!("{}:{port}", primary_ip())],
            now(),
            MAX_INVITATION_TTL_SECS,
        )
        .map_err(network_error)?;
        (listener, invitation)
    };
    let info = InviteInfo {
        code: invitation.encode().map_err(network_error)?.to_string(),
        expires_at: invitation.expires_at(),
    };
    let (decision, decided) = oneshot::channel();
    let task =
        tauri::async_runtime::spawn(wait_for_joiner(app.clone(), control, listener, decided));
    *invite_slot = Some(InviteState {
        decision: Some(decision),
        task,
    });
    Ok(info)
}

async fn wait_for_joiner<R: Runtime>(
    app: AppHandle<R>,
    control: Arc<Control>,
    listener: PairingListener,
    decided: oneshot::Receiver<bool>,
) {
    let outcome = tokio::time::timeout(
        Duration::from_secs(MAX_INVITATION_TTL_SECS),
        pair_one(&app, &control, &listener, decided),
    )
    .await
    .unwrap_or_else(|_| {
        Err(CommandError {
            code: "invitation_expired",
            message: "the invitation expired".into(),
        })
    });
    let _ = app.emit(
        "pairing-finished",
        PairingFinished {
            paired: outcome.is_ok(),
            code: outcome.as_ref().err().map(|error| error.code),
            message: outcome.err().map(|error| error.message),
        },
    );
    let _ = app.emit("devices-changed", ());
    *network(&app).invite.lock().await = None;
}

/// Reviews one joiner, asks the owner, and proposes the enrollment. It
/// succeeds once the vault's devices accepted the proposal and the joiner
/// was told; the joiner then catches up and becomes a member on its own.
async fn pair_one<R: Runtime>(
    app: &AppHandle<R>,
    control: &Control,
    listener: &PairingListener,
    decided: oneshot::Receiver<bool>,
) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    let net = &state.network;
    let gone = || CommandError {
        code: "locked",
        message: "unlock the vault to finish pairing".into(),
    };
    let pending: PendingJoin = loop {
        let incoming = listener.next_request().await.map_err(network_error)?;
        let vault = state.vault.lock().await;
        let invitations = net.invitations.lock().await;
        let mut peers = net.peers.lock().await;
        let vault = vault.as_ref().ok_or_else(gone)?;
        let reviewed = incoming.review(vault, &invitations, &mut peers, now());
        if let Ok(pending) = reviewed {
            break pending;
        }
    };
    let _ = app.emit("pairing-code", pending.sas());
    // Nothing is locked while the owner compares the codes.
    if !decided.await.unwrap_or(false) {
        let _ = pending.decline().await;
        return Err(network_error(osm_vault_peer::Error::NotConfirmed));
    }
    let (proposal, approved) = {
        let vault = state.vault.lock().await;
        let mut invitations = net.invitations.lock().await;
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(gone)?;
        pending
            .approve_enrollment(
                vault,
                &mut invitations,
                control.endpoint.roster(),
                control.endpoint.listen_port(),
                now(),
            )
            .map_err(network_error)?
    };
    // The owner's confirmation becomes a proposal that a majority of the
    // vault's devices must accept.
    if let Err(error) = control::submit(&control.node, proposal).await {
        let _ = approved.refuse().await;
        return Err(network_error(error));
    }
    approved.send().await.map_err(network_error)
}

#[derive(Clone, Serialize)]
struct PairingFinished {
    paired: bool,
    code: Option<&'static str>,
    message: Option<String>,
}

/// The owner's answer after comparing the codes on both devices.
#[tauri::command]
pub async fn confirm_invite(
    accept: bool,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    let mut invite = state.network.invite.lock().await;
    let decision = invite
        .as_mut()
        .and_then(|invite| invite.decision.take())
        .ok_or(CommandError {
            code: "no_invitation",
            message: "no pairing is waiting for a decision".into(),
        })?;
    let _ = decision.send(accept);
    Ok(())
}

#[tauri::command]
pub async fn cancel_invite(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    if let Some(invite) = state.network.invite.lock().await.take() {
        invite.task.abort();
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinInfo {
    pub(crate) sas: String,
    /// This device already holds the vault and keeps it.
    pub(crate) keeps_vault: bool,
}

/// Connects to the inviting device from an invitation code. A device
/// without a vault joins as a new device. A device that was paired by an
/// older build joins with the vault it has, which must be unlocked.
#[tauri::command]
pub async fn join_start<R: Runtime>(
    code: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<JoinInfo, CommandError> {
    let net = &state.network;
    if net.join.lock().await.take().is_some() {
        abandon_control(&app).await;
    }
    if net.control().await.is_some() {
        return Err(CommandError {
            code: "vault_exists",
            message: "this device already belongs to a vault's devices".into(),
        });
    }
    let invitation = Invitation::decode(&code).map_err(network_error)?;
    let (prepared, keeps_vault) = {
        let vault = state.vault.lock().await;
        let mut peers = net.peers.lock().await;
        match vault.as_ref() {
            None => (PreparedJoin::new(invitation, &mut peers, now()), false),
            Some(vault) if vault.is_unlocked() => (
                PreparedJoin::with_vault(invitation, vault, &mut peers, now()),
                true,
            ),
            Some(_) => return Err(locked()),
        }
    };
    let connection = prepared
        .map_err(network_error)?
        .connect()
        .await
        .map_err(network_error)?;
    // The node runs from here on so that the leader can bring this device
    // up to date. It accepts no one until the inviting device names the
    // members.
    let joiner = connection.joiner();
    let control = start_control(&app, joiner.vault_id(), joiner.control_device()).await?;
    let sas = connection.sas();
    *net.join.lock().await = Some(JoinState {
        connection,
        control,
    });
    let _ = app.emit("devices-changed", ());
    Ok(JoinInfo { sas, keeps_vault })
}

/// Called when the owner confirms the codes match on this device. Waits for
/// the inviting device's approval and for the vault's devices to enroll
/// this one, then creates its vault, or for a device that keeps its vault,
/// brings that vault in line.
#[tauri::command]
pub async fn join_finish<R: Runtime>(
    password: Option<String>,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    let net = &state.network;
    let keeps_vault = match net.join.lock().await.as_ref() {
        Some(join) => join.connection.joiner().has_vault(),
        None => {
            return Err(CommandError {
                code: "no_pairing",
                message: "start joining with an invitation code first".into(),
            })
        }
    };
    let password = password.unwrap_or_default();
    if !keeps_vault && password.chars().count() < 12 {
        return Err(CommandError {
            code: "invalid_item",
            message: "use at least 12 characters for this device password".into(),
        });
    }
    let Some(JoinState {
        connection,
        control,
    }) = net.join.lock().await.take()
    else {
        return Err(CommandError {
            code: "no_pairing",
            message: "start joining with an invitation code first".into(),
        });
    };
    let joined = finish_join(&app, connection, &control, &password).await;
    if let Err(error) = joined {
        abandon_control(&app).await;
        let _ = app.emit("devices-changed", ());
        return Err(error);
    }
    net.clear_reset_note();
    maintain(&app, &control).await;
    // Fetch the vault's contents right away.
    let sync_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = sync_with_members(&sync_app).await;
    });
    Ok(())
}

async fn finish_join<R: Runtime>(
    app: &AppHandle<R>,
    connection: PairingConnection,
    control: &Control,
    password: &str,
) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    let (joiner, grant) = connection
        .receive_enrollment()
        .await
        .map_err(network_error)?;
    // The grant names the members: accept them, and keep telling them where
    // this device listens until one of them has brought it up to date.
    let members = joiner.members(&grant).map_err(network_error)?;
    control
        .endpoint
        .introduce(&members)
        .map_err(network_error)?;
    let deadline = tokio::time::Instant::now() + ENROLLMENT_TIMEOUT;
    while !joiner.enrolled(&control.node.state()) {
        if tokio::time::Instant::now() > deadline {
            return Err(CommandError {
                code: "enrollment_timeout",
                message: "the vault's devices did not finish enrolling this device; \
                          cancel the enrollment on the inviting device and try again"
                    .into(),
            });
        }
        control.endpoint.announce_all().await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let committed = control.node.state();
    let mut vault = state.vault.lock().await;
    if joiner.has_vault() {
        let vault = vault
            .as_mut()
            .filter(|vault| vault.is_unlocked())
            .ok_or_else(locked)?;
        joiner
            .finish_in_place(&grant, true, &committed, vault)
            .map_err(network_error)?;
        state
            .network
            .peers
            .lock()
            .await
            .clear_legacy_peers()
            .map_err(network_error)?;
    } else {
        if vault.is_some() {
            return Err(CommandError {
                code: "vault_exists",
                message: "this device already has a vault".into(),
            });
        }
        *vault = Some(
            joiner
                .finish_enrollment(&grant, true, &committed, &state.path, password)
                .map_err(network_error)?,
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn cancel_join<R: Runtime>(
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    if state.network.join.lock().await.take().is_some() {
        abandon_control(&app).await;
        let _ = app.emit("devices-changed", ());
    }
    Ok(())
}

/// The address other devices on the local network most likely reach this
/// one at. Connecting a UDP socket sends nothing; it only selects a route.
fn primary_ip() -> std::net::IpAddr {
    std::net::UdpSocket::bind(("0.0.0.0", 0))
        .and_then(|socket| {
            socket.connect(("192.0.2.1", 9))?;
            socket.local_addr()
        })
        .map(|address| address.ip())
        .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn locked() -> CommandError {
    CommandError {
        code: "locked",
        message: "unlock the vault first".into(),
    }
}

fn storage_error(error: std::io::Error) -> CommandError {
    CommandError {
        code: "storage",
        message: error.to_string(),
    }
}

fn network_error(error: osm_vault_peer::Error) -> CommandError {
    use osm_vault_peer::Error;
    let code = match &error {
        Error::NotConfirmed => "not_confirmed",
        Error::PinMismatch => "pin_mismatch",
        Error::InvitationExpired | Error::Sync(osm_vault_sync::Error::InvitationExpired) => {
            "invitation_expired"
        }
        Error::InvalidInvitation => "invalid_invitation",
        Error::VaultMismatch => "vault_mismatch",
        Error::Timeout => "timeout",
        Error::Removed => "removed",
        Error::EnrollmentRefused => "enrollment_refused",
        Error::Vault(osm_vault_core::Error::Locked) => "locked",
        Error::Membership(inner) => match **inner {
            osm_vault_membership::Error::QuorumUnavailable
            | osm_vault_membership::Error::NotLeader(_) => "quorum_unavailable",
            _ => "network",
        },
        Error::Rejected(Rejection::ChangeInProgress) => "change_in_progress",
        Error::Rejected(_) => "rejected",
        _ => "network",
    };
    CommandError {
        code,
        message: error.to_string(),
    }
}
