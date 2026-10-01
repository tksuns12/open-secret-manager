//! Pairing and sync for the desktop shell.
//!
//! While the app is open and paired, a listener accepts sync connections
//! from the paired device only (its pinned certificate; anything else fails
//! the TLS handshake before the vault is touched). A locked vault still
//! receives: revisions are staged and verified at the next unlock. This
//! device dials its peer shortly after a local change, at unlock, and when
//! the owner asks. Status reaches the interface as `sync-status` events.
//!
//! Network waits never hold the vault: handshakes happen first, and while
//! the owner compares pairing codes nothing is locked.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        Mutex as StdMutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use osm_vault_core::IngressReport;
use osm_vault_peer::{
    invite, Invitation, PairingConnection, PairingListener, PeerStore, PendingJoin, SyncEndpoint,
    MAX_INVITATION_TTL_SECS,
};
use osm_vault_sync::{InvitationPolicy, InvitationStore};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::{
    net::TcpListener,
    sync::{oneshot, Mutex},
};

use crate::{AppState, CommandError};

/// Preferred sync port; another is used if it is taken.
const SYNC_PORT: u16 = 47_820;
/// Wait after a local change before dialing, so a burst of edits syncs once.
const SYNC_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// `unpaired`, `idle`, `syncing`, `synced`, `received`, or `error`.
    state: &'static str,
    last_synced_at: Option<u64>,
    message: Option<String>,
    /// First four bytes of the paired device's ID, in hex.
    peer: Option<String>,
    peer_address: Option<String>,
    /// Revisions received while locked, waiting for unlock.
    pending: usize,
}

pub struct Network {
    peers: Mutex<PeerStore>,
    invitations: Mutex<InvitationStore>,
    status: StdMutex<SyncStatus>,
    /// The inviter's pending decision, while a joiner waits.
    invite: Mutex<Option<InviteState>>,
    join: Mutex<Option<PairingConnection>>,
    /// Serializes binding the sync listener; `listen_port` is 0 until bound.
    binding: Mutex<()>,
    listen_port: AtomicU16,
    syncing: AtomicBool,
    sync_generation: AtomicU64,
}

struct InviteState {
    decision: Option<oneshot::Sender<bool>>,
    task: tauri::async_runtime::JoinHandle<()>,
}

impl Network {
    pub fn open(vault_path: &Path) -> Result<Self, CommandError> {
        let directory = vault_path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(directory).map_err(storage_error)?;
        let peers = PeerStore::open(directory.join("peers.sqlite3")).map_err(network_error)?;
        // One-use invitation tokens are recorded durably so a restart
        // cannot make a used token valid again.
        let invitations = InvitationStore::open(
            directory.join("invitations.sqlite3"),
            InvitationPolicy::default(),
        )
        .map_err(|error| network_error(error.into()))?;
        let status = initial_status(&peers);
        Ok(Self {
            peers: Mutex::new(peers),
            invitations: Mutex::new(invitations),
            status: StdMutex::new(status),
            invite: Mutex::new(None),
            join: Mutex::new(None),
            binding: Mutex::new(()),
            listen_port: AtomicU16::new(0),
            syncing: AtomicBool::new(false),
            sync_generation: AtomicU64::new(0),
        })
    }
}

fn initial_status(peers: &PeerStore) -> SyncStatus {
    match peers
        .peers()
        .ok()
        .and_then(|peers| peers.into_iter().next())
    {
        Some(peer) => SyncStatus {
            state: "idle",
            peer: Some(short_id(&peer.device_id)),
            peer_address: peer.address,
            ..SyncStatus::default()
        },
        None => SyncStatus {
            state: "unpaired",
            ..SyncStatus::default()
        },
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

/// Starts the sync listener at launch if this device is paired.
pub fn start_listener<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let paired = network(&app)
            .peers
            .lock()
            .await
            .peers()
            .map(|peers| !peers.is_empty())
            .unwrap_or(false);
        if paired {
            ensure_listener(&app).await;
        }
    });
}

/// Binds the sync listener if it is not running and returns its port. Until
/// a device is paired every connection fails the handshake, since there is
/// no certificate to accept.
pub async fn ensure_listener<R: Runtime>(app: &AppHandle<R>) -> Option<u16> {
    let net = network(app);
    let _binding = net.binding.lock().await;
    let port = net.listen_port.load(Ordering::SeqCst);
    if port != 0 {
        return Some(port);
    }
    let listener = match TcpListener::bind(("0.0.0.0", SYNC_PORT)).await {
        Ok(listener) => listener,
        Err(_) => match TcpListener::bind(("0.0.0.0", 0)).await {
            Ok(listener) => listener,
            Err(error) => {
                update_status(app, |status| {
                    status.state = "error";
                    status.message = Some(format!("cannot listen for sync: {error}"));
                });
                return None;
            }
        },
    };
    let port = listener.local_addr().ok()?.port();
    net.listen_port.store(port, Ordering::SeqCst);
    tauri::async_runtime::spawn(accept_loop(app.clone(), listener));
    Some(port)
}

async fn accept_loop<R: Runtime>(app: AppHandle<R>, listener: TcpListener) {
    let net = network(&app);
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let endpoint = {
            let mut peers = net.peers.lock().await;
            match SyncEndpoint::load(&mut peers) {
                Ok(endpoint) => endpoint,
                Err(_) => continue,
            }
        };
        // The handshake runs before the vault is locked, so a stranger
        // cannot stall the app; it fails unless the certificate is the
        // paired device's.
        let Ok(connection) = endpoint.accept(tcp).await else {
            continue;
        };
        run_session(&app, connection, endpoint.peer().device_id).await;
    }
}

/// Runs one session over an authenticated connection, holding the vault for
/// its duration.
async fn run_session<R: Runtime>(
    app: &AppHandle<R>,
    connection: osm_vault_peer::SyncConnection,
    peer_device: [u8; 16],
) {
    let state = app.state::<AppState>();
    let net = &state.network;
    update_status(app, |status| status.state = "syncing");
    let port = net.listen_port.load(Ordering::SeqCst);
    let result = {
        let mut vault = state.vault.lock().await;
        match vault.as_mut() {
            Some(vault) => connection
                .run(vault, (port != 0).then_some(port))
                .await
                .map(|outcome| (outcome, vault.is_unlocked())),
            None => {
                update_status(app, |status| status.state = "idle");
                return;
            }
        }
    };
    match result {
        Ok((outcome, unlocked)) => {
            if let Some(address) = &outcome.peer_address {
                let _ = net.peers.lock().await.set_address(&peer_device, address);
            }
            let report = outcome.report;
            update_status(app, |status| {
                status.state = if unlocked || report.received == 0 {
                    "synced"
                } else {
                    "received"
                };
                status.last_synced_at = Some(now());
                status.message = None;
                status.pending = report.pending;
                if outcome.peer_address.is_some() {
                    status.peer_address = outcome.peer_address.clone();
                }
            });
            if report.applied > 0 || report.quarantined > 0 {
                let _ = app.emit("vault-changed", ());
            }
        }
        Err(error) => update_status(app, |status| {
            status.state = "error";
            status.message = Some(error.to_string());
        }),
    }
}

/// Dials the paired device and syncs. At most one outgoing sync runs at a
/// time.
async fn sync_with_peer<R: Runtime>(app: &AppHandle<R>) -> Result<(), CommandError> {
    let net = network(app);
    if net.syncing.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let result: Result<(), CommandError> = async {
        let endpoint = SyncEndpoint::load(&mut *net.peers.lock().await).map_err(network_error)?;
        let address = endpoint.peer().address.clone().ok_or(CommandError {
            code: "peer_address",
            message: "the other device's address is not known yet; sync from that device once"
                .into(),
        })?;
        update_status(app, |status| status.state = "syncing");
        let connection = endpoint.connect(&address).await.map_err(network_error)?;
        run_session(app, connection, endpoint.peer().device_id).await;
        Ok(())
    }
    .await;
    net.syncing.store(false, Ordering::SeqCst);
    if let Err(error) = &result {
        update_status(app, |status| {
            status.state = "error";
            status.message = Some(error.message.clone());
        });
    }
    result
}

/// Syncs shortly after a local change. A newer change restarts the wait.
pub fn schedule_sync<R: Runtime>(app: &AppHandle<R>) {
    let net = network(app);
    let generation = net.sync_generation.fetch_add(1, Ordering::SeqCst) + 1;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SYNC_DELAY).await;
        if network(&app).sync_generation.load(Ordering::SeqCst) == generation {
            let _ = sync_with_peer(&app).await;
        }
    });
}

/// Reports what unlock verified, then catches up with the peer.
pub fn after_unlock<R: Runtime>(app: &AppHandle<R>, processed: &IngressReport) {
    update_status(app, |status| {
        status.pending = processed.pending;
        if status.state == "received" {
            status.state = "synced";
        }
        if processed.rejected > 0 {
            status.state = "error";
            status.message = Some(format!(
                "{} received revisions failed verification and were discarded",
                processed.rejected
            ));
        }
    });
    if processed.applied > 0 || processed.quarantined > 0 {
        let _ = app.emit("vault-changed", ());
    }
    schedule_sync(app);
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
    sync_with_peer(&app).await
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
    // The grant tells the joiner where to sync, so listen before inviting.
    ensure_listener(&app).await.ok_or(CommandError {
        code: "network",
        message: "cannot listen for sync connections".into(),
    })?;
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
        peers.ensure_capacity().map_err(network_error)?;
        let listener = PairingListener::bind("0.0.0.0:0", &mut peers)
            .await
            .map_err(network_error)?;
        let port = listener.local_addr().map_err(network_error)?.port();
        let vault = vault
            .as_ref()
            .filter(|vault| vault.is_unlocked())
            .ok_or(CommandError {
                code: "locked",
                message: "unlock the vault to invite a device".into(),
            })?;
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
    let task = tauri::async_runtime::spawn(wait_for_joiner(app.clone(), listener, decided));
    *invite_slot = Some(InviteState {
        decision: Some(decision),
        task,
    });
    Ok(info)
}

async fn wait_for_joiner<R: Runtime>(
    app: AppHandle<R>,
    listener: PairingListener,
    decided: oneshot::Receiver<bool>,
) {
    let outcome = tokio::time::timeout(
        Duration::from_secs(MAX_INVITATION_TTL_SECS),
        pair_one(&app, &listener, decided),
    )
    .await
    .unwrap_or_else(|_| Err("the invitation expired".into()));
    if outcome.is_ok() {
        update_status(&app, |status| {
            *status = SyncStatus {
                state: "idle",
                ..status.clone()
            }
        });
        refresh_peer(&app).await;
    }
    let _ = app.emit(
        "pairing-finished",
        PairingFinished {
            paired: outcome.is_ok(),
            message: outcome.err(),
        },
    );
    *network(&app).invite.lock().await = None;
}

async fn pair_one<R: Runtime>(
    app: &AppHandle<R>,
    listener: &PairingListener,
    decided: oneshot::Receiver<bool>,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let net = &state.network;
    let pending: PendingJoin = loop {
        let incoming = listener
            .next_request()
            .await
            .map_err(|error| error.to_string())?;
        let vault = state.vault.lock().await;
        let invitations = net.invitations.lock().await;
        let mut peers = net.peers.lock().await;
        let Some(vault) = vault.as_ref() else {
            return Err("the vault is no longer available".into());
        };
        let reviewed = incoming.review(vault, &invitations, &mut peers, now());
        if let Ok(pending) = reviewed {
            break pending;
        }
    };
    let _ = app.emit("pairing-code", pending.sas());
    // Nothing is locked while the owner compares the codes.
    if !decided.await.unwrap_or(false) {
        let _ = pending.decline().await;
        return Err("pairing was declined".into());
    }
    let approved = {
        let mut vault = state.vault.lock().await;
        let mut invitations = net.invitations.lock().await;
        let mut peers = net.peers.lock().await;
        let vault = vault
            .as_mut()
            .filter(|vault| vault.is_unlocked())
            .ok_or("unlock the vault to finish pairing")?;
        let sync_port = net.listen_port.load(Ordering::SeqCst);
        pending
            .approve(
                vault,
                &mut invitations,
                &mut peers,
                (sync_port != 0).then_some(sync_port),
                now(),
            )
            .map_err(|error| error.to_string())?
    };
    approved.send().await.map_err(|error| error.to_string())
}

#[derive(Clone, Serialize)]
struct PairingFinished {
    paired: bool,
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
}

/// Connects to the inviting device from an invitation code. Only possible
/// before this device has a vault.
#[tauri::command]
pub async fn join_start(
    code: String,
    state: tauri::State<'_, AppState>,
) -> Result<JoinInfo, CommandError> {
    if state.vault.lock().await.is_some() {
        return Err(CommandError {
            code: "vault_exists",
            message: "this device already has a vault".into(),
        });
    }
    let invitation = Invitation::decode(&code).map_err(network_error)?;
    let connection = {
        let mut peers = state.network.peers.lock().await;
        osm_vault_peer::start_pairing(invitation, &mut peers, now())
            .await
            .map_err(network_error)?
    };
    let sas = connection.sas();
    *state.network.join.lock().await = Some(connection);
    Ok(JoinInfo { sas })
}

/// Called when the owner confirms the codes match on this device. Waits for
/// the inviting device's approval, then creates this device's vault.
#[tauri::command]
pub async fn join_finish<R: Runtime>(
    password: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle<R>,
) -> Result<(), CommandError> {
    if password.chars().count() < 12 {
        return Err(CommandError {
            code: "invalid_item",
            message: "use at least 12 characters for this device password".into(),
        });
    }
    let connection = state.network.join.lock().await.take().ok_or(CommandError {
        code: "no_pairing",
        message: "start joining with an invitation code first".into(),
    })?;
    let (joiner, grant) = connection.receive_grant().await.map_err(network_error)?;
    {
        let mut vault = state.vault.lock().await;
        if vault.is_some() {
            return Err(CommandError {
                code: "vault_exists",
                message: "this device already has a vault".into(),
            });
        }
        let mut peers = state.network.peers.lock().await;
        let joined = joiner
            .finish(&grant, true, &state.path, &password, &mut peers, now())
            .map_err(network_error)?;
        *vault = Some(joined);
    }
    refresh_peer(&app).await;
    // Listen before the first sync so it tells the inviter where to reach
    // this device.
    ensure_listener(&app).await;
    // Fetch the vault's contents right away.
    let sync_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = sync_with_peer(&sync_app).await;
    });
    Ok(())
}

#[tauri::command]
pub async fn cancel_join(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    state.network.join.lock().await.take();
    Ok(())
}

async fn refresh_peer<R: Runtime>(app: &AppHandle<R>) {
    let status = initial_status(&*network(app).peers.lock().await);
    update_status(app, |current| {
        current.peer = status.peer;
        current.peer_address = status.peer_address;
        if current.state == "unpaired" {
            current.state = status.state;
        }
    });
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

fn short_id(device_id: &[u8; 16]) -> String {
    device_id[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn storage_error(error: std::io::Error) -> CommandError {
    CommandError {
        code: "storage",
        message: error.to_string(),
    }
}

fn network_error(error: osm_vault_peer::Error) -> CommandError {
    let code = match error {
        osm_vault_peer::Error::NotConfirmed => "not_confirmed",
        osm_vault_peer::Error::PinMismatch => "pin_mismatch",
        osm_vault_peer::Error::InvitationExpired
        | osm_vault_peer::Error::Sync(osm_vault_sync::Error::InvitationExpired) => {
            "invitation_expired"
        }
        osm_vault_peer::Error::InvalidInvitation => "invalid_invitation",
        osm_vault_peer::Error::PeerLimit => "peer_limit",
        osm_vault_peer::Error::NotPaired => "not_paired",
        osm_vault_peer::Error::Timeout => "timeout",
        _ => "network",
    };
    CommandError {
        code,
        message: error.to_string(),
    }
}
